using System;
using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using WSCT.ISO7816;
using static Gp4Net.Cryptography.CryptoService;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Immutable data structure representing the bytes needed for R-MAC calculation on a response APDU.
/// This type enforces that valid cryptographic keys and session state exist before R-MAC verification can proceed.
/// </summary>
/// <remarks>
/// This type implements the "make invalid states unrepresentable" principle by requiring
/// proof of a valid secure channel session with R-MAC enabled at construction time.
/// </remarks>
[PublicAPI]
public sealed record ResponseMacData
{
    /// <summary>
    /// The bytes to use for R-MAC calculation (Data|SW1|SW2).
    /// </summary>
    public ImmutableArray<byte> CalculationBytes { get; }
    
    /// <summary>
    /// The R-MAC extracted from the response (first 8 bytes of Udr if present).
    /// </summary>
    public ImmutableArray<byte> ExtractedMac { get; }
    
    /// <summary>
    /// The response data without the R-MAC.
    /// </summary>
    public ImmutableArray<byte> PlaintextData { get; }
    
    /// <summary>
    /// The validated session keys from the secure channel establishment.
    /// </summary>
    public SessionKeys ValidatedKeys { get; }
    
    /// <summary>
    /// The current MAC chaining state for continuous MAC calculation.
    /// </summary>
    public MacChainingState ChainState { get; }
    
    /// <summary>
    /// The protocol version for R-MAC calculation (SCP02 or SCP03).
    /// </summary>
    public ScpVersion ProtocolVersion { get; }
    
    /// <summary>
    /// Private constructor ensures validation through factory method.
    /// </summary>
    private ResponseMacData(
        ImmutableArray<byte> calculationBytes,
        ImmutableArray<byte> extractedMac,
        ImmutableArray<byte> plaintextData,
        SessionKeys keys,
        MacChainingState chainState,
        ScpVersion protocolVersion)
    {
        CalculationBytes = calculationBytes;
        ExtractedMac = extractedMac;
        PlaintextData = plaintextData;
        ValidatedKeys = keys;
        ChainState = chainState;
        ProtocolVersion = protocolVersion;
    }
    
    /// <summary>
    /// Creates ResponseMacData from a response APDU and validated secure channel session.
    /// </summary>
    /// <param name="response">The response APDU to extract R-MAC from.</param>
    /// <param name="validSession">A valid secure channel session with R-MAC enabled.</param>
    /// <returns>Success with ResponseMacData if session has R-MAC, failure otherwise.</returns>
    public static Result<ResponseMacData, SmartCardError> Create(
        ResponseAPDU response,
        SecureChannelState validSession)
    {
        return Maybe<ResponseAPDU>
            .From(response)
            .ToResult(SmartCardError.InvalidArgument("Response cannot be null"))
            .Bind(_ => Maybe<SecureChannelState>
                .From(validSession)
                .ToResult(SmartCardError.InvalidArgument("Session state cannot be null")))
            .Bind(session =>
                session.SecurityLevel.HasRMac()
                    ? Result.Success<SecureChannelState, SmartCardError>(session)
                    : Result.Failure<SecureChannelState, SmartCardError>(
                        SmartCardError.SecurityError("R-MAC not enabled in current session")))
            .Bind(session => ExtractRMacComponents(response, session))
            .Map(components => new ResponseMacData(
                components.calculationBytes.ToImmutableArray(),
                components.extractedMac.ToImmutableArray(),
                components.plaintextData.ToImmutableArray(),
                validSession.SessionKeys,
                validSession.MacChaining,
                validSession.ProtocolVersion));
    }
    
    /// <summary>
    /// Extracts R-MAC components from a response APDU.
    /// </summary>
    private static Result<(byte[] calculationBytes, byte[] extractedMac, byte[] plaintextData), SmartCardError> 
        ExtractRMacComponents(ResponseAPDU response, SecureChannelState session)
    {
        var udr = response.Udr ?? Array.Empty<byte>();
        var macSize = 8; // Both SCP02 and SCP03 use 8-byte R-MACs
        
        if (udr.Length >= macSize)
        {
            // R-MAC is the first 'macSize' bytes of Udr
            var extractedMac = new byte[macSize];
            Array.Copy(udr, 0, extractedMac, 0, macSize);
            
            // Data is Udr without the R-MAC
            var plaintextData = new byte[udr.Length - macSize];
            if (plaintextData.Length > 0)
            {
                Array.Copy(udr, macSize, plaintextData, 0, plaintextData.Length);
            }
            
            // For R-MAC calculation: Data|SW1|SW2
            var calculationBytes = new byte[plaintextData.Length + 2];
            if (plaintextData.Length > 0)
            {
                Array.Copy(plaintextData, 0, calculationBytes, 0, plaintextData.Length);
            }
            calculationBytes[calculationBytes.Length - 2] = response.Sw1;
            calculationBytes[calculationBytes.Length - 1] = response.Sw2;
            
            return Result.Success<(byte[], byte[], byte[]), SmartCardError>(
                (calculationBytes, extractedMac, plaintextData));
        }
        else
        {
            // Response too short for R-MAC
            return Result.Failure<(byte[], byte[], byte[]), SmartCardError>(
                SmartCardError.InvalidData($"Response too short for R-MAC: {udr.Length} bytes"));
        }
    }
    
    /// <summary>
    /// Creates ResponseMacData for a response without R-MAC (used for building R-MAC).
    /// </summary>
    /// <param name="response">The response APDU to prepare for R-MAC generation.</param>
    /// <param name="validSession">A valid secure channel session.</param>
    /// <returns>Success with ResponseMacData for R-MAC generation.</returns>
    public static Result<ResponseMacData, SmartCardError> CreateForGeneration(
        ResponseAPDU response,
        SecureChannelState validSession)
    {
        return Maybe<ResponseAPDU>
            .From(response)
            .ToResult(SmartCardError.InvalidArgument("Response cannot be null"))
            .Bind(_ => Maybe<SecureChannelState>
                .From(validSession)
                .ToResult(SmartCardError.InvalidArgument("Session state cannot be null")))
            .Map(session =>
            {
                var udr = response.Udr ?? Array.Empty<byte>();
                
                // For R-MAC generation: Data|SW1|SW2
                var calculationBytes = new byte[udr.Length + 2];
                if (udr.Length > 0)
                {
                    Array.Copy(udr, 0, calculationBytes, 0, udr.Length);
                }
                calculationBytes[calculationBytes.Length - 2] = response.Sw1;
                calculationBytes[calculationBytes.Length - 1] = response.Sw2;
                
                return new ResponseMacData(
                    calculationBytes.ToImmutableArray(),
                    ImmutableArray<byte>.Empty, // No extracted MAC for generation
                    udr.ToImmutableArray(),
                    session.SessionKeys,
                    session.MacChaining,
                    session.ProtocolVersion);
            });
    }
}