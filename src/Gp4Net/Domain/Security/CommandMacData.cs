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
/// Immutable data structure representing the bytes needed for MAC calculation on a command APDU.
/// This type enforces that valid cryptographic keys and session state exist before MAC calculation can proceed.
/// </summary>
/// <remarks>
/// This type implements the "make invalid states unrepresentable" principle by requiring
/// proof of a valid secure channel session at construction time. You cannot create an instance
/// without having established a secure channel with MAC capabilities enabled.
/// </remarks>
[PublicAPI]
public sealed record CommandMacData
{
    /// <summary>
    /// The bytes to use for MAC calculation (CLA|INS|P1|P2|Lc|Data without MAC or Le).
    /// </summary>
    public ImmutableArray<byte> CalculationBytes { get; }
    
    /// <summary>
    /// The validated session keys from the secure channel establishment.
    /// Presence of this field proves that key derivation was successful.
    /// </summary>
    public SessionKeys ValidatedKeys { get; }
    
    /// <summary>
    /// The current MAC chaining state for continuous MAC calculation.
    /// </summary>
    public MacChainingState ChainState { get; }
    
    /// <summary>
    /// The protocol version for MAC calculation (SCP02 or SCP03).
    /// </summary>
    public ScpVersion ProtocolVersion { get; }
    
    /// <summary>
    /// Private constructor ensures validation through factory method.
    /// </summary>
    private CommandMacData(
        ImmutableArray<byte> calculationBytes,
        SessionKeys keys,
        MacChainingState chainState,
        ScpVersion protocolVersion)
    {
        CalculationBytes = calculationBytes;
        ValidatedKeys = keys;
        ChainState = chainState;
        ProtocolVersion = protocolVersion;
    }
    
    /// <summary>
    /// Creates CommandMacData from a command APDU and validated secure channel session.
    /// </summary>
    /// <param name="command">The command APDU to extract MAC calculation bytes from.</param>
    /// <param name="validSession">A valid secure channel session with C-MAC enabled.</param>
    /// <returns>Success with CommandMacData if session has C-MAC, failure otherwise.</returns>
    public static Result<CommandMacData, SmartCardError> Create(
        CommandAPDU command,
        SecureChannelState validSession)
    {
        return Maybe<CommandAPDU>
            .From(command)
            .ToResult(SmartCardError.InvalidArgument("Command cannot be null"))
            .Bind(_ => Maybe<SecureChannelState>
                .From(validSession)
                .ToResult(SmartCardError.InvalidArgument("Session state cannot be null")))
            .Bind(session =>
                session.SecurityLevel.HasCMac()
                    ? Result.Success<SecureChannelState, SmartCardError>(session)
                    : Result.Failure<SecureChannelState, SmartCardError>(
                        SmartCardError.SecurityError("C-MAC not enabled in current session")))
            .Bind(session => ExtractMacCalculationBytes(command, session))
            .Map(bytes => new CommandMacData(
                bytes.ToImmutableArray(),
                validSession.SessionKeys,
                validSession.MacChaining,
                validSession.ProtocolVersion));
    }
    
    /// <summary>
    /// Extracts the bytes needed for MAC calculation from a command APDU.
    /// </summary>
    private static Result<byte[], SmartCardError> ExtractMacCalculationBytes(
        CommandAPDU command,
        SecureChannelState session)
    {
        var binaryCommand = command.BinaryCommand;
        var isSecured = (command.Cla & 0x04) != 0;
        
        if (isSecured)
        {
            // For secured commands, we need to remove the MAC from Udc
            var udc = command.Udc ?? Array.Empty<byte>();
            var macSize = session.ProtocolVersion == ScpVersion.Scp03 ? 8 : 8; // Both use 8-byte MACs
            
            if (udc.Length >= macSize)
            {
                // Extract plaintext data (Udc without MAC)
                var plaintextData = new byte[udc.Length - macSize];
                if (plaintextData.Length > 0)
                {
                    Array.Copy(udc, 0, plaintextData, 0, plaintextData.Length);
                }
                
                // Rebuild MAC input with plaintext data
                return RebuildMacInput(command, plaintextData, binaryCommand);
            }
        }
        
        // For unsecured commands, remove Le if present
        return RemoveLeFromCommand(command, binaryCommand);
    }
    
    private static Result<byte[], SmartCardError> RebuildMacInput(
        CommandAPDU command,
        byte[] plaintextData,
        byte[] binaryCommand)
    {
        var headerSize = 4; // CLA|INS|P1|P2
        var dataStartPos = headerSize;
        
        // Determine Lc encoding size
        if (binaryCommand.Length > headerSize)
        {
            var lcByte = binaryCommand[headerSize];
            if (lcByte == 0x00 && binaryCommand.Length > headerSize + 2)
            {
                dataStartPos += 3; // Extended Lc: 00|XX|XX
            }
            else
            {
                dataStartPos += 1; // Short Lc
            }
        }
        
        // Build MAC input bytes
        var macInputSize = dataStartPos + plaintextData.Length;
        var macInputBytes = new byte[macInputSize];
        
        // Copy header and Lc
        Array.Copy(binaryCommand, 0, macInputBytes, 0, dataStartPos);
        
        // Update Lc value to reflect plaintext data size
        if (dataStartPos == headerSize + 1)
        {
            macInputBytes[headerSize] = (byte)plaintextData.Length;
        }
        else if (dataStartPos == headerSize + 3)
        {
            macInputBytes[headerSize] = 0x00;
            macInputBytes[headerSize + 1] = (byte)(plaintextData.Length >> 8);
            macInputBytes[headerSize + 2] = (byte)(plaintextData.Length & 0xFF);
        }
        
        // Copy plaintext data
        if (plaintextData.Length > 0)
        {
            Array.Copy(plaintextData, 0, macInputBytes, dataStartPos, plaintextData.Length);
        }
        
        return Result.Success<byte[], SmartCardError>(macInputBytes);
    }
    
    private static Result<byte[], SmartCardError> RemoveLeFromCommand(
        CommandAPDU command,
        byte[] binaryCommand)
    {
        // For MAC calculation, we need CLA|INS|P1|P2|Lc|Data (no Le)
        var macInputBytes = binaryCommand;
        
        var leMaybe = Maybe<uint>.From(command.Le);
        if (leMaybe.HasValue)
        {
            var headerSize = 4;
            var udc = command.Udc ?? Array.Empty<byte>();
            var dataSize = udc.Length;
            
            // Determine Lc size
            var lcSize = 1;
            if (binaryCommand.Length > headerSize && binaryCommand[headerSize] == 0x00)
            {
                lcSize = 3;
            }
            
            // Calculate where Le starts
            var leStartPos = headerSize + lcSize + dataSize;
            
            // Copy everything except Le
            if (leStartPos < binaryCommand.Length)
            {
                macInputBytes = new byte[leStartPos];
                Array.Copy(binaryCommand, 0, macInputBytes, 0, leStartPos);
            }
        }
        
        return Result.Success<byte[], SmartCardError>(macInputBytes);
    }
}