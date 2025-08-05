using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// Common cryptogram operations shared between SCP protocols.
/// All methods are pure static functions with no side effects.
/// </summary>
[PublicAPI]
public static class ScpCryptogramOperations
{
    /// <summary>
    /// Builds card cryptogram data for SCP02.
    /// Per GP Card Specification Appendix E.4.2.1: Host Challenge (8) || Sequence Counter (2) || Card Challenge (6)
    /// with ISO 7816-4 padding to 24 bytes total.
    /// </summary>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <param name="hostChallenge">The host challenge.</param>
    /// <returns>The SCP02 card cryptogram data.</returns>
    public static Result<byte[], SmartCardError> BuildScp02CardCryptogramData(
        InitializeUpdateResponse response,
        byte[] hostChallenge)
    {
        var hostValidation = ScpCommonOperations.ValidateHostChallenge(hostChallenge);
        if (hostValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidData(hostValidation.Error));
            
        var cardValidation = ScpCommonOperations.ValidateCardChallenge(response.CardChallenge, 6);
        if (cardValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidResponse(cardValidation.Error));
            
        return ExtractScp02SequenceCounter(response)
            .Map(sequenceCounter =>
            {
                // SCP02 card cryptogram data: Host Challenge (8) || Sequence Counter (2) || Card Challenge (6)
                var hostBytes = hostChallenge;
                var seqCounterBytes = sequenceCounter.Length >= 2 ? sequenceCounter[..2] : sequenceCounter; // First 2 bytes
                var cardBytes = response.CardChallenge; // Already 6 bytes for SCP02
                    
                var data = CryptographicOperations.ConcatenateArrays(hostBytes, seqCounterBytes, cardBytes);
                    
                // Apply ISO 7816-4 padding to make 24 bytes total
                return CryptographicOperations.PadToLength(data, 24).Value;
            });
    }

    /// <summary>
    /// Builds host cryptogram data for SCP02.
    /// Per GP Card Specification Appendix E.4.2.2: Sequence Counter (2) || Card Challenge (6) || Host Challenge (8)
    /// with ISO 7816-4 padding to 24 bytes total.
    /// </summary>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <param name="hostChallenge">The host challenge.</param>
    /// <returns>The SCP02 host cryptogram data.</returns>
    public static Result<byte[], SmartCardError> BuildScp02HostCryptogramData(
        InitializeUpdateResponse response,
        byte[] hostChallenge)
    {
        var hostValidation = ScpCommonOperations.ValidateHostChallenge(hostChallenge);
        if (hostValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidData(hostValidation.Error));
            
        var cardValidation = ScpCommonOperations.ValidateCardChallenge(response.CardChallenge, 6);
        if (cardValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidResponse(cardValidation.Error));
            
        return ExtractScp02SequenceCounter(response)
            .Map(sequenceCounter =>
            {
                // SCP02 host cryptogram data: Sequence Counter (2) || Card Challenge (6) || Host Challenge (8)
                var seqCounterBytes = sequenceCounter.Length >= 2 ? sequenceCounter[..2] : sequenceCounter; // First 2 bytes
                var cardBytes = response.CardChallenge; // Already 6 bytes for SCP02
                var hostBytes = hostChallenge;
                    
                var data = CryptographicOperations.ConcatenateArrays(seqCounterBytes, cardBytes, hostBytes);
                    
                // Apply ISO 7816-4 padding to make 24 bytes total
                return CryptographicOperations.PadToLength(data, 24).Value;
            });
    }

    /// <summary>
    /// Builds card cryptogram data for SCP03.
    /// Per GP SCP03 Specification: Host Challenge (8) || Card Challenge (8) (no padding required).
    /// </summary>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <param name="hostChallenge">The host challenge.</param>
    /// <returns>The SCP03 card cryptogram data.</returns>
    public static Result<byte[], SmartCardError> BuildScp03CardCryptogramData(
        InitializeUpdateResponse response,
        byte[] hostChallenge)
    {
        var hostValidation = ScpCommonOperations.ValidateHostChallenge(hostChallenge);
        if (hostValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidData(hostValidation.Error));
            
        var cardValidation = ScpCommonOperations.ValidateCardChallenge(response.CardChallenge, 8);
        if (cardValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidResponse(cardValidation.Error));
            
        // SCP03 card cryptogram data: Host Challenge (8) || Card Challenge (8)
        return Result.Success<byte[], SmartCardError>(
            CryptographicOperations.ConcatenateArrays(hostChallenge, response.CardChallenge));
    }

    /// <summary>
    /// Builds host cryptogram data for SCP03.
    /// Per GP SCP03 Specification: Card Challenge (8) || Host Challenge (8) (no padding required).
    /// </summary>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <param name="hostChallenge">The host challenge.</param>
    /// <returns>The SCP03 host cryptogram data.</returns>
    public static Result<byte[], SmartCardError> BuildScp03HostCryptogramData(
        InitializeUpdateResponse response,
        byte[] hostChallenge)
    {
        var hostValidation = ScpCommonOperations.ValidateHostChallenge(hostChallenge);
        if (hostValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidData(hostValidation.Error));
            
        var cardValidation = ScpCommonOperations.ValidateCardChallenge(response.CardChallenge, 8);
        if (cardValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidResponse(cardValidation.Error));
            
        // SCP03 host cryptogram data: Card Challenge (8) || Host Challenge (8)
        return Result.Success<byte[], SmartCardError>(
            CryptographicOperations.ConcatenateArrays(response.CardChallenge, hostChallenge));
    }

    /// <summary>
    /// Verifies a card cryptogram against expected value.
    /// </summary>
    /// <param name="expectedCryptogram">The expected cryptogram.</param>
    /// <param name="actualCryptogram">The actual cryptogram from card.</param>
    /// <returns>True if cryptograms match, false otherwise.</returns>
    public static bool VerifyCryptogram(byte[] expectedCryptogram, byte[] actualCryptogram)
    {
        if (expectedCryptogram == null || actualCryptogram == null)
            return false;
            
        if (expectedCryptogram.Length != actualCryptogram.Length)
            return false;
            
        // Use constant-time comparison to prevent timing attacks
        return CryptographicOperations.CompareBytes(expectedCryptogram, actualCryptogram);
    }

    /// <summary>
    /// Creates cryptogram verification function for a specific protocol.
    /// Returns a function that can verify cryptograms using the appropriate data builder.
    /// </summary>
    /// <param name="buildCryptogramData">Function to build protocol-specific cryptogram data.</param>
    /// <param name="calculateCryptogram">Function to calculate cryptogram from data.</param>
    /// <returns>A cryptogram verification function.</returns>
    public static Func<InitializeUpdateResponse, byte[], byte[], bool> CreateCryptogramVerifier(
        Func<InitializeUpdateResponse, byte[], Result<byte[], SmartCardError>> buildCryptogramData,
        Func<byte[], byte[], Result<byte[], SmartCardError>> calculateCryptogram)
    {
        return (response, hostChallenge, macKey) =>
        {
            var dataResult = buildCryptogramData(response, hostChallenge);
            if (dataResult.IsFailure)
                return false;
                
            var cryptogramResult = calculateCryptogram(macKey, dataResult.Value);
            if (cryptogramResult.IsFailure)
                return false;
                
            return VerifyCryptogram(cryptogramResult.Value, response.CardCryptogram);
        };
    }

    /// <summary>
    /// Creates cryptogram calculation function for a specific protocol.
    /// Returns a function that can calculate cryptograms using the appropriate data builder.
    /// </summary>
    /// <param name="buildCryptogramData">Function to build protocol-specific cryptogram data.</param>
    /// <param name="calculateCryptogram">Function to calculate cryptogram from data.</param>
    /// <returns>A cryptogram calculation function.</returns>
    public static Func<InitializeUpdateResponse, byte[], byte[], Result<byte[], SmartCardError>> CreateCryptogramCalculator(
        Func<InitializeUpdateResponse, byte[], Result<byte[], SmartCardError>> buildCryptogramData,
        Func<byte[], byte[], Result<byte[], SmartCardError>> calculateCryptogram)
    {
        return (response, hostChallenge, macKey) =>
        {
            return buildCryptogramData(response, hostChallenge)
                .Bind(data => calculateCryptogram(macKey, data));
        };
    }

    // Private helper methods

    /// <summary>
    /// Extracts the sequence counter from an SCP02 INITIALIZE UPDATE response.
    /// </summary>
    /// <param name="response">The response.</param>
    /// <returns>The sequence counter.</returns>
    private static Result<byte[], SmartCardError> ExtractScp02SequenceCounter(InitializeUpdateResponse response)
    {
        return response.SequenceCounter switch
        {
            null => Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidResponse("SCP02 requires sequence counter in INITIALIZE UPDATE response")),
            { Length: < 2 } => Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidResponse($"SCP02 sequence counter must be at least 2 bytes, got {response.SequenceCounter.Length}")),
            _ => Result.Success<byte[], SmartCardError>(response.SequenceCounter)
        };
    }

}