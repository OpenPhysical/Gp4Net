using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Centralized service for MAC (Message Authentication Code) calculations.
/// Eliminates DRY violations by providing a single implementation for all MAC operations.
/// Uses BouncyCastle exclusively for cryptographic operations.
/// </summary>
public sealed class MacService
{
    private readonly ILogger<MacService> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="MacService"/> class.
    /// </summary>
    /// <param name="logger">The logger instance. If null, uses NullLogger.</param>
    public MacService(ILogger<MacService> logger = null)
    {
        _logger = logger ?? NullLogger<MacService>.Instance;
    }

    /// <summary>
    /// Calculates a MAC using the appropriate algorithm based on the protocol.
    /// </summary>
    /// <param name="key">The MAC key.</param>
    /// <param name="data">The data to calculate MAC over.</param>
    /// <param name="protocol">The secure channel protocol version.</param>
    /// <param name="macLength">The desired MAC length in bytes (default is 8).</param>
    /// <returns>The calculated MAC or an error.</returns>
    public Result<byte[], SmartCardError> CalculateMac(
        byte[] key,
        byte[] data,
        ScpVersion protocol,
        int macLength = 8)
    {
        _logger.LogDebug("Calculating MAC for {Protocol}, output length: {MacLength} bytes", protocol, macLength);

        return protocol switch
        {
            ScpVersion.Scp02 => Calculate3DesMac(key, data, macLength),
            ScpVersion.Scp03 => CalculateAesCmac(key, data, macLength),
            _ => Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument($"Unsupported protocol: {protocol}"))
        };
    }

    /// <summary>
    /// Calculates a 3DES MAC using ISO 9797-1 MAC Algorithm 3.
    /// Per GlobalPlatform Card Specification v2.3.1 Section B.1.2.2 "Retail MAC":
    /// "The Retail MAC is also known as the Single DES Plus Final Triple DES MAC"
    /// Used for SCP02 C-MAC and R-MAC generation as specified in Section E.4.3.
    /// </summary>
    /// <param name="key">The 3DES key (16 or 24 bytes).</param>
    /// <param name="data">The data to calculate MAC over.</param>
    /// <param name="macLength">The desired MAC length in bytes.</param>
    /// <returns>The calculated MAC or an error.</returns>
    public Result<byte[], SmartCardError> Calculate3DesMac(
        byte[] key,
        byte[] data,
        int macLength = 8)
    {
        if (key is null)
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("Key cannot be null"));
        
        if (data is null)
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("Data cannot be null"));

        if (key.Length == 0)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("Key cannot be empty"));
        }

        var keyValidationResult = ValidateKeyLength(key, new[] { 16, 24 }, "3DES key must be 16 or 24 bytes");
        if (keyValidationResult.IsFailure)
            return Result.Failure<byte[], SmartCardError>(keyValidationResult.Error);
            
        var macLengthResult = ValidateMacLength(macLength, 1, 8, "MAC length must be between 1 and 8 bytes");
        if (macLengthResult.IsFailure)
            return Result.Failure<byte[], SmartCardError>(macLengthResult.Error);
            
        return Result.Try(() =>
            {
                _logger.LogTrace("Calculating 3DES MAC over {DataLength} bytes", data.Length);

                // Use ISO 9797-1 MAC Algorithm 3 (retail MAC) with ISO 7816-4 padding
                // Per GP Card Spec v2.3.1 Section B.1.2.2: uses ISO/IEC 9797-1 padding method 2
                // IMPORTANT: ISO9797Alg3Mac requires a DesEngine, not DesEdeEngine
                // The MAC algorithm handles the 3DES transformation internally
                var mac = new ISO9797Alg3Mac(new DesEngine(), new ISO7816d4Padding());
                mac.Init(new KeyParameter(key));
                mac.BlockUpdate(data, 0, data.Length);

                var fullMac = new byte[8];
                _ = mac.DoFinal(fullMac, 0);

                // Return requested MAC length
                if (macLength == 8)
                {
                    return fullMac;
                }
                else
                {
                    var truncatedMac = new byte[macLength];
                    Array.Copy(fullMac, 0, truncatedMac, 0, macLength);
                    return truncatedMac;
                }
            }, ex => 
            {
                _logger.LogError(ex, "Failed to calculate 3DES MAC");
                return SmartCardError.CryptographicError($"3DES MAC calculation failed: {ex.Message}");
            });
    }

    /// <summary>
    /// Calculates an AES-CMAC.
    /// Per GlobalPlatform SCP03 v1.1.1 Section 4.1.3 "MACing":
    /// "Calculation and verification of MACs shall use the CMAC scheme specified in [NIST 800-38B]"
    /// Section 6.2.4: "A C-MAC is generated...uses the S-MAC key"
    /// For SCP03, the MAC is truncated to 8 bytes for APDUs (Section 6.2.4).
    /// </summary>
    /// <param name="key">The AES key (16, 24, or 32 bytes).</param>
    /// <param name="data">The data to calculate MAC over.</param>
    /// <param name="macLength">The desired MAC length in bytes.</param>
    /// <returns>The calculated MAC or an error.</returns>
    public Result<byte[], SmartCardError> CalculateAesCmac(
        byte[] key,
        byte[] data,
        int macLength = 8)
    {
        if (key is null)
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("Key cannot be null"));
        
        if (data is null)
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("Data cannot be null"));

        if (key.Length == 0)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("Key cannot be empty"));
        }

        var keyValidationResult = ValidateKeyLength(key, new[] { 16, 24, 32 }, "AES key must be 16, 24, or 32 bytes");
        if (keyValidationResult.IsFailure)
            return Result.Failure<byte[], SmartCardError>(keyValidationResult.Error);
            
        var macLengthResult = ValidateMacLength(macLength, 1, 16, "MAC length must be between 1 and 16 bytes");
        if (macLengthResult.IsFailure)
            return Result.Failure<byte[], SmartCardError>(macLengthResult.Error);
            
        return Result.Try(() =>
            {
                _logger.LogTrace("Calculating AES-CMAC over {DataLength} bytes", data.Length);

                // Calculate CMAC
                var cmac = new CMac(new AesEngine(), macLength * 8); // macLength in bits
                cmac.Init(new KeyParameter(key));
                cmac.BlockUpdate(data, 0, data.Length);

                var mac = new byte[macLength];
                _ = cmac.DoFinal(mac, 0);

                return mac;
            }, ex => 
            {
                _logger.LogError(ex, "Failed to calculate AES-CMAC");
                return SmartCardError.CryptographicError($"AES-CMAC calculation failed: {ex.Message}");
            });
    }

    /// <summary>
    /// Calculates a MAC with chaining for protocols that require it.
    /// Updates the chaining value for subsequent MAC calculations.
    /// </summary>
    /// <param name="key">The MAC key.</param>
    /// <param name="data">The data to calculate MAC over.</param>
    /// <param name="chainingValue">The current chaining state.</param>
    /// <param name="protocol">The secure channel protocol version.</param>
    /// <param name="macLength">The desired MAC length in bytes.</param>
    /// <returns>A result containing the MAC and new chaining state, or an error.</returns>
    public Result<(byte[] mac, byte[] newChainingValue), SmartCardError> CalculateMacWithChaining(
        byte[] key,
        byte[] data,
        byte[] chainingValue,
        ScpVersion protocol,
        int macLength = 8)
    {
        var chainingMaybe = Maybe<byte[]>.From(chainingValue);
        var preparedDataResult = chainingMaybe.Match(
            Some: chainData => 
                (protocol == ScpVersion.Scp03 && chainData.Length > 0)
                    ? Result.Success<(byte[], bool), SmartCardError>((
                        CombineArrays(chainData, data),
                        true))
                    : Result.Success<(byte[], bool), SmartCardError>((data, false)),
            None: () => Result.Success<(byte[], bool), SmartCardError>((data, false)));
                
        return preparedDataResult
        .Bind(preparedData =>
        {
            var (macData, isChained) = preparedData;
            return CalculateMac(key, macData, protocol, macLength)
                .Map(mac => 
                {
                    // Return both MAC and new chaining state
                    var newChainingState = (isChained || protocol == ScpVersion.Scp03) ? mac : chainingValue;
                    return (mac, newChainingState);
                });
        });
    }

    /// <summary>
    /// Verifies a MAC by comparing it with a calculated MAC.
    /// </summary>
    /// <param name="key">The MAC key.</param>
    /// <param name="data">The data to verify MAC for.</param>
    /// <param name="expectedMac">The expected MAC value.</param>
    /// <param name="protocol">The secure channel protocol version.</param>
    /// <returns>Success (true) if MAC is valid, failure with error otherwise.</returns>
    public Result<bool, SmartCardError> VerifyMac(
        byte[] key,
        byte[] data,
        byte[] expectedMac,
        ScpVersion protocol)
    {
        if (expectedMac == null || expectedMac.Length == 0)
        {
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument("Expected MAC cannot be null or empty"));
        }

        return CalculateMac(key, data, protocol, expectedMac.Length)
            .Bind(calculatedMac =>
            {
                // Constant-time comparison to prevent timing attacks
                var isValid = true;
                for (var i = 0; i < expectedMac.Length; i++)
                {
                    isValid &= calculatedMac[i] == expectedMac[i];
                }

                return isValid
                    ? Result.Success<bool, SmartCardError>(true)
                    : Result.Failure<bool, SmartCardError>(
                        SmartCardError.SecurityError("MAC verification failed"));
            });
    }

    private static UnitResult<SmartCardError> ValidateKeyLength(byte[] key, int[] validLengths, string errorMessage)
    {
        return validLengths.Contains(key.Length)
            ? UnitResult.Success<SmartCardError>()
            : UnitResult.Failure<SmartCardError>(SmartCardError.InvalidArgument(errorMessage));
    }

    private static UnitResult<SmartCardError> ValidateMacLength(int macLength, int minLength, int maxLength, string errorMessage)
    {
        return (macLength >= minLength && macLength <= maxLength)
            ? UnitResult.Success<SmartCardError>()
            : UnitResult.Failure<SmartCardError>(SmartCardError.InvalidArgument(errorMessage));
    }

    /// <summary>
    /// Combines two byte arrays into a single array using functional approach.
    /// </summary>
    private static byte[] CombineArrays(byte[] first, byte[] second)
    {
        var result = new byte[first.Length + second.Length];
        first.CopyTo(result, 0);
        second.CopyTo(result, first.Length);
        return result;
    }
}
