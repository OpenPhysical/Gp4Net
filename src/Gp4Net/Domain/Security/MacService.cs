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
/// Defines the specific usage context for MAC calculations.
/// Different SCP protocols and operations require different MAC algorithms.
/// </summary>
public enum MacUsage
{
    /// <summary>
    /// Command MAC (C-MAC) for APDU commands.
    /// SCP02: Uses Retail MAC (ISO 9797-1 Algorithm 3).
    /// SCP03: Uses AES-CMAC (NIST 800-38B).
    /// </summary>
    Command,
    
    /// <summary>
    /// Response MAC (R-MAC) for APDU responses.
    /// SCP02: Uses Retail MAC (ISO 9797-1 Algorithm 3).
    /// SCP03: Uses AES-CMAC (NIST 800-38B).
    /// </summary>
    Response,
    
    /// <summary>
    /// Authentication cryptograms (card/host cryptograms).
    /// SCP02: Uses Full 3DES MAC (ISO 9797-1 Algorithm 1).
    /// SCP03: Uses AES-CMAC with data derivation scheme.
    /// </summary>
    Cryptogram
}

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
    /// Calculates a MAC using the appropriate algorithm based on the protocol and usage context.
    /// Automatically routes to the correct algorithm per GlobalPlatform specifications.
    /// </summary>
    /// <param name="key">The MAC key.</param>
    /// <param name="data">The data to calculate MAC over.</param>
    /// <param name="protocol">The secure channel protocol version.</param>
    /// <param name="usage">The specific usage context (Command, Response, or Cryptogram).</param>
    /// <param name="macLength">The desired MAC length in bytes (default is 8).</param>
    /// <returns>The calculated MAC or an error.</returns>
    public Result<byte[], SmartCardError> CalculateMac(
        byte[] key,
        byte[] data,
        ScpVersion protocol,
        MacUsage usage = MacUsage.Command,
        int macLength = 8)
    {
        _logger.LogDebug("Calculating MAC for {Protocol} {Usage}, output length: {MacLength} bytes", protocol, usage, macLength);
        System.Console.WriteLine($"🔍 MacService.CalculateMac - Protocol: {protocol}, Usage: {usage}, Key: {Convert.ToHexString(key)}, Data: {Convert.ToHexString(data)}");

        return (protocol, usage) switch
        {
            // SCP02 routing based on usage context per GP Card Spec v2.3.1
            (ScpVersion.Scp02, MacUsage.Command or MacUsage.Response) => 
                Calculate3DesRetailMac(key, data, macLength),  // ISO 9797-1 Algorithm 3
            
            (ScpVersion.Scp02, MacUsage.Cryptogram) => 
                Calculate3DesFullMac(key, data, macLength),    // ISO 9797-1 Algorithm 1
            
            // SCP03 uses AES-CMAC for all operations per GP SCP03 v1.1.1
            (ScpVersion.Scp03, _) => 
                CalculateAesCmac(key, data, macLength),        // NIST 800-38B CMAC
            
            _ => Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument($"Unsupported protocol/usage: {protocol}/{usage}"))
        };
    }

    /// <summary>
    /// Calculates a 3DES MAC using ISO 9797-1 MAC Algorithm 3 (Retail MAC).
    /// Per GlobalPlatform Card Specification v2.3.1 Section B.1.2.2 "Single DES Plus Final Triple DES MAC":
    /// "This is also known as the Retail MAC. It is as defined in [ISO 9797-1] as MAC Algorithm 3."
    /// Used for SCP02 C-MAC and R-MAC generation as specified in Section E.4.3.
    /// </summary>
    /// <param name="key">The 3DES key (16 or 24 bytes).</param>
    /// <param name="data">The data to calculate MAC over.</param>
    /// <param name="macLength">The desired MAC length in bytes.</param>
    /// <returns>The calculated MAC or an error.</returns>
    public Result<byte[], SmartCardError> Calculate3DesRetailMac(
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
                _logger.LogTrace("Calculating 3DES Retail MAC over {DataLength} bytes", data.Length);
                _logger.LogDebug("🔍 Retail MAC Debug - Key: {Key}, Data: {Data}", Convert.ToHexString(key), Convert.ToHexString(data));
                System.Console.WriteLine($"🔍 MacService Retail MAC - Key: {Convert.ToHexString(key)}, Data: {Convert.ToHexString(data)}");

                // Use ISO 9797-1 MAC Algorithm 3 (retail MAC) with ISO 7816-4 padding
                // Per GP Card Spec v2.3.1 Section B.1.2.2: uses ISO/IEC 9797-1 padding method 2
                // IMPORTANT: ISO9797Alg3Mac requires a DesEngine, not DesEdeEngine
                // The MAC algorithm handles the 3DES transformation internally
                var mac = new ISO9797Alg3Mac(new DesEngine(), new ISO7816d4Padding());
                mac.Init(new KeyParameter(key));
                mac.BlockUpdate(data, 0, data.Length);

                var fullMac = new byte[8];
                _ = mac.DoFinal(fullMac, 0);
                
                System.Console.WriteLine($"🔍 MacService Retail MAC Result: {Convert.ToHexString(fullMac)}");

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
    /// Backward compatibility wrapper for the old Calculate3DesMac method.
    /// Routes to Calculate3DesRetailMac (ISO 9797-1 Algorithm 3) for existing code.
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
        return Calculate3DesRetailMac(key, data, macLength);
    }

    /// <summary>
    /// Calculates a 3DES MAC using ISO 9797-1 MAC Algorithm 1 (Full Triple DES MAC).
    /// Per GlobalPlatform Card Specification v2.3.1 Section B.1.2.1 "Full Triple DES MAC":
    /// "The full triple DES MAC is as defined in [ISO 9797-1] as MAC Algorithm 1, with initial 
    /// transformation 1 and output transformation 1, without truncation, and with Triple DES 
    /// taking the place of the block cipher."
    /// Used for SCP02 authentication cryptogram calculations as specified in Section E.4.2.
    /// </summary>
    /// <param name="key">The 3DES key (16 or 24 bytes).</param>
    /// <param name="data">The data to calculate MAC over (must be padded to 8-byte blocks).</param>
    /// <param name="macLength">The desired MAC length in bytes.</param>
    /// <returns>The calculated MAC or an error.</returns>
    public Result<byte[], SmartCardError> Calculate3DesFullMac(
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

        // Validate data is padded to 8-byte blocks
        if (data.Length % 8 != 0)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("Data must be padded to 8-byte blocks for Full 3DES MAC"));
        }
            
        return Result.Try(() =>
            {
                _logger.LogTrace("Calculating Full 3DES MAC (ISO 9797-1 Algorithm 1) over {DataLength} bytes", data.Length);

                // Full 3DES CBC-MAC with zero IV per ISO 9797-1 Algorithm 1
                var zeroIv = new byte[8];
                var engine = new DesEdeEngine();
                var blockCipher = new Org.BouncyCastle.Crypto.Modes.CbcBlockCipher(engine);
                blockCipher.Init(true, new ParametersWithIV(new KeyParameter(key), zeroIv));

                // Process all blocks with CBC chaining using functional aggregation
                var blockCount = data.Length / 8;
                var mac = Enumerable.Range(0, blockCount)
                    .Aggregate(new byte[8], (currentMac, blockIndex) =>
                    {
                        var blockStart = blockIndex * 8;
                        var inputBlock = new byte[8];
                        Array.Copy(data, blockStart, inputBlock, 0, 8);
                        
                        // XOR with previous MAC (CBC chaining) using functional transformation
                        var xorBlock = inputBlock.Select((b, i) => (byte)(b ^ currentMac[i])).ToArray();
                        
                        // Encrypt with 3DES
                        var result = new byte[8];
                        blockCipher.ProcessBlock(xorBlock, 0, result, 0);
                        return result;
                    });

                // Return requested MAC length
                return macLength == 8 
                    ? mac 
                    : mac.Take(macLength).ToArray();
            }, ex => 
            {
                _logger.LogError(ex, "Failed to calculate Full 3DES MAC");
                return SmartCardError.CryptographicError($"Full 3DES MAC calculation failed: {ex.Message}");
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
                var cmac = new CMac(new AesEngine(), 128); // AES block size in bits
                cmac.Init(new KeyParameter(key));
                cmac.BlockUpdate(data, 0, data.Length);

                var fullMac = new byte[16]; // AES-CMAC is always 16 bytes
                _ = cmac.DoFinal(fullMac, 0);

                // Truncate to requested length
                var mac = new byte[macLength];
                Array.Copy(fullMac, 0, mac, 0, macLength);
                
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
            return CalculateMac(key, macData, protocol, MacUsage.Command, macLength)
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

        return CalculateMac(key, data, protocol, MacUsage.Command, expectedMac.Length)
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
