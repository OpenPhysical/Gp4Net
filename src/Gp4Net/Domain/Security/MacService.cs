using System;
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
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(data);

        if (key.Length == 0)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("Key cannot be empty"));
        }

        try
        {

            if (key.Length != 16 && key.Length != 24)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument("3DES key must be 16 or 24 bytes"));
            }

            if (macLength < 1 || macLength > 8)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument("MAC length must be between 1 and 8 bytes"));
            }

            _logger.LogTrace("Calculating 3DES MAC over {DataLength} bytes", data.Length);

            // Use ISO 9797-1 MAC Algorithm 3 (retail MAC) with ISO 7816-4 padding
            // Per GP Card Spec v2.3.1 Section B.1.2.2: uses ISO/IEC 9797-1 padding method 2
            // IMPORTANT: ISO9797Alg3Mac requires a DesEngine, not DesEdeEngine
            // The MAC algorithm handles the 3DES transformation internally
            var mac = new ISO9797Alg3Mac(new DesEngine(), new ISO7816d4Padding());
            mac.Init(new KeyParameter(key));
            mac.BlockUpdate(data, 0, data.Length);

            var fullMac = new byte[8];
            mac.DoFinal(fullMac, 0);

            // Return requested MAC length
            if (macLength == 8)
            {
                return Result.Success<byte[], SmartCardError>(fullMac);
            }
            else
            {
                var truncatedMac = new byte[macLength];
                Array.Copy(fullMac, 0, truncatedMac, 0, macLength);
                return Result.Success<byte[], SmartCardError>(truncatedMac);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to calculate 3DES MAC");
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.CryptographicError($"3DES MAC calculation failed: {ex.Message}"));
        }
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
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(data);

        if (key.Length == 0)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("Key cannot be empty"));
        }

        try
        {

            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument("AES key must be 16, 24, or 32 bytes"));
            }

            if (macLength < 1 || macLength > 16)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument("MAC length must be between 1 and 16 bytes"));
            }

            _logger.LogTrace("Calculating AES-CMAC over {DataLength} bytes", data.Length);

            // Calculate CMAC
            var cmac = new CMac(new AesEngine(), macLength * 8); // macLength in bits
            cmac.Init(new KeyParameter(key));
            cmac.BlockUpdate(data, 0, data.Length);

            var mac = new byte[macLength];
            cmac.DoFinal(mac, 0);

            return Result.Success<byte[], SmartCardError>(mac);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to calculate AES-CMAC");
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.CryptographicError($"AES-CMAC calculation failed: {ex.Message}"));
        }
    }

    /// <summary>
    /// Calculates a MAC with chaining for protocols that require it.
    /// Updates the chaining value for subsequent MAC calculations.
    /// </summary>
    /// <param name="key">The MAC key.</param>
    /// <param name="data">The data to calculate MAC over.</param>
    /// <param name="chainingValue">The current chaining value (will be updated).</param>
    /// <param name="protocol">The secure channel protocol version.</param>
    /// <param name="macLength">The desired MAC length in bytes.</param>
    /// <returns>The calculated MAC or an error.</returns>
    public Result<byte[], SmartCardError> CalculateMacWithChaining(
        byte[] key,
        byte[] data,
        ref byte[] chainingValue,
        ScpVersion protocol,
        int macLength = 8)
    {
        try
        {
            // For SCP03, prepend chaining value to data
            if (protocol == ScpVersion.Scp03 && chainingValue != null && chainingValue.Length > 0)
            {
                var chainedData = new byte[chainingValue.Length + data.Length];
                Array.Copy(chainingValue, 0, chainedData, 0, chainingValue.Length);
                Array.Copy(data, 0, chainedData, chainingValue.Length, data.Length);
                
                var result = CalculateMac(key, chainedData, protocol, macLength);
                
                // Update chaining value with the calculated MAC
                if (result.IsSuccess)
                {
                    chainingValue = result.Value;
                }
                
                return result;
            }
            else
            {
                // No chaining or first MAC in chain
                var result = CalculateMac(key, data, protocol, macLength);
                
                // Initialize or update chaining value
                if (result.IsSuccess && protocol == ScpVersion.Scp03)
                {
                    chainingValue = result.Value;
                }
                
                return result;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to calculate MAC with chaining");
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.CryptographicError($"MAC calculation with chaining failed: {ex.Message}"));
        }
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
}