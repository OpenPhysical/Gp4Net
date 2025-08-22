using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Service for calculating cryptographic authentication values (cryptograms) according to GlobalPlatform specifications.
/// Implements proper cryptogram calculation for SCP02 and SCP03 protocols.
/// Per GP SCP03 v1.1.1 Section 6.2.2: SCP03 cryptograms use data derivation scheme (KDF).
/// Per GP Card Spec v2.3.1 Section E.4.2: SCP02 cryptograms use Full 3DES MAC.
/// </summary>
public sealed class CryptogramService
{
    private readonly ILogger<CryptogramService> _logger;
    private readonly KeyDerivationService _keyDerivationService;

    /// <summary>
    /// Initializes a new instance of the <see cref="CryptogramService"/> class.
    /// </summary>
    /// <param name="logger">Optional logger instance.</param>
    /// <param name="keyDerivationService">Optional key derivation service. If null, creates a new instance.</param>
    public CryptogramService(ILogger<CryptogramService> logger = null, KeyDerivationService keyDerivationService = null)
    {
        _logger = logger ?? NullLogger<CryptogramService>.Instance;
        _keyDerivationService = keyDerivationService ?? new KeyDerivationService();
    }

    /// <summary>
    /// Calculates a card cryptogram for the specified protocol.
    /// Per GP SCP03 v1.1.1 Section 6.2.2.2: SCP03 uses data derivation scheme with S-MAC key.
    /// Per GP Card Spec v2.3.1 Section E.4.2.1: SCP02 uses Full 3DES MAC with S-ENC key.
    /// </summary>
    /// <param name="key">The MAC key to use for cryptogram calculation.</param>
    /// <param name="hostChallenge">The host challenge (8 bytes).</param>
    /// <param name="cardChallenge">The card challenge (8 bytes).</param>
    /// <param name="sequenceCounter">The sequence counter (SCP02 only).</param>
    /// <param name="protocol">The SCP protocol version.</param>
    /// <returns>The calculated card cryptogram (8 bytes) or an error.</returns>
    public Result<byte[], SmartCardError> CalculateCardCryptogram(
        byte[] key,
        byte[] hostChallenge,
        byte[] cardChallenge,
        Maybe<byte[]> sequenceCounter,
        ScpVersion protocol)
    {
        _logger.LogDebug("Calculating card cryptogram for {Protocol}", protocol);

        return protocol switch
        {
            ScpVersion.Scp02 => CalculateScp02CardCryptogram(key, hostChallenge, cardChallenge, sequenceCounter),
            ScpVersion.Scp03 => CalculateScp03CardCryptogram(key, hostChallenge, cardChallenge),
            _ => Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument($"Unsupported protocol: {protocol}"))
        };
    }

    /// <summary>
    /// Calculates a host cryptogram for the specified protocol.
    /// Per GP SCP03 v1.1.1 Section 6.2.2.3: SCP03 uses data derivation scheme with S-MAC key.
    /// Per GP Card Spec v2.3.1 Section E.4.2.2: SCP02 uses Full 3DES MAC with S-ENC key.
    /// </summary>
    /// <param name="key">The MAC key to use for cryptogram calculation.</param>
    /// <param name="hostChallenge">The host challenge (8 bytes).</param>
    /// <param name="cardChallenge">The card challenge (8 bytes).</param>
    /// <param name="sequenceCounter">The sequence counter (SCP02 only).</param>
    /// <param name="protocol">The SCP protocol version.</param>
    /// <returns>The calculated host cryptogram (8 bytes) or an error.</returns>
    public Result<byte[], SmartCardError> CalculateHostCryptogram(
        byte[] key,
        byte[] hostChallenge,
        byte[] cardChallenge,
        Maybe<byte[]> sequenceCounter,
        ScpVersion protocol)
    {
        _logger.LogDebug("Calculating host cryptogram for {Protocol}", protocol);

        return protocol switch
        {
            ScpVersion.Scp02 => CalculateScp02HostCryptogram(key, hostChallenge, cardChallenge, sequenceCounter),
            ScpVersion.Scp03 => CalculateScp03HostCryptogram(key, hostChallenge, cardChallenge),
            _ => Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument($"Unsupported protocol: {protocol}"))
        };
    }

    /// <summary>
    /// Calculates a generic cryptogram using the specified protocol and data.
    /// This is a lower-level method for custom cryptogram calculations.
    /// NOTE: For SCP03 authentication cryptograms, use CalculateCardCryptogram/CalculateHostCryptogram instead,
    /// as they properly use the data derivation scheme per GP SCP03 v1.1.1 Section 6.2.2.
    /// </summary>
    /// <param name="key">The key to use for cryptogram calculation.</param>
    /// <param name="data">The data to authenticate.</param>
    /// <param name="protocol">The SCP protocol version.</param>
    /// <returns>The calculated cryptogram or an error.</returns>
    public Result<byte[], SmartCardError> CalculateCryptogram(
        byte[] key,
        byte[] data,
        ScpVersion protocol)
    {
        _logger.LogDebug("Calculating generic cryptogram for {Protocol}", protocol);

        return protocol switch
        {
            // For SCP02, use Full 3DES MAC directly (data should already be properly padded)
            ScpVersion.Scp02 => CryptographicOperations.CalculateFull3DesMac(key, data),
            ScpVersion.Scp03 => CalculateAesCmac(key, data).Map(mac => mac[..8]), // Return first 8 bytes - for C-MAC/R-MAC only
            _ => Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument($"Unsupported protocol: {protocol}"))
        };
    }

    /// <summary>
    /// Calculates SCP02 card cryptogram using 3DES-CBC-MAC.
    /// Per GlobalPlatform Card Specification v2.3.1 Section E.4.2.1.
    /// Data format: Host Challenge (8) || Sequence Counter (2) || Card Challenge (6) || Padding.
    /// </summary>
    private Result<byte[], SmartCardError> CalculateScp02CardCryptogram(
        byte[] key,
        byte[] hostChallenge,
        byte[] cardChallenge,
        Maybe<byte[]> sequenceCounter)
    {
        if (sequenceCounter.HasNoValue)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("SCP02 card cryptogram requires sequence counter"));
        }

        var seqCounter = sequenceCounter.Value;
        if (seqCounter.Length != 2)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("SCP02 sequence counter must be 2 bytes"));
        }

        if (cardChallenge.Length != 6)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("SCP02 card challenge must be 6 bytes"));
        }

        // Build cryptogram data: Host Challenge (8) || Sequence Counter (2) || Card Challenge (6) || Padding
        var cryptogramData = new byte[24]; // Padded to 3DES block size
        Array.Copy(hostChallenge, 0, cryptogramData, 0, 8);
        Array.Copy(seqCounter, 0, cryptogramData, 8, 2);
        Array.Copy(cardChallenge, 0, cryptogramData, 10, 6);
        // Apply ISO 7816-4 padding
        cryptogramData[16] = 0x80;
        // Rest is already zeros

        return Calculate3DesCbcMac(key, cryptogramData);
    }

    /// <summary>
    /// Calculates SCP02 host cryptogram using 3DES-CBC-MAC.
    /// Per GlobalPlatform Card Specification v2.3.1 Section E.4.2.2.
    /// Data format: Sequence Counter (2) || Card Challenge (6) || Host Challenge (8) || Padding.
    /// </summary>
    private Result<byte[], SmartCardError> CalculateScp02HostCryptogram(
        byte[] key,
        byte[] hostChallenge,
        byte[] cardChallenge,
        Maybe<byte[]> sequenceCounter)
    {
        if (sequenceCounter.HasNoValue)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("SCP02 host cryptogram requires sequence counter"));
        }

        var seqCounter = sequenceCounter.Value;
        if (seqCounter.Length != 2)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("SCP02 sequence counter must be 2 bytes"));
        }

        if (cardChallenge.Length != 6)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("SCP02 card challenge must be 6 bytes"));
        }

        // Build cryptogram data: Sequence Counter (2) || Card Challenge (6) || Host Challenge (8) || Padding
        var cryptogramData = seqCounter
            .Concat(cardChallenge)
            .Concat(hostChallenge)
            .Concat(new byte[] { 0x80 }) // ISO 7816-4 padding
            .Concat(new byte[7]) // Pad to 24 bytes (3DES block size)
            .ToArray();

        return Calculate3DesCbcMac(key, cryptogramData);
    }

    /// <summary>
    /// Calculates SCP03 card cryptogram using data derivation scheme.
    /// Per GlobalPlatform SCP03 v1.1.1 Section 6.2.2.2:
    /// "The card cryptogram (8 bytes) is calculated using the data derivation scheme defined in section 4.1.5
    /// with the session key S-MAC and the derivation constant set to 'card authentication cryptogram generation'."
    /// Derivation constant: 0x00, Context: Host Challenge (8) || Card Challenge (8), Length: 0x0040 (64 bits).
    /// </summary>
    private Result<byte[], SmartCardError> CalculateScp03CardCryptogram(
        byte[] key,
        byte[] hostChallenge,
        byte[] cardChallenge)
    {
        if (hostChallenge.Length != 8)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("SCP03 host challenge must be 8 bytes"));
        }

        if (cardChallenge.Length != 8)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("SCP03 card challenge must be 8 bytes"));
        }

        // Build context: Host Challenge (8) || Card Challenge (8)
        var context = hostChallenge.Concat(cardChallenge).ToArray();

        // Use data derivation scheme per GP SCP03 v1.1.1 Section 4.1.5
        // Derivation constant 0x00 for card cryptogram (Table 4-1)
        return _keyDerivationService.DeriveScp03Data(
            key,
            DerivationConstants.CardCryptogram,  // 0x00
            context,
            64); // 64 bits = 8 bytes output
    }

    /// <summary>
    /// Calculates SCP03 host cryptogram using data derivation scheme.
    /// Per GlobalPlatform SCP03 v1.1.1 Section 6.2.2.3:
    /// "The host cryptogram (8 bytes) is calculated using the data derivation scheme defined in section 4.1.5
    /// with the session key S-MAC and the derivation constant set to 'host authentication cryptogram generation'."
    /// Derivation constant: 0x01, Context: Host Challenge (8) || Card Challenge (8), Length: 0x0040 (64 bits).
    /// </summary>
    private Result<byte[], SmartCardError> CalculateScp03HostCryptogram(
        byte[] key,
        byte[] hostChallenge,
        byte[] cardChallenge)
    {
        if (hostChallenge.Length != 8)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("SCP03 host challenge must be 8 bytes"));
        }

        if (cardChallenge.Length != 8)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("SCP03 card challenge must be 8 bytes"));
        }

        // Build context: Host Challenge (8) || Card Challenge (8)
        // Note: Same format as card cryptogram per GP specification
        var context = hostChallenge.Concat(cardChallenge).ToArray();

        // Use data derivation scheme per GP SCP03 v1.1.1 Section 4.1.5
        // Derivation constant 0x01 for host cryptogram (Table 4-1)
        return _keyDerivationService.DeriveScp03Data(
            key,
            DerivationConstants.HostCryptogram,  // 0x01
            context,
            64); // 64 bits = 8 bytes output
    }

    /// <summary>
    /// Calculates AES-CMAC using BouncyCastle.
    /// </summary>
    private Result<byte[], SmartCardError> CalculateAesCmac(byte[] key, byte[] data)
    {
        try
        {
            var cmac = new CMac(new AesEngine(), 128);
            cmac.Init(new KeyParameter(key));
            cmac.BlockUpdate(data, 0, data.Length);
            
            var mac = new byte[16];
            _ = cmac.DoFinal(mac, 0);
            
            return Result.Success<byte[], SmartCardError>(mac);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "AES-CMAC calculation failed");
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.CryptographicError($"AES-CMAC failed: {ex.Message}"));
        }
    }

    /// <summary>
    /// Calculates Full 3DES MAC for SCP02 cryptograms.
    /// Per GlobalPlatform Card Specification v2.3.1 Section B.1.2.1 "Full Triple DES":
    /// "The result of the last encryption with the Triple DES key is the MAC."
    /// Used specifically for SCP02 cryptograms as specified in Section E.4.2.
    /// </summary>
    private Result<byte[], SmartCardError> Calculate3DesCbcMac(byte[] key, byte[] data)
    {
        // Use Full 3DES MAC for SCP02 cryptograms (not Retail MAC)
        // Per GP Card Spec v2.3.1 Section E.4.2: "Full Triple DES MAC"
        return Scp02Cryptography.CalculateScp02Cryptogram(key, data);
    }

}