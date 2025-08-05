using System;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Protocol;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Kdf.Modes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.Domain.Keys;

/// <summary>
/// Centralized service for key derivation operations.
/// Eliminates DRY violations by providing a single implementation for SCP02/SCP03 key derivation.
/// Uses KDF108 for SP 800-108 compliant operations and BouncyCastle for cryptographic primitives.
/// </summary>
public sealed class KeyDerivationService : IKeyDerivationService
{
    private readonly ILogger<KeyDerivationService> _logger;
    private readonly CounterModeKdf _kdf;

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyDerivationService"/> class.
    /// </summary>
    /// <param name="logger">The logger instance. If null, uses NullLogger.</param>
    public KeyDerivationService(ILogger<KeyDerivationService> logger = null)
    {
        _logger = logger ?? NullLogger<KeyDerivationService>.Instance;
        _kdf = new CounterModeKdf();
    }

    /// <summary>
    /// Derives session keys for the specified key derivation context.
    /// </summary>
    /// <param name="context">The key derivation context containing all necessary parameters.</param>
    /// <returns>The derived session keys or an error.</returns>
    public Result<SessionKeys, SmartCardError> DeriveSessionKeys(IKeyDerivationContext context)
    {
        _logger.LogDebug("Deriving session keys for {Protocol}", context.Protocol);

        return context.Protocol switch
        {
            ScpVersion.Scp02 => DeriveScp02SessionKeys(context),
            ScpVersion.Scp03 => DeriveScp03SessionKeys(context),
            _ => Result.Failure<SessionKeys, SmartCardError>(
                SmartCardError.InvalidArgument($"Unsupported protocol: {context.Protocol}"))
        };
    }

    /// <summary>
    /// Derives SCP03 session keys using SP 800-108 KDF in counter mode.
    /// Per GlobalPlatform SCP03 v1.1.1 Section 4.1.5 "Data Derivation Scheme" and Section 6.2.1 "Session Keys".
    /// Uses NIST SP 800-108 KDF in counter mode with AES-CMAC as the PRF.
    /// </summary>
    private Result<SessionKeys, SmartCardError> DeriveScp03SessionKeys(IKeyDerivationContext context)
    {
        if (context.KeySet is not Scp03KeySet scp03KeySet)
        {
            return Result.Failure<SessionKeys, SmartCardError>(
                SmartCardError.InvalidArgument("SCP03 requires Scp03KeySet"));
        }

        try
        {
            // Get SCP i parameter for key derivation context modification
            var iParameter = context.GetImplementationParameter();

            // Context is concatenation of host challenge and card challenge
            // Per GP SCP03 v1.1.1, some implementations may modify the context based on i parameter
            var derivationContext = new byte[16];
            Array.Copy(context.HostChallenge, 0, derivationContext, 0, 8);
            Array.Copy(context.CardChallenge, 0, derivationContext, 8, 8);

            _logger.LogDebug("SCP03 key derivation with i parameter: 0x{IParameter:X2}", iParameter);

            // Determine key length based on key set
            var keyLength = scp03KeySet.EncKey.Length * 8; // Convert to bits

            // Derive each session key
            var sEncResult = DeriveScp03Key(
                scp03KeySet.EncKey,
                DerivationConstants.SEnc,
                derivationContext,
                keyLength);

            if (sEncResult.IsFailure)
            {
                return Result.Failure<SessionKeys, SmartCardError>(sEncResult.Error);
            }

            var sMacResult = DeriveScp03Key(
                scp03KeySet.MacKey,
                DerivationConstants.SMac,
                derivationContext,
                keyLength);

            if (sMacResult.IsFailure)
            {
                return Result.Failure<SessionKeys, SmartCardError>(sMacResult.Error);
            }

            var sRMacResult = DeriveScp03Key(
                scp03KeySet.MacKey,
                DerivationConstants.SrMac,
                derivationContext,
                keyLength);

            if (sRMacResult.IsFailure)
            {
                return Result.Failure<SessionKeys, SmartCardError>(sRMacResult.Error);
            }

            _logger.LogInformation("Successfully derived SCP03 session keys");
            return Result.Success<SessionKeys, SmartCardError>(
                new SessionKeys(sEncResult.Value, sMacResult.Value, sRMacResult.Value, scp03KeySet.DekKey));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SCP03 key derivation failed");
            return Result.Failure<SessionKeys, SmartCardError>(
                SmartCardError.CryptographicError($"SCP03 key derivation failed: {ex.Message}"));
        }
    }

    /// <summary>
    /// Derives a single SCP03 key using SP 800-108 KDF.
    /// Per GlobalPlatform SCP03 v1.1.1 Section 4.1.5 "Data Derivation Scheme".
    /// Uses the exact GP structure: Counter(1) + Label(12) + Separator(1) + L(2) + Context(16)
    /// PRF is CMAC as specified in NIST SP 800-38B with full 16 byte output.
    /// </summary>
    private Result<byte[], SmartCardError> DeriveScp03Key(
        byte[] kdk,
        byte derivationConstant,
        byte[] context,
        int keyLengthBits)
    {
        try
        {
            // Build the GP SCP03 v1.1.1 Section 4.1.5 structure:
            // Label (12 bytes: 11 zeros + derivation constant) + Separator (1 byte) + L (2 bytes) + Counter (1 byte) + Context (16 bytes)
            // Total: 32 bytes
            // The spec says counter comes after L field, so we need to split the fixed input data

            // Build fixed input data before counter
            var dataBeforeCounter = new byte[15]; // Label + Separator + L
            var offset = 0;

            // Label (11 bytes of 0x00)
            Array.Copy(DerivationConstants.Scp03Label, 0, dataBeforeCounter, offset, 11);
            offset += 11;

            // Derivation constant (1 byte)
            dataBeforeCounter[offset++] = derivationConstant;

            // Separator (1 byte)
            dataBeforeCounter[offset++] = 0x00;

            // L (length in bits as 2-byte big-endian)
            dataBeforeCounter[offset++] = (byte)(keyLengthBits >> 8);
            dataBeforeCounter[offset++] = (byte)keyLengthBits;

            // Build fixed input data after counter
            var dataAfterCounter = new byte[16]; // Context
            Array.Copy(context, 0, dataAfterCounter, 0, 16);

            // Determine PRF type based on key length
            var prfType = kdk.Length switch
            {
                16 => PrfType.CmacAes128,
                24 => PrfType.CmacAes192,
                32 => PrfType.CmacAes256,
                _ => throw new ArgumentException($"Unsupported key length: {kdk.Length} bytes")
            };

            // Configure KDF options for SCP03 - counter in the middle
            var options = new KdfOptions(
                prfType: prfType,
                counterLengthBits: 8, // SCP03 uses 8-bit counter
                useCounter: true,
                counterLocation: CounterLocation.MiddleFixed // Counter in the middle
            );

            // Use DeriveWithSplitFixedInput to place counter in the middle
            var derivedKey = _kdf.DeriveWithSplitFixedInput(
                kdk,
                dataBeforeCounter,
                dataAfterCounter,
                keyLengthBits,
                options);

            return Result.Success<byte[], SmartCardError>(derivedKey);
        }
        catch (Exception ex)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.CryptographicError($"SCP03 key derivation failed: {ex.Message}"));
        }
    }

    /// <summary>
    /// Derives data using SCP03 key derivation scheme for non-key derivation purposes.
    /// Per GlobalPlatform SCP03 v1.1.1 Section 4.1.5 "Data Derivation Scheme".
    /// Used for cryptogram generation, card challenge generation, etc.
    /// </summary>
    /// <param name="key">The key to use for derivation (KDK).</param>
    /// <param name="derivationConstant">The derivation constant from Table 4-1.</param>
    /// <param name="context">The context data (typically challenges concatenated).</param>
    /// <param name="outputLengthBits">The desired output length in bits.</param>
    /// <returns>The derived data or an error.</returns>
    public Result<byte[], SmartCardError> DeriveScp03Data(
        byte[] key,
        byte derivationConstant,
        byte[] context,
        int outputLengthBits)
    {
        try
        {
            // Validate inputs
            if (key == null || key.Length == 0)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument("Key cannot be null or empty"));
            }

            if (context == null || context.Length == 0)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument("Context cannot be null or empty"));
            }

            if (outputLengthBits % 8 != 0 || outputLengthBits <= 0 || outputLengthBits > 256)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument("Output length must be a positive multiple of 8 bits, up to 256"));
            }

            _logger.LogDebug("Deriving SCP03 data with constant 0x{Constant:X2}, output length {Length} bits",
                derivationConstant, outputLengthBits);

            // Use the same DeriveScp03Key method but with the specified derivation constant
            return DeriveScp03Key(key, derivationConstant, context, outputLengthBits);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SCP03 data derivation failed");
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.CryptographicError($"SCP03 data derivation failed: {ex.Message}"));
        }
    }

    /// <summary>
    /// Derives SCP02 session keys.
    /// Per GlobalPlatform Card Specification v2.3.1 Section E.4.1 "SCP02 - Session Key Derivation".
    /// Uses 3DES ECB encryption of derivation data.
    /// </summary>
    private Result<SessionKeys, SmartCardError> DeriveScp02SessionKeys(IKeyDerivationContext context)
    {
        if (context.KeySet is not Scp02KeySet scp02KeySet)
        {
            return Result.Failure<SessionKeys, SmartCardError>(
                SmartCardError.InvalidArgument("SCP02 requires Scp02KeySet"));
        }

        if (context.SequenceCounter.HasNoValue)
        {
            return Result.Failure<SessionKeys, SmartCardError>(
                SmartCardError.InvalidArgument("SCP02 requires sequence counter"));
        }

        var sequenceCounter = context.SequenceCounter.Value;

        try
        {
            // Derive session encryption key using SCP02 constant 0x0182
            var sEncResult = DeriveScp02Key(
                scp02KeySet.EncKey,
                DerivationConstants.Scp02.SecureChannelEncryption,
                sequenceCounter);

            if (sEncResult.IsFailure)
            {
                return Result.Failure<SessionKeys, SmartCardError>(sEncResult.Error);
            }

            // For basic SCP02, MAC keys are often not derived (depends on implementation)
            var implementation = context.Implementation.GetValueOrDefault(ScpImplementation.Scp02StaticMac);

            byte[] sMac;
            byte[] sRMac;

            if (implementation == ScpImplementation.Scp02StaticMac)
            {
                // Static MAC - use base keys directly
                sMac = scp02KeySet.MacKey;
                sRMac = scp02KeySet.MacKey;
            }
            else
            {
                // Derive C-MAC key using SCP02 constant 0x0101
                var sMacResult = DeriveScp02Key(
                    scp02KeySet.MacKey,
                    DerivationConstants.Scp02.CMac,
                    sequenceCounter);

                if (sMacResult.IsFailure)
                {
                    return Result.Failure<SessionKeys, SmartCardError>(sMacResult.Error);
                }

                // Derive R-MAC key separately using SCP02 constant 0x0102
                var sRMacResult = DeriveScp02Key(
                    scp02KeySet.MacKey,
                    DerivationConstants.Scp02.RMac,
                    sequenceCounter);

                if (sRMacResult.IsFailure)
                {
                    return Result.Failure<SessionKeys, SmartCardError>(sRMacResult.Error);
                }

                sMac = sMacResult.Value;
                sRMac = sRMacResult.Value;
            }

            // Derive DEK session key using SCP02 constant 0x0181
            var sDekResult = DeriveScp02Key(
                scp02KeySet.DekKey,
                DerivationConstants.Scp02.DataEncryptionKey,
                sequenceCounter);

            if (sDekResult.IsFailure)
            {
                return Result.Failure<SessionKeys, SmartCardError>(sDekResult.Error);
            }

            _logger.LogInformation("Successfully derived SCP02 session keys");
            return Result.Success<SessionKeys, SmartCardError>(
                new SessionKeys(sEncResult.Value, sMac, sRMac, sDekResult.Value));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SCP02 key derivation failed");
            return Result.Failure<SessionKeys, SmartCardError>(
                SmartCardError.CryptographicError($"SCP02 key derivation failed: {ex.Message}"));
        }
    }

    /// <summary>
    /// Derives a single SCP02 key using 3DES-CBC encryption.
    /// Per GlobalPlatform Card Specification v2.3.1 Section E.4.1:
    /// "Session keys are the result of encrypting derivation data with the static keys"
    /// Per Figure E-2: Derivation data format (16 bytes): constant (2 bytes) || sequence counter (2 bytes) || padding (12 bytes)
    /// </summary>
    private Result<byte[], SmartCardError> DeriveScp02Key(
        byte[] baseKey,
        byte[] derivationConstant,
        byte[] sequenceCounter)
    {
        try
        {
            // Validate inputs - per GP Card Spec v2.3.1 Tables E-2 and E-3, all SCP02 keys are 16 bytes
            if (baseKey.Length != 16)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument("SCP02 base key must be 16 bytes per GP specification"));
            }

            if (derivationConstant == null || derivationConstant.Length != 2)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument("SCP02 derivation constant must be 2 bytes"));
            }

            if (sequenceCounter == null || sequenceCounter.Length != 2)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument("SCP02 sequence counter must be 2 bytes"));
            }

            // SCP02 key derivation data construction per GP Card Spec v2.3.1 Figure E-2:
            // Derivation data (16 bytes): Constant (2 bytes) || Sequence Counter (2 bytes) || '00' Padding (12 bytes)
            var derivationData = new byte[16];
            Array.Copy(derivationConstant, 0, derivationData, 0, 2);
            Array.Copy(sequenceCounter, 0, derivationData, 2, 2);
            // Remaining 12 bytes are already 0x00 from array initialization

            // Encrypt the derivation data using 3DES-CBC with zero IV per GP Card Spec v2.3.1 Section E.4.1
            var zeroIv = new byte[8]; // Zero IV for CBC mode
            var parametersWithIv = new ParametersWithIV(new KeyParameter(baseKey), zeroIv);
            var cipher = new BufferedBlockCipher(new CbcBlockCipher(new DesEdeEngine()));
            cipher.Init(true, parametersWithIv);

            var output = new byte[cipher.GetOutputSize(derivationData.Length)];
            var len = cipher.ProcessBytes(derivationData, 0, derivationData.Length, output, 0);
            cipher.DoFinal(output, len);

            // Per GP Card Spec v2.3.1 Figure E-2: Session Key is 16 bytes
            // The 3DES-CBC encryption of 16-byte derivation data produces exactly 16 bytes
            // Return the entire output as the session key
            return Result.Success<byte[], SmartCardError>(output);
        }
        catch (Exception ex)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.CryptographicError($"SCP02 key derivation failed: {ex.Message}"));
        }
    }

    /// <summary>
    /// Derives a key for a specific purpose using the appropriate protocol.
    /// This is a convenience method that creates a KeyDerivationContext internally.
    /// </summary>
    /// <param name="keySet">The static key set.</param>
    /// <param name="hostChallenge">The host challenge.</param>
    /// <param name="cardChallenge">The card challenge.</param>
    /// <param name="sequenceCounter">The sequence counter (required for SCP02).</param>
    /// <param name="implementation">The SCP implementation option.</param>
    /// <returns>The derived session keys or an error.</returns>
    public Result<SessionKeys, SmartCardError> DeriveSessionKeys(
        IKeySet keySet,
        byte[] hostChallenge,
        byte[] cardChallenge,
        Maybe<byte[]> sequenceCounter = default,
        Maybe<ScpImplementation> implementation = default)
    {
        return KeyDerivationContext.Create(
            keySet,
            hostChallenge,
            cardChallenge,
            sequenceCounter,
            implementation)
            .Bind(DeriveSessionKeys);
    }

    /// <summary>
    /// Calculates a cryptogram for authentication purposes.
    /// </summary>
    /// <param name="context">The cryptogram calculation context.</param>
    /// <returns>The calculated cryptogram or an error.</returns>
    public Result<byte[], SmartCardError> CalculateCryptogram(ICryptogramContext context)
    {
        _logger.LogDebug("Calculating cryptogram of type {Type} for protocol 0x{Protocol:X2}",
            context.Type, context.ProtocolVersion);

        // For SCP03 authentication cryptograms, use the data derivation scheme
        if (context.ProtocolVersion == 0x03 &&
            (context.Type == CryptogramType.CardCryptogram || context.Type == CryptogramType.HostCryptogram))
        {
            // Validate context data length
            if (context.Data.Length != 16)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument("SCP03 cryptogram context must be 16 bytes (host challenge || card challenge)"));
            }

            // Determine derivation constant based on cryptogram type
            var derivationConstant = context.Type switch
            {
                CryptogramType.CardCryptogram => DerivationConstants.CardCryptogram, // 0x00
                CryptogramType.HostCryptogram => DerivationConstants.HostCryptogram, // 0x01
                _ => throw new InvalidOperationException($"Unexpected cryptogram type: {context.Type}")
            };

            // Use SCP03 data derivation scheme
            return DeriveScp03Data(
                context.Key,
                derivationConstant,
                context.Data,
                64); // 64 bits = 8 bytes output
        }

        // For other cases, delegate to CryptogramService
        var cryptogramService = new Gp4Net.Domain.Security.CryptogramService();

        return context.Type switch
        {
            CryptogramType.CardCryptogram => cryptogramService.CalculateCardCryptogram(
                context.Key,
                context.Data.Length >= 8 ? context.Data[..8] : context.Data, // host challenge
                context.Data.Length >= 16 ? context.Data[8..16] : new byte[8], // card challenge
                Maybe<byte[]>.None, // sequence counter - would need to be in context
                GetProtocolFromContext(context)),

            CryptogramType.HostCryptogram => cryptogramService.CalculateHostCryptogram(
                context.Key,
                context.Data.Length >= 8 ? context.Data[..8] : context.Data, // host challenge
                context.Data.Length >= 16 ? context.Data[8..16] : new byte[8], // card challenge
                Maybe<byte[]>.None, // sequence counter - would need to be in context
                GetProtocolFromContext(context)),

            _ => cryptogramService.CalculateCryptogram(
                context.Key,
                context.Data,
                GetProtocolFromContext(context))
        };
    }

    private static ScpVersion GetProtocolFromContext(ICryptogramContext context)
    {
        // Map protocol version byte to ScpVersion enum
        return context.ProtocolVersion switch
        {
            0x02 => ScpVersion.Scp02,
            0x03 => ScpVersion.Scp03,
            _ => ScpVersion.Scp03 // Default to SCP03
        };
    }
}
