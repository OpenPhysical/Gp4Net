using System;
using System.Linq;
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
                new UnsupportedProtocolError(context.Protocol.ToString()))
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
                new InvalidKeyError("KeySet", "SCP03 requires Scp03KeySet"));
        }

        try
        {
            // Get SCP i parameter for key derivation context modification
            var iParameter = context.GetImplementationParameter();

            // Context is concatenation of host challenge and card challenge
            // Per GP SCP03 v1.1.1, some implementations may modify the context based on i parameter
            var derivationContext = context.HostChallenge.Concat(context.CardChallenge).ToArray();

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
                new CryptographicError("SCP03 key derivation", ex.Message));
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
            DerivationConstants.Scp03Label.CopyTo(dataBeforeCounter, offset);
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
            context.CopyTo(dataAfterCounter, 0);

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
                new CryptographicError("SCP03 key derivation", ex.Message));
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
                    new NullParameterError("key"));
            }

            if (context == null || context.Length == 0)
            {
                return Result.Failure<byte[], SmartCardError>(
                    new NullParameterError("context"));
            }

            if (outputLengthBits % 8 != 0 || outputLengthBits <= 0 || outputLengthBits > 256)
            {
                return Result.Failure<byte[], SmartCardError>(
                    new InvalidLengthError("outputLengthBits", 8, outputLengthBits));
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
                new CryptographicError("SCP03 data derivation", ex.Message));
        }
    }

    /// <summary>
    /// SCP02 key derivation parameters.
    /// </summary>
    private record Scp02KeyDerivationParams(
        Scp02KeySet KeySet,
        byte[] SequenceCounter,
        ScpImplementation Implementation);

    /// <summary>
    /// Derives SCP02 session keys.
    /// Per GlobalPlatform Card Specification v2.3.1 Section E.4.1 "SCP02 - Session Key Derivation".
    /// Uses 3DES ECB encryption of derivation data.
    /// </summary>
    private Result<SessionKeys, SmartCardError> DeriveScp02SessionKeys(IKeyDerivationContext context)
    {
        // Build derivation parameters
        var buildParams = context.KeySet.AsScp02KeySet()
            .Bind(keySet => context.SequenceCounter.ToResult("SCP02 requires sequence counter")
                .Map(seqCounter => new Scp02KeyDerivationParams(
                    keySet, 
                    seqCounter, 
                    context.Implementation.GetValueOrDefault(ScpImplementation.Scp02I15))));

        // Compose key derivations functionally
        return buildParams.Bind(derivationParams =>
        {
            _logger.LogDebug("SCP02 key derivation with implementation i={Implementation:X2}", (byte)derivationParams.Implementation);
            
            return DeriveAllScp02Keys(derivationParams);
        });
    }

    /// <summary>
    /// Derives all SCP02 session keys using functional composition.
    /// </summary>
    private Result<SessionKeys, SmartCardError> DeriveAllScp02Keys(Scp02KeyDerivationParams parameters)
    {
        _logger.LogDebug("SCP02 key derivation starting with implementation i={Implementation:X2}", (byte)parameters.Implementation);
        _logger.LogTrace("ENC key: {EncKey}", Convert.ToHexString(parameters.KeySet.EncKey));
        _logger.LogTrace("MAC key: {MacKey}", Convert.ToHexString(parameters.KeySet.MacKey));
        _logger.LogTrace("DEK key: {DekKey}", Convert.ToHexString(parameters.KeySet.DekKey));
        _logger.LogTrace("Sequence counter: {SequenceCounter}", Convert.ToHexString(parameters.SequenceCounter));
        _logger.LogDebug("Uses derived MAC keys: {UsesDerivedMacKeys}", UsesDerivedMacKeys(parameters.Implementation));
        
        var deriveMacKey = UsesDerivedMacKeys(parameters.Implementation)
            ? DeriveScp02Key(parameters.KeySet.MacKey, DerivationConstants.Scp02.CMac, parameters.SequenceCounter)
            : Result.Success<byte[], SmartCardError>(parameters.KeySet.MacKey);

        return DeriveScp02Key(parameters.KeySet.EncKey, DerivationConstants.Scp02.SecureChannelEncryption, parameters.SequenceCounter)
            .Bind(sEnc => deriveMacKey
                .Bind(sMac => 
                {
                    // Always derive R-MAC session key, regardless of implementation support
                    // GP Pro behavior shows distinct R-MAC keys are derived even for i=00
                    var deriveRMac = DeriveScp02Key(parameters.KeySet.MacKey, DerivationConstants.Scp02.RMac, parameters.SequenceCounter);
                    
                    return deriveRMac.Bind(sRMac =>
                        DeriveScp02Key(parameters.KeySet.DekKey, DerivationConstants.Scp02.DataEncryptionKey, parameters.SequenceCounter)
                            .Map(sDek => new SessionKeys(sEnc, sMac, sRMac, sDek)));
                }));
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
        // Delegate to pure functional implementation
        return Scp02Cryptography.DeriveScp02SessionKey(baseKey, derivationConstant, sequenceCounter);
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

        switch (context.ProtocolVersion)
        {
            // For SCP03 authentication cryptograms, use the data derivation scheme
            case 0x03 when
                context.Type is CryptogramType.CardCryptogram or CryptogramType.HostCryptogram:
            {
                // Validate context data length
                if (context.Data.Length != 16)
                {
                    return Result.Failure<byte[], SmartCardError>(
                        new InvalidLengthError("cryptogramContext", 16, context.Data.Length));
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

            // For SCP02, the data is already properly formatted by CryptogramBuilder
            // It includes the sequence counter and proper padding, so we should not decompose it
            case 0x02:
                // For SCP02, use the appropriate MAC algorithm based on cryptogram type
                return context.Type switch
                {
                    CryptogramType.CardCryptogram or CryptogramType.HostCryptogram => 
                        // SCP02 uses Full 3DES MAC for cryptograms
                        CryptographicOperations.CalculateFull3DesMac(context.Key, context.Data),
                    
                    CryptogramType.CommandMac or CryptogramType.ResponseMac => 
                        // SCP02 uses Retail MAC for C-MAC and R-MAC
                        CryptographicOperations.CalculateRetailMac(context.Key, context.Data),
                    
                    _ => Result.Failure<byte[], SmartCardError>(
                        new UnsupportedImplementationError($"SCP02 cryptogram type: {context.Type}"))
                };
            default:
            {
                // For other protocols, delegate to CryptogramService
                var cryptogramService = new Gp4Net.Domain.Security.CryptogramService();
        
                // For non-SCP02 protocols, use the existing logic
                return cryptogramService.CalculateCryptogram(
                    context.Key,
                    context.Data,
                    GetProtocolFromContext(context));
            }
        }

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

    /// <summary>
    /// Determines whether an SCP02 implementation uses derived MAC keys or static MAC keys.
    /// Based on GlobalPlatform test vectors and real-world implementations.
    /// </summary>
    /// <param name="implementation">The SCP02 implementation</param>
    /// <returns>True if MAC keys should be derived, false if they should remain static</returns>
    private static bool UsesDerivedMacKeys(ScpImplementation implementation)
    {
        // Based on comprehensive analysis of test vectors and real card behavior:
        // Per GP Card Spec v2.3.1 Section E.4.1, MAC keys are derived using constant 0x0101
        // Only specific implementations use static MAC keys
        return implementation switch
        {
            // Only this specific implementation uses static MAC keys
            ScpImplementation.Scp02I15 => false,  // Test vector confirms: uses static MAC
            
            // All other implementations use derived MAC keys
            // This includes i=00 as confirmed by GP Pro traces
            _ => true  // Default: derive MAC keys per specification
        };
    }
}

/// <summary>
/// Extension methods for functional composition in key derivation.
/// </summary>
internal static class KeyDerivationExtensions
{
    /// <summary>
    /// Safely casts a generic IKeySet to a specific Scp02KeySet.
    /// </summary>
    /// <param name="keySet">The generic key set</param>
    /// <returns>A Result containing the cast key set or an error</returns>
    internal static Result<Scp02KeySet, SmartCardError> AsScp02KeySet(this IKeySet keySet)
    {
        return keySet is Scp02KeySet scp02KeySet
            ? Result.Success<Scp02KeySet, SmartCardError>(scp02KeySet)
            : Result.Failure<Scp02KeySet, SmartCardError>(
                new InvalidKeyError("KeySet", "SCP02 requires Scp02KeySet"));
    }

    /// <summary>
    /// Converts a Maybe to a Result with a custom error message.
    /// </summary>
    /// <typeparam name="T">The type contained in the Maybe</typeparam>
    /// <param name="maybe">The Maybe value</param>
    /// <param name="errorMessage">Error message if Maybe has no value</param>
    /// <returns>A Result containing the value or an error</returns>
    internal static Result<T, SmartCardError> ToResult<T>(this Maybe<T> maybe, string errorMessage)
    {
        return maybe.HasValue
            ? Result.Success<T, SmartCardError>(maybe.Value)
            : Result.Failure<T, SmartCardError>(new InvalidFormatError("parameter", errorMessage));
    }
}
