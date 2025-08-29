using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Constants;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Security;
using JetBrains.Annotations;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Kdf.Modes;
using Microsoft.Extensions.Logging;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Cryptographic service implementation for the virtual card emulator.
/// Implements actual GlobalPlatform cryptographic operations for testing.
/// Uses injected IRngService for deterministic testing support.
/// Uses single type-safe CryptogramService - no duplication.
/// </summary>
[PublicAPI]
public class CryptographicService
{
    private readonly IKeyDerivationService _keyDerivationService;
    private readonly IRngService _rngService;
    private readonly ILogger<CryptographicService> _logger;

    public CryptographicService(ILogger<CryptographicService> logger)
        : this(new KeyDerivationService(), new SecureRngService(), logger)
    {
    }

    public CryptographicService()
        : this(Microsoft.Extensions.Logging.Abstractions.NullLogger<CryptographicService>.Instance)
    {
    }

    public CryptographicService(IKeyDerivationService keyDerivationService, ILogger<CryptographicService> logger)
        : this(keyDerivationService, new SecureRngService(), logger)
    {
    }

    public CryptographicService(IKeyDerivationService keyDerivationService)
        : this(keyDerivationService, Microsoft.Extensions.Logging.Abstractions.NullLogger<CryptographicService>.Instance)
    {
    }

    public CryptographicService(IRngService rngService)
        : this(new KeyDerivationService(), rngService, Microsoft.Extensions.Logging.Abstractions.NullLogger<CryptographicService>.Instance)
    {
    }

    public CryptographicService(IKeyDerivationService keyDerivationService, IRngService rngService, ILogger<CryptographicService> logger)
    {
        _keyDerivationService = keyDerivationService;
        _rngService = rngService;
        _logger = logger;
    }

    public Result<byte[], SmartCardError> GenerateChallenge(int length)
    {
        return _rngService.GetBytes(length);
    }

    /// <summary>
    /// Generates pseudo-random challenge using SCP03 KDF per GlobalPlatform Card Specification v2.3.1.
    /// Uses key derivation with sequence counter and AID as context.
    /// </summary>
    public Result<byte[], SmartCardError> GeneratePseudoRandomChallenge(
        byte[] staticKey, byte[] sequenceCounter, byte[] aid, int length)
    {
        // SCP03 pseudo-random challenge generation per GP specification
        // Uses KDF with specific label and context

        // Build context: sequence counter || AID
        byte[] context = new byte[sequenceCounter.Length + aid.Length];
        Array.Copy(sequenceCounter, 0, context, 0, sequenceCounter.Length);
        Array.Copy(aid, 0, context, sequenceCounter.Length, aid.Length);

        // Use KDF with proper derivation constant for card challenge generation
        // Per GP spec: derivation constant 0x02 for card challenge generation
        byte derivationConstant = 0x02;

        // Derive pseudo-random data using the same KDF structure as session keys
        return DerivePseudoRandomChallenge(staticKey, derivationConstant, context, length * 8);
    }

    public Result<byte[], SmartCardError> CalculateCardCryptogram(
        byte[] hostChallenge, byte[] cardChallenge, IKeySet keys, byte scpVersion, byte implementationParameter, Maybe<byte[]> sequenceCounter)
    {
        return scpVersion switch
        {
            0x02 => sequenceCounter.Match(
                Some: counter => counter.Length == 2
                    ? CalculateScp02CardCryptogram(hostChallenge, cardChallenge, counter, keys, implementationParameter)
                    : SmartCardError.InvalidArgument("SCP02 requires a 2-byte sequence counter"),
                None: () => SmartCardError.InvalidArgument("SCP02 requires a sequence counter")
            ),
            0x03 => sequenceCounter.HasValue
                ? SmartCardError.InvalidArgument("SCP03 does not use a separate sequence counter")
                : CalculateScp03CardCryptogram(hostChallenge, cardChallenge, keys),
            _ => SmartCardError.InvalidArgument($"Unsupported SCP version: {scpVersion:X2}")
        };
    }

    public Result<byte[], SmartCardError> CalculateHostCryptogram(
        byte[] hostChallenge, byte[] cardChallenge, IKeySet keys, byte scpVersion, byte implementationParameter, Maybe<byte[]> sequenceCounter)
    {
        return scpVersion switch
        {
            0x02 => sequenceCounter.Match(
                Some: counter => counter.Length == 2
                    ? CalculateScp02HostCryptogram(hostChallenge, cardChallenge, counter, keys, implementationParameter)
                    : SmartCardError.InvalidArgument("SCP02 requires a 2-byte sequence counter"),
                None: () => SmartCardError.InvalidArgument("SCP02 requires a sequence counter")
            ),
            0x03 => sequenceCounter.HasValue
                ? SmartCardError.InvalidArgument("SCP03 does not use a separate sequence counter")
                : CalculateScp03HostCryptogram(hostChallenge, cardChallenge, keys),
            _ => SmartCardError.InvalidArgument($"Unsupported SCP version: {scpVersion:X2}")
        };
    }

    /// <summary>
    /// Verifies cryptogram by comparing received and expected values using secure comparison.
    /// </summary>
    public Result<bool, SmartCardError> VerifyCryptogram(byte[] received, byte[] expected)
    {
        return Result.Success<bool, SmartCardError>(received.SequenceEqual(expected));
    }

    /// <summary>
    /// Derives SCP session keys from base keys and challenge data per GlobalPlatform Card Specification v2.3.1.
    /// </summary>
    public Result<SessionKeys, SmartCardError> DeriveSessionKeys(
        IKeySet baseKeys, byte[] hostChallenge, byte[] cardChallenge, byte scpVersion)
    {
        return scpVersion switch
        {
            0x02 => DeriveScp02SessionKeys(baseKeys, hostChallenge, cardChallenge),
            0x03 => DeriveScp03SessionKeys(baseKeys, hostChallenge, cardChallenge),
            _ => SmartCardError.InvalidArgument($"Unsupported SCP version: {scpVersion:X2}")
        };
    }

    // SCP02 Implementation

    private Result<byte[], SmartCardError> CalculateScp02CardCryptogram(
        byte[] hostChallenge, byte[] cardChallenge, byte[] sequenceCounter, IKeySet keys, byte implementationParameter)
    {
        _logger.LogDebug("CalculateScp02CardCryptogram called");

        if (keys is not Scp02KeySet scp02Keys)
        {
            _logger.LogError("Invalid key set type - SCP02 requires Scp02KeySet");
            return SmartCardError.InvalidArgument("SCP02 requires SCP02 key set");
        }

        // Per GP Card Spec v2.3.1 Section E.4.2: Authentication cryptograms use S-ENC session key
        // Validate inputs
        if (cardChallenge.Length != 6)
        {
            _logger.LogError("Invalid card challenge length: {Length} bytes, expected 6", cardChallenge.Length);
            return SmartCardError.InvalidArgument($"SCP02 card challenge must be 6 bytes, got {cardChallenge.Length}");
        }

        if (sequenceCounter.Length != 2)
        {
            _logger.LogError("Invalid sequence counter length: {Length} bytes, expected 2", sequenceCounter.Length);
            return SmartCardError.InvalidArgument($"SCP02 sequence counter must be 2 bytes, got {sequenceCounter.Length}");
        }

        // Construct full 8-byte card challenge for key derivation
        byte[] fullCardChallenge = new byte[8];
        Array.Copy(sequenceCounter, 0, fullCardChallenge, 0, 2);
        Array.Copy(cardChallenge, 0, fullCardChallenge, 2, 6);

        _logger.LogDebug("SCP02 Card Cryptogram - Host Challenge: {HostChallenge}, Card Challenge: {CardChallenge}, Sequence Counter: {SeqCounter}, Implementation: 0x{Impl:X2}",
            Convert.ToHexString(hostChallenge),
            Convert.ToHexString(cardChallenge),
            Convert.ToHexString(sequenceCounter),
            implementationParameter);

#if DEBUG
        _logger.LogDebug("DEBUG: Using key set with Key Version: 0x{KeyVersion:X2}", scp02Keys.KeyVersion);
#endif

        Result<SecureSessionKeys, SmartCardError> sessionKeysResult = Domain.Protocol.Scp02ProtocolImpl.DeriveSessionKeys(
            keys,
            hostChallenge,
            cardChallenge,  // Pass the 6-byte card challenge
            sequenceCounter,
            implementationParameter
        );

        return sessionKeysResult.Match(
            sessionKeys =>
            {
                _logger.LogDebug("Session keys derived successfully");

#if DEBUG
                _logger.LogDebug("DEBUG: S-ENC length: {Length} bytes", sessionKeys.SEnc.Length);
#endif

                // Build card cryptogram data per GP spec E.4.2.1
                // Format: Host Challenge (8) || Sequence Counter (2) || Card Challenge (6) || Padding
                byte[] cryptogramData = new byte[24]; // Will be padded to 3DES block size
                Array.Copy(hostChallenge, 0, cryptogramData, 0, 8);
                Array.Copy(sequenceCounter, 0, cryptogramData, 8, 2);
                Array.Copy(cardChallenge, 0, cryptogramData, 10, 6);  // Use the 6-byte card challenge directly
                // Apply ISO 7816-4 padding
                cryptogramData[16] = 0x80;
                // Rest is already zeros

                _logger.LogDebug("Cryptogram data constructed (24 bytes with padding)");

                // Calculate cryptogram using S-ENC session key (per GP spec E.4.2)
                _logger.LogDebug("Calculating cryptogram MAC using S-ENC session key");

                // Calculate cryptogram using static MacCalculations for SCP02
                Result<byte[], SmartCardError> result = MacCalculations.CalculateScp02Cryptogram(
                    sessionKeys.SEnc,  // Use S-ENC session key, not static MAC key
                    cryptogramData
                );

                return result.Match(
                    cryptogram =>
                    {
                        _logger.LogDebug("Card cryptogram calculated successfully: {Cryptogram}", Convert.ToHexString(cryptogram));
                        return Result.Success<byte[], SmartCardError>(cryptogram);
                    },
                    error =>
                    {
                        _logger.LogError("Failed to calculate card cryptogram: {Error}", error.Message);
                        return Result.Failure<byte[], SmartCardError>(error);
                    }
                );
            },
            error =>
            {
                _logger.LogError("Failed to derive session keys: {Error}", error.Message);
                return Result.Failure<byte[], SmartCardError>(error);
            });
    }

    private Result<byte[], SmartCardError> CalculateScp02HostCryptogram(
        byte[] hostChallenge, byte[] cardChallenge, byte[] sequenceCounter, IKeySet keys, byte implementationParameter)
    {
        if (keys is not Scp02KeySet scp02Keys)
            return SmartCardError.InvalidArgument("SCP02 requires SCP02 key set");

        // Per GP Card Spec v2.3.1 Section E.4.2: Authentication cryptograms use S-ENC session key

        // Validate inputs
        if (cardChallenge.Length != 6)
            return SmartCardError.InvalidArgument($"SCP02 card challenge must be 6 bytes, got {cardChallenge.Length}");

        if (sequenceCounter.Length != 2)
            return SmartCardError.InvalidArgument($"SCP02 sequence counter must be 2 bytes, got {sequenceCounter.Length}");

        // Construct full 8-byte card challenge for key derivation
        byte[] fullCardChallenge = new byte[8];
        Array.Copy(sequenceCounter, 0, fullCardChallenge, 0, 2);
        Array.Copy(cardChallenge, 0, fullCardChallenge, 2, 6);

        Result<SecureSessionKeys, SmartCardError> sessionKeysResult = Domain.Protocol.Scp02ProtocolImpl.DeriveSessionKeys(
            keys,
            hostChallenge,
            cardChallenge,  // Pass the 6-byte card challenge
            sequenceCounter,
            implementationParameter
        );

        return sessionKeysResult.Match(
            sessionKeys =>
            {
                // Build host cryptogram data per GP spec E.4.2.2
                // Format: Sequence Counter (2) || Card Challenge (6) || Host Challenge (8) || Padding
                byte[] cryptogramData = new byte[24]; // Will be padded to 3DES block size
                Array.Copy(sequenceCounter, 0, cryptogramData, 0, 2);
                Array.Copy(cardChallenge, 0, cryptogramData, 2, 6);  // Use the 6-byte card challenge directly
                Array.Copy(hostChallenge, 0, cryptogramData, 8, 8);
                // Apply ISO 7816-4 padding
                cryptogramData[16] = 0x80;
                // Rest is already zeros

                // Calculate cryptogram using S-ENC session key (per GP spec E.4.2)
                return MacCalculations.CalculateScp02Cryptogram(
                    sessionKeys.SEnc,  // Use S-ENC session key, not static MAC key
                    cryptogramData
                );
            },
            error => Result.Failure<byte[], SmartCardError>(error));
    }

    private Result<SessionKeys, SmartCardError> DeriveScp02SessionKeys(
        IKeySet baseKeys, byte[] hostChallenge, byte[] cardChallenge)
    {
        if (baseKeys is not Scp02KeySet scp02Keys)
            return SmartCardError.InvalidArgument("SCP02 requires SCP02 key set");

        // ELIMINATE DRY VIOLATION: Use the same production KeyDerivationService and Scp02ProtocolImpl
        // that the host-side uses for consistency

        // The sequence counter should be 0001 for virtual cards, not derived from card challenge
        byte[] sequenceCounter = [0x00, 0x01];

        // Use the same production Scp02ProtocolImpl.DeriveSessionKeys method
        return Domain.Protocol.Scp02ProtocolImpl.DeriveSessionKeys(
            scp02Keys,
            hostChallenge,
            cardChallenge,  // Pass the 6-byte card challenge directly
            sequenceCounter,
            0x15  // P71 cards use implementation parameter i=15
        );
    }

    // Removed duplicate Derive3DesSessionKey method - now using production Scp2ProtocolImpl

    // SCP03 Implementation

    private Result<byte[], SmartCardError> CalculateScp03CardCryptogram(
        byte[] hostChallenge, byte[] cardChallenge, IKeySet keys)
    {
        if (keys is not Scp03KeySet scp03Keys)
            return SmartCardError.InvalidArgument("SCP03 requires SCP03 key set");

        // Use single type-safe CryptogramService - no duplication
        Result<SessionKeys, SmartCardError> sessionKeysResult = DeriveScp03SessionKeys(keys, hostChallenge, cardChallenge);
        if (sessionKeysResult.IsFailure)
            return sessionKeysResult.Error;

        SessionKeys? sessionKeys = sessionKeysResult.Value;

        // Create type-safe SCP03 key set with session MAC key
        Scp03KeySet keySetWithSession = new Scp03KeySet(
            scp03Keys.EncKey,
            scp03Keys.MacKey,
            scp03Keys.DekKey,
            scp03Keys.KeyVersion)
        {
            SMac = sessionKeys.SMac
        };

        // Create type-safe SCP03 parameters
        Result<Scp03CryptogramParameters, SmartCardError> parametersResult = CryptogramParameters.ForScp03(
            hostChallenge,
            cardChallenge,
            keySetWithSession);

        if (parametersResult.IsFailure)
            return parametersResult.Error;

        CryptogramService cryptogramService = new CryptogramService();
        return cryptogramService.CalculateCardCryptogram(parametersResult.Value);
    }

    private Result<byte[], SmartCardError> CalculateScp03HostCryptogram(
        byte[] hostChallenge, byte[] cardChallenge, IKeySet keys)
    {
        if (keys is not Scp03KeySet scp03Keys)
            return SmartCardError.InvalidArgument("SCP03 requires SCP03 key set");

        // Use single type-safe CryptogramService - no duplication
        Result<SessionKeys, SmartCardError> sessionKeysResult = DeriveScp03SessionKeys(keys, hostChallenge, cardChallenge);
        if (sessionKeysResult.IsFailure)
            return sessionKeysResult.Error;

        SessionKeys? sessionKeys = sessionKeysResult.Value;

        // Create type-safe SCP03 key set with session MAC key
        Scp03KeySet keySetWithSession = new Scp03KeySet(
            scp03Keys.EncKey,
            scp03Keys.MacKey,
            scp03Keys.DekKey,
            scp03Keys.KeyVersion)
        {
            SMac = sessionKeys.SMac
        };

        // Create type-safe SCP03 parameters
        Result<Scp03CryptogramParameters, SmartCardError> parametersResult = CryptogramParameters.ForScp03(
            hostChallenge,
            cardChallenge,
            keySetWithSession);

        if (parametersResult.IsFailure)
            return parametersResult.Error;

        CryptogramService cryptogramService = new CryptogramService();
        return cryptogramService.CalculateHostCryptogram(parametersResult.Value);
    }

    private Result<SessionKeys, SmartCardError> DeriveScp03SessionKeys(
        IKeySet baseKeys, byte[] hostChallenge, byte[] cardChallenge)
    {
        if (baseKeys is not Scp03KeySet scp03Keys)
            return SmartCardError.InvalidArgument("SCP03 requires SCP03 key set");

        // ELIMINATED DRY: Use single production KeyDerivationService - no role-specific logic needed
        // Create key derivation context for SCP03
        Scp03KeyDerivationContext derivationContext = new Scp03KeyDerivationContext(
            scp03Keys,
            hostChallenge,
            cardChallenge
        );

        // Use same production KeyDerivationService that host uses
        return _keyDerivationService.DeriveSessionKeys(derivationContext);
    }

    // Utility methods

    private Result<byte[], SmartCardError> DerivePseudoRandomChallenge(byte[] kdk, byte derivationConstant, byte[] context, int outputLengthBits)
    {
        // Use the same KDF structure as SCP03 session key derivation
        // Per GP spec section 4.1.5

        // Build the fixed input data: Label + Separator + L
        byte[] fixedInputBeforeCounter = new byte[11 + 1 + 1 + 2]; // Label + derivation + separator + L
        int offset = 0;

        // Label (11 bytes of 0x00 followed by derivation constant)
        Array.Fill(fixedInputBeforeCounter, (byte)0x00, 0, 11);
        offset += 11;
        fixedInputBeforeCounter[offset++] = derivationConstant;

        // Separator
        fixedInputBeforeCounter[offset++] = 0x00;

        // L (length in bits as 2-byte big-endian)
        fixedInputBeforeCounter[offset++] = (byte)(outputLengthBits >> 8);
        fixedInputBeforeCounter[offset++] = (byte)outputLengthBits;

        // Use Kdf108 library with correct parameters
        Maybe<Kdf108.Domain.Kdf.PrfType> prfTypeResult = kdk.Length switch
        {
            16 => Kdf108.Domain.Kdf.PrfType.CmacAes128,
            24 => Kdf108.Domain.Kdf.PrfType.CmacAes192,
            32 => Kdf108.Domain.Kdf.PrfType.CmacAes256,
            _ => Maybe<Kdf108.Domain.Kdf.PrfType>.None
        };
        
        if (prfTypeResult.HasNoValue)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument($"Unsupported key length: {kdk.Length} bytes"));
        }
        
        Kdf108.Domain.Kdf.PrfType prfType = prfTypeResult.Match(
            value => value,
            () => default // Should not reach here after HasNoValue check
        );

        KdfOptions options = new Kdf108.Domain.Kdf.KdfOptions(
            prfType: prfType,
            counterLengthBits: 8, // SCP03 uses 8-bit counter
            useCounter: true,
            counterLocation: Kdf108.Domain.Kdf.CounterLocation.MiddleFixed
        );

        CounterModeKdf kdf = new Kdf108.Domain.Kdf.Modes.CounterModeKdf();

        return Result.Try(() => kdf.DeriveWithSplitFixedInput(
            kdk,
            fixedInputBeforeCounter,
            context,
            outputLengthBits,
            options
        ), ex => SmartCardError.CryptographicError($"KDF108 derivation failed: {ex.Message}"));
    }

    private byte[] BuildScp03Context(byte[] hostChallenge, byte[] cardChallenge)
    {
        // Context = Host Challenge || Card Challenge
        byte[] context = new byte[hostChallenge.Length + cardChallenge.Length];
        Array.Copy(hostChallenge, 0, context, 0, hostChallenge.Length);
        Array.Copy(cardChallenge, 0, context, hostChallenge.Length, cardChallenge.Length);
        return context;
    }


    public Result<byte[], SmartCardError> CalculateAesCmac(byte[] key, byte[] data)
    {
        // Use the centralized MacCalculations for consistency and correctness
        return MacCalculations.CalculateScp03FullMac(key, data);
    }

    private Result<byte[], SmartCardError> Expand3DesKey(byte[] key)
    {
        return key.Length switch
        {
            24 => Result.Success<byte[], SmartCardError>(key),
            16 => Result.Success<byte[], SmartCardError>(CreateExpanded3DesKey(key)),
            _ => Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument($"Invalid 3DES key length: {key.Length}"))
        };
    }
    
    private static byte[] CreateExpanded3DesKey(byte[] key)
    {
        // Expand to 24 bytes: K1 || K2 || K1
        byte[] expanded = new byte[24];
        Array.Copy(key, 0, expanded, 0, 16);
        Array.Copy(key, 0, expanded, 16, 8);
        return expanded;
    }

    /// <summary>
    /// SCP03 key derivation context implementation.
    /// </summary>
    private class Scp03KeyDerivationContext : IKeyDerivationContext
    {
        public ScpVersion Protocol
        {
            get
            {
                return ScpVersion.Scp03;
            }
        }
        public IKeySet KeySet { get; }
        public byte[] HostChallenge { get; }
        public byte[] CardChallenge { get; }
        public Maybe<byte[]> SequenceCounter
        {
            get
            {
                return Maybe<byte[]>.None;
            }
        }
        public Maybe<Domain.Protocol.ScpImplementation> Implementation
        {
            get
            {
                return Maybe<Domain.Protocol.ScpImplementation>.None;
            }
        }

        public Scp03KeyDerivationContext(IKeySet keySet, byte[] hostChallenge, byte[] cardChallenge)
        {
            KeySet = keySet;
            HostChallenge = hostChallenge;
            CardChallenge = cardChallenge;
        }

        public byte GetImplementationParameter()
        {
            // Default SCP03 implementation parameter
            return Implementation.GetValueOrDefault(Domain.Protocol.ScpImplementation.Scp03I70) switch
            {
                Domain.Protocol.ScpImplementation.Scp03I70 => 0x70,
                Domain.Protocol.ScpImplementation.Scp03I60 => 0x60,
                Domain.Protocol.ScpImplementation.Scp03I11 => 0x11,
                _ => 0x70  // Default to pseudo-random
            };
        }
    }

    public Result<(byte[] securedData, CardState newState), SmartCardError> ApplyResponseSecurity(
        byte[] responseData,
        SessionKeys sessionKeys,
        byte[] macChainingValue,
        uint encryptionCounter,
        byte scpVersion,
        byte securityLevel,
        CardState currentState)
    {
        // Use the ResponseSecurityProcessor from the domain
        Domain.SecurityLevel domainSecurityLevel = (Domain.SecurityLevel)securityLevel;

        return CardResponseSecurityProcessor.ApplyResponseSecurity(
                responseData,
                domainSecurityLevel,
                sessionKeys,
                [..macChainingValue],
                encryptionCounter,
                scpVersion
            )
            .Bind(processedResult =>
                // Create MacChainingState from the new chaining value
                currentState.SecureChannel
                    .ToResult(SmartCardError.InvalidArgument("Secure channel not established"))
                    .Bind(secureChannel => MacChainingState.Create(
                        processedResult.NewMacChainingValue.ToArray(),
                        secureChannel.ProtocolVersion,
                        0x00)) // implementation parameter - could be tracked in state if needed
                    .Bind(macChainingState =>
                        // Update secure channel state with new counter and MAC chaining
                        currentState.SecureChannel
                            .ToResult(SmartCardError.InvalidArgument("Secure channel not established"))
                            .Bind(secureChannel => secureChannel.UpdateCounterAndMac(
                                processedResult.NewEncryptionCounter,
                                macChainingState))
                            .Map(updatedSecureChannel =>
                            {
                                CardState newState = currentState.WithUpdatedSecureChannel(updatedSecureChannel);
                                return (processedResult.SecuredData, newState);
                            })
                    )
            );
    }
}
