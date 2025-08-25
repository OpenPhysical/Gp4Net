using System;
using System.Linq;
using Org.BouncyCastle.Security;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Constants;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Security;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

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

    public Result<byte[], SmartCardError> GeneratePseudoRandomChallenge(
        byte[] staticKey, byte[] sequenceCounter, byte[] aid, int length)
    {
        try
        {
            // SCP03 pseudo-random challenge generation per GP specification
            // Uses KDF with specific label and context
            
            // Build context: sequence counter || AID
            var context = new byte[sequenceCounter.Length + aid.Length];
            Array.Copy(sequenceCounter, 0, context, 0, sequenceCounter.Length);
            Array.Copy(aid, 0, context, sequenceCounter.Length, aid.Length);
            
            // Use KDF with proper derivation constant for card challenge generation
            // Per GP spec: derivation constant 0x02 for card challenge generation
            byte derivationConstant = 0x02;
            
            // Derive pseudo-random data using the same KDF structure as session keys
            var derivedData = DerivePseudoRandomChallenge(staticKey, derivationConstant, context, length * 8);
            
            return Result.Success<byte[], SmartCardError>(derivedData);
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"Failed to generate pseudo-random challenge: {ex.Message}");
        }
    }

    public Result<byte[], SmartCardError> CalculateCardCryptogram(
        byte[] hostChallenge, byte[] cardChallenge, IKeySet keys, byte scpVersion, byte implementationParameter, Maybe<byte[]> sequenceCounter)
    {
        try
        {
            switch (scpVersion)
            {
                case 0x02:
                    return sequenceCounter.Match(
                        Some: counter => counter.Length == 2
                            ? CalculateScp02CardCryptogram(hostChallenge, cardChallenge, counter, keys, implementationParameter)
                            : SmartCardError.InvalidArgument("SCP02 requires a 2-byte sequence counter"),
                        None: () => SmartCardError.InvalidArgument("SCP02 requires a sequence counter")
                    );
                case 0x03:
                    return sequenceCounter.HasValue
                        ? SmartCardError.InvalidArgument("SCP03 does not use a separate sequence counter")
                        : CalculateScp03CardCryptogram(hostChallenge, cardChallenge, keys);
                default:
                    return SmartCardError.InvalidArgument($"Unsupported SCP version: {scpVersion:X2}");
            }
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"Failed to calculate card cryptogram: {ex.Message}");
        }
    }

    public Result<byte[], SmartCardError> CalculateHostCryptogram(
        byte[] hostChallenge, byte[] cardChallenge, IKeySet keys, byte scpVersion, byte implementationParameter, Maybe<byte[]> sequenceCounter)
    {
        try
        {
            switch (scpVersion)
            {
                case 0x02:
                    return sequenceCounter.Match(
                        Some: counter => counter.Length == 2
                            ? CalculateScp02HostCryptogram(hostChallenge, cardChallenge, counter, keys, implementationParameter)
                            : SmartCardError.InvalidArgument("SCP02 requires a 2-byte sequence counter"),
                        None: () => SmartCardError.InvalidArgument("SCP02 requires a sequence counter")
                    );
                case 0x03:
                    return sequenceCounter.HasValue
                        ? SmartCardError.InvalidArgument("SCP03 does not use a separate sequence counter")
                        : CalculateScp03HostCryptogram(hostChallenge, cardChallenge, keys);
                default:
                    return SmartCardError.InvalidArgument($"Unsupported SCP version: {scpVersion:X2}");
            }
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"Failed to calculate host cryptogram: {ex.Message}");
        }
    }

    public Result<bool, SmartCardError> VerifyCryptogram(byte[] received, byte[] expected)
    {
        try
        {
            return Result.Success<bool, SmartCardError>(received.SequenceEqual(expected));
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"Failed to verify cryptogram: {ex.Message}");
        }
    }

    public Result<Gp4Net.Domain.Keys.SessionKeys, SmartCardError> DeriveSessionKeys(
        IKeySet baseKeys, byte[] hostChallenge, byte[] cardChallenge, byte scpVersion)
    {
        try
        {
            switch (scpVersion)
            {
                case 0x02:
                    return DeriveScp02SessionKeys(baseKeys, hostChallenge, cardChallenge);
                case 0x03:
                    return DeriveScp03SessionKeys(baseKeys, hostChallenge, cardChallenge);
                default:
                    return SmartCardError.InvalidArgument($"Unsupported SCP version: {scpVersion:X2}");
            }
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"Failed to derive session keys: {ex.Message}");
        }
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
        var fullCardChallenge = new byte[8];
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
        
        var sessionKeysResult = Gp4Net.Domain.Protocol.Scp02ProtocolImpl.DeriveSessionKeys(
            keys,
            hostChallenge,
            cardChallenge,  // Pass the 6-byte card challenge
            sequenceCounter,
            implementationParameter
        );
        
        if (sessionKeysResult.IsFailure)
        {
            _logger.LogError("Failed to derive session keys: {Error}", sessionKeysResult.Error.Message);
            return sessionKeysResult.Error;
        }
        
        var sessionKeys = sessionKeysResult.Value;
        _logger.LogDebug("Session keys derived successfully");
        
#if DEBUG
        _logger.LogDebug("DEBUG: S-ENC length: {Length} bytes", sessionKeys.SEnc.Length);
#endif
        
        // Build card cryptogram data per GP spec E.4.2.1
        // Format: Host Challenge (8) || Sequence Counter (2) || Card Challenge (6) || Padding
        var cryptogramData = new byte[24]; // Will be padded to 3DES block size
        Array.Copy(hostChallenge, 0, cryptogramData, 0, 8);
        Array.Copy(sequenceCounter, 0, cryptogramData, 8, 2);
        Array.Copy(cardChallenge, 0, cryptogramData, 10, 6);  // Use the 6-byte card challenge directly
        // Apply ISO 7816-4 padding
        cryptogramData[16] = 0x80;
        // Rest is already zeros
        
        _logger.LogDebug("Cryptogram data constructed (24 bytes with padding)");
        
        var cryptogramDataResult = Result.Success<byte[], SmartCardError>(cryptogramData);
        
        if (cryptogramDataResult.IsFailure)
            return cryptogramDataResult.Error;
        
        // Calculate cryptogram using S-ENC session key (per GP spec E.4.2)
        // ELIMINATE DRY: Use same MacService as host-side for consistency
        _logger.LogDebug("Calculating cryptogram MAC using S-ENC session key");
        
        return cryptogramDataResult.Bind(cryptogramData =>
        {
            var macService = new MacService();
            var result = macService.CalculateMac(
                sessionKeys.SEnc,  // Use S-ENC session key, not static MAC key
                cryptogramData,
                ScpVersion.Scp02,
                MacUsage.Cryptogram,
                macLength: 8
            );
            
            return result.Match(
                onSuccess: calculatedMac =>
                {
                    _logger.LogDebug("Card cryptogram calculated successfully: {Cryptogram}", Convert.ToHexString(calculatedMac));
                    return Result.Success<byte[], SmartCardError>(calculatedMac);
                },
                onFailure: error =>
                {
                    _logger.LogError("Failed to calculate card cryptogram: {Error}", error.Message);
                    return Result.Failure<byte[], SmartCardError>(error);
                });
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
        var fullCardChallenge = new byte[8];
        Array.Copy(sequenceCounter, 0, fullCardChallenge, 0, 2);
        Array.Copy(cardChallenge, 0, fullCardChallenge, 2, 6);
        
        var sessionKeysResult = Gp4Net.Domain.Protocol.Scp02ProtocolImpl.DeriveSessionKeys(
            keys,
            hostChallenge,
            cardChallenge,  // Pass the 6-byte card challenge
            sequenceCounter,
            implementationParameter
        );
        
        if (sessionKeysResult.IsFailure)
            return sessionKeysResult.Error;
        
        var sessionKeys = sessionKeysResult.Value;
        
        // Build host cryptogram data per GP spec E.4.2.2
        // Format: Sequence Counter (2) || Card Challenge (6) || Host Challenge (8) || Padding
        var cryptogramData = new byte[24]; // Will be padded to 3DES block size
        Array.Copy(sequenceCounter, 0, cryptogramData, 0, 2);
        Array.Copy(cardChallenge, 0, cryptogramData, 2, 6);  // Use the 6-byte card challenge directly
        Array.Copy(hostChallenge, 0, cryptogramData, 8, 8);
        // Apply ISO 7816-4 padding
        cryptogramData[16] = 0x80;
        // Rest is already zeros
        
        var cryptogramDataResult = Result.Success<byte[], SmartCardError>(cryptogramData);
        
        if (cryptogramDataResult.IsFailure)
            return cryptogramDataResult.Error;
        
        // Calculate cryptogram using S-ENC session key (per GP spec E.4.2)
        // ELIMINATE DRY: Use same MacService as host-side for consistency
        return cryptogramDataResult.Bind(cryptogramData =>
        {
            var macService = new MacService();
            return macService.CalculateMac(
                sessionKeys.SEnc,  // Use S-ENC session key, not static MAC key
                cryptogramData,
                ScpVersion.Scp02,
                MacUsage.Cryptogram,
                macLength: 8
            );
        });
    }

    private Result<Gp4Net.Domain.Keys.SessionKeys, SmartCardError> DeriveScp02SessionKeys(
        IKeySet baseKeys, byte[] hostChallenge, byte[] cardChallenge)
    {
        if (baseKeys is not Scp02KeySet scp02Keys)
            return SmartCardError.InvalidArgument("SCP02 requires SCP02 key set");

        // ELIMINATE DRY VIOLATION: Use the same production KeyDerivationService and Scp02ProtocolImpl 
        // that the host-side uses for consistency
        
        // The sequence counter should be 0001 for virtual cards, not derived from card challenge
        var sequenceCounter = new byte[] { 0x00, 0x01 };
        
        // Use the same production Scp02ProtocolImpl.DeriveSessionKeys method
        return Gp4Net.Domain.Protocol.Scp02ProtocolImpl.DeriveSessionKeys(
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
        var sessionKeysResult = DeriveScp03SessionKeys(keys, hostChallenge, cardChallenge);
        if (sessionKeysResult.IsFailure)
            return sessionKeysResult.Error;
        
        var sessionKeys = sessionKeysResult.Value;
        
        // Create type-safe SCP03 key set with session MAC key
        var keySetWithSession = new Scp03KeySet(
            scp03Keys.EncKey, 
            scp03Keys.MacKey, 
            scp03Keys.DekKey, 
            scp03Keys.KeyVersion) 
        { 
            SMac = sessionKeys.SMac 
        };
        
        // Create type-safe SCP03 parameters
        var parametersResult = CryptogramParameters.ForScp03(
            hostChallenge,
            cardChallenge,
            keySetWithSession);
                
        if (parametersResult.IsFailure)
            return parametersResult.Error;
        
        var cryptogramService = new Domain.Security.CryptogramService();
        return cryptogramService.CalculateCardCryptogram(parametersResult.Value);
    }

    private Result<byte[], SmartCardError> CalculateScp03HostCryptogram(
        byte[] hostChallenge, byte[] cardChallenge, IKeySet keys)
    {
        if (keys is not Scp03KeySet scp03Keys)
            return SmartCardError.InvalidArgument("SCP03 requires SCP03 key set");
            
        // Use single type-safe CryptogramService - no duplication
        var sessionKeysResult = DeriveScp03SessionKeys(keys, hostChallenge, cardChallenge);
        if (sessionKeysResult.IsFailure)
            return sessionKeysResult.Error;
        
        var sessionKeys = sessionKeysResult.Value;
        
        // Create type-safe SCP03 key set with session MAC key
        var keySetWithSession = new Scp03KeySet(
            scp03Keys.EncKey, 
            scp03Keys.MacKey, 
            scp03Keys.DekKey, 
            scp03Keys.KeyVersion) 
        { 
            SMac = sessionKeys.SMac 
        };
        
        // Create type-safe SCP03 parameters
        var parametersResult = CryptogramParameters.ForScp03(
            hostChallenge,
            cardChallenge,
            keySetWithSession);
                
        if (parametersResult.IsFailure)
            return parametersResult.Error;
        
        var cryptogramService = new Domain.Security.CryptogramService();
        return cryptogramService.CalculateHostCryptogram(parametersResult.Value);
    }

    private Result<Gp4Net.Domain.Keys.SessionKeys, SmartCardError> DeriveScp03SessionKeys(
        IKeySet baseKeys, byte[] hostChallenge, byte[] cardChallenge)
    {
        if (baseKeys is not Scp03KeySet scp03Keys)
            return SmartCardError.InvalidArgument("SCP03 requires SCP03 key set");

        try
        {
            // ELIMINATED DRY: Use single production KeyDerivationService - no role-specific logic needed
            // Create key derivation context for SCP03
            var derivationContext = new Scp03KeyDerivationContext(
                scp03Keys,
                hostChallenge,
                cardChallenge
            );
            
            // Use same production KeyDerivationService that host uses
            var sessionKeysResult = _keyDerivationService.DeriveSessionKeys(derivationContext);
            
            if (sessionKeysResult.IsFailure)
                return Result.Failure<Gp4Net.Domain.Keys.SessionKeys, SmartCardError>(sessionKeysResult.Error);
            
            // Return the domain session keys
            return Result.Success<Gp4Net.Domain.Keys.SessionKeys, SmartCardError>(sessionKeysResult.Value);
        }
        catch (Exception ex)
        {
            return Result.Failure<Gp4Net.Domain.Keys.SessionKeys, SmartCardError>(
                SmartCardError.CryptographicError($"Failed to derive SCP03 session keys: {ex.Message}"));
        }
    }

    // Utility methods

    private byte[] DerivePseudoRandomChallenge(byte[] kdk, byte derivationConstant, byte[] context, int outputLengthBits)
    {
        // Use the same KDF structure as SCP03 session key derivation
        // Per GP spec section 4.1.5
        
        // Build the fixed input data: Label + Separator + L
        var fixedInputBeforeCounter = new byte[11 + 1 + 1 + 2]; // Label + derivation + separator + L
        var offset = 0;

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
        var prfType = kdk.Length switch
        {
            16 => Kdf108.Domain.Kdf.PrfType.CmacAes128,
            24 => Kdf108.Domain.Kdf.PrfType.CmacAes192,
            32 => Kdf108.Domain.Kdf.PrfType.CmacAes256,
            _ => throw new ArgumentException($"Unsupported key length: {kdk.Length} bytes"),
        };

        var options = new Kdf108.Domain.Kdf.KdfOptions(
            prfType: prfType,
            counterLengthBits: 8, // SCP03 uses 8-bit counter
            useCounter: true,
            counterLocation: Kdf108.Domain.Kdf.CounterLocation.MiddleFixed
        );

        var kdf = new Kdf108.Domain.Kdf.Modes.CounterModeKdf();
        
        return kdf.DeriveWithSplitFixedInput(
            kdk,
            fixedInputBeforeCounter,
            context,
            outputLengthBits,
            options
        );
    }

    private byte[] BuildScp03Context(byte[] hostChallenge, byte[] cardChallenge)
    {
        // Context = Host Challenge || Card Challenge
        var context = new byte[hostChallenge.Length + cardChallenge.Length];
        Array.Copy(hostChallenge, 0, context, 0, hostChallenge.Length);
        Array.Copy(cardChallenge, 0, context, hostChallenge.Length, cardChallenge.Length);
        return context;
    }


    public Result<byte[], SmartCardError> CalculateAesCmac(byte[] key, byte[] data)
    {
        // Use the centralized MacService for consistency and correctness
        var macService = new MacService();
        return macService.CalculateAesCmac(key, data, macLength: 16);
    }

    private byte[] Expand3DesKey(byte[] key)
    {
        switch (key.Length)
        {
            case 24:
                return key;
            case 16:
            {
                // Expand to 24 bytes: K1 || K2 || K1
                var expanded = new byte[24];
                Array.Copy(key, 0, expanded, 0, 16);
                Array.Copy(key, 0, expanded, 16, 8);
                return expanded;
            }
            default:
                throw new ArgumentException($"Invalid 3DES key length: {key.Length}");
        }

    }

    /// <summary>
    /// Simple key derivation service implementation for testing.
    /// </summary>
    private class KeyDerivationService : IKeyDerivationService
    {
        public Result<Gp4Net.Domain.Keys.SessionKeys, SmartCardError> DeriveSessionKeys(IKeyDerivationContext context)
        {
            if (context.Protocol == ScpVersion.Scp03 && context.KeySet is Scp03KeySet scp03KeySet)
            {
                var derivationContext = BuildScp03Context(context.HostChallenge, context.CardChallenge);
                
                // Use the same KDF method as cryptogram calculation for consistency
                // Per SCP03 specification Table 4-1, session keys use specific derivation constants
                
                // Derive S-ENC (derivation constant 0x04)
                var sEnc = DeriveSessionKey(scp03KeySet.EncKey, 0x04, derivationContext, 128);
                
                // Derive S-MAC (derivation constant 0x06) 
                var sMac = DeriveSessionKey(scp03KeySet.MacKey, 0x06, derivationContext, 128);
                
                // Derive S-RMAC (derivation constant 0x07)
                var sRMac = DeriveSessionKey(scp03KeySet.MacKey, 0x07, derivationContext, 128);
                
                return Result.Success<Gp4Net.Domain.Keys.SessionKeys, SmartCardError>(
                    new Gp4Net.Domain.Keys.SessionKeys(sEnc, sMac, sRMac, scp03KeySet.DekKey));
            }
            
            return Result.Failure<Gp4Net.Domain.Keys.SessionKeys, SmartCardError>(
                SmartCardError.InvalidArgument($"Protocol version {context.Protocol} not supported"));
        }
        
        /// <summary>
        /// Derives a session key using the same KDF structure as other SCP03 operations.
        /// </summary>
        private byte[] DeriveSessionKey(byte[] kdk, byte derivationConstant, byte[] context, int outputLengthBits)
        {
            // Build the fixed input data: Label + Separator + L
            var fixedInputBeforeCounter = new byte[11 + 1 + 1 + 2]; // Label + derivation + separator + L
            var offset = 0;

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
            var prfType = kdk.Length switch
            {
                16 => Kdf108.Domain.Kdf.PrfType.CmacAes128,
                24 => Kdf108.Domain.Kdf.PrfType.CmacAes192,
                32 => Kdf108.Domain.Kdf.PrfType.CmacAes256,
                _ => throw new ArgumentException($"Unsupported key length: {kdk.Length} bytes"),
            };

            var options = new Kdf108.Domain.Kdf.KdfOptions(
                prfType: prfType,
                counterLengthBits: 8, // SCP03 uses 8-bit counter
                useCounter: true,
                counterLocation: Kdf108.Domain.Kdf.CounterLocation.MiddleFixed
            );

            var kdf = new Kdf108.Domain.Kdf.Modes.CounterModeKdf();
            
            return kdf.DeriveWithSplitFixedInput(
                kdk,
                fixedInputBeforeCounter,
                context, // This is the data after counter
                outputLengthBits,
                options
            );
        }
        
        public Result<byte[], SmartCardError> CalculateCryptogram(ICryptogramContext context)
        {
            if (context.ProtocolVersion == 0x03)
            {
                var macService = new MacService();
                return macService.CalculateAesCmac(context.Key, context.Data, macLength: 8);
            }
            
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument($"Protocol version {context.ProtocolVersion:X2} not supported"));
        }
        
        
        private byte[] BuildScp03Context(byte[] hostChallenge, byte[] cardChallenge)
        {
            var context = new byte[hostChallenge.Length + cardChallenge.Length];
            Array.Copy(hostChallenge, 0, context, 0, hostChallenge.Length);
            Array.Copy(cardChallenge, 0, context, hostChallenge.Length, cardChallenge.Length);
            return context;
        }
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
        public Maybe<Gp4Net.Domain.Protocol.ScpImplementation> Implementation
        {
            get
            {
                return Maybe<Gp4Net.Domain.Protocol.ScpImplementation>.None;
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
            return Implementation.GetValueOrDefault(Gp4Net.Domain.Protocol.ScpImplementation.Scp03I70) switch
            {
                Gp4Net.Domain.Protocol.ScpImplementation.Scp03I70 => 0x70,
                Gp4Net.Domain.Protocol.ScpImplementation.Scp03I60 => 0x60,
                Gp4Net.Domain.Protocol.ScpImplementation.Scp03I11 => 0x11,
                _ => 0x70  // Default to pseudo-random
            };
        }
    }

    public Result<(byte[] securedData, CardState newState), SmartCardError> ApplyResponseSecurity(
        byte[] responseData,
        Gp4Net.Domain.Keys.SessionKeys sessionKeys,
        byte[] macChainingValue,
        uint encryptionCounter,
        byte scpVersion,
        byte securityLevel,
        CardState currentState)
    {
        try
        {
            // Use the ResponseSecurityProcessor from the domain
            var domainSecurityLevel = (Gp4Net.Domain.SecurityLevel)securityLevel;
            
            var result = Gp4Net.Domain.Security.CardResponseSecurityProcessor.ApplyResponseSecurity(
                responseData,
                domainSecurityLevel,
                sessionKeys,
                [..macChainingValue],
                encryptionCounter,
                scpVersion
            );
            
            if (result.IsFailure)
                return Result.Failure<(byte[] securedData, CardState newState), SmartCardError>(result.Error);
            
            var processedResult = result.Value;
            
            // Update the secure channel state with new values
            
            // Create MacChainingState from the new chaining value
            var macChainingResult = MacChainingState.Create(
                processedResult.NewMacChainingValue.ToArray(),
                currentState.SecureChannel.Value.ProtocolVersion,
                0x00); // implementation parameter - could be tracked in state if needed
                
            if (macChainingResult.IsFailure)
            {
                return Result.Failure<(byte[] securedData, CardState newState), SmartCardError>(
                    macChainingResult.Error);
            }
            
            // Update secure channel state with new counter and MAC chaining
            var updatedSecureChannelResult = currentState.SecureChannel.Value.UpdateCounterAndMac(
                processedResult.NewEncryptionCounter, 
                macChainingResult.Value);
                
            if (updatedSecureChannelResult.IsFailure)
            {
                return Result.Failure<(byte[] securedData, CardState newState), SmartCardError>(
                    updatedSecureChannelResult.Error);
            }
            
            var newState = currentState.WithUpdatedSecureChannel(updatedSecureChannelResult.Value);
            
            return Result.Success<(byte[] securedData, CardState newState), SmartCardError>(
                (processedResult.SecuredData, newState));
        }
        catch (Exception ex)
        {
            return Result.Failure<(byte[] securedData, CardState newState), SmartCardError>(
                SmartCardError.CryptographicError($"Failed to apply response security: {ex.Message}"));
        }
    }
}