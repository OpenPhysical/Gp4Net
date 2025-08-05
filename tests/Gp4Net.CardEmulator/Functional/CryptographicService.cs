using System;
using System.Linq;
using System.Security.Cryptography;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Constants;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Security;
using Gp4Net.Utils;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Cryptographic service implementation for the virtual card emulator.
/// Implements actual GlobalPlatform cryptographic operations for testing.
/// </summary>
[PublicAPI]
public class CryptographicService : ICryptographicService
{
    private readonly IKeyDerivationService _keyDerivationService;
    private readonly ILogger<CryptographicService> _logger;
    
    public CryptographicService(ILogger<CryptographicService>? logger = null)
    {
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<CryptographicService>.Instance;
        
        // Use the simple test implementation defined in this file
        _keyDerivationService = new KeyDerivationService();
    }
    
    public CryptographicService(IKeyDerivationService keyDerivationService, ILogger<CryptographicService>? logger = null)
    {
        _keyDerivationService = keyDerivationService;
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<CryptographicService>.Instance;
    }

    public Result<byte[], SmartCardError> GenerateChallenge(int length)
    {
        try
        {
            var challenge = new byte[length];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(challenge);
            return Result.Success<byte[], SmartCardError>(challenge);
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"Failed to generate challenge: {ex.Message}");
        }
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
        byte[] hostChallenge, byte[] cardChallenge, IKeySet keys, byte scpVersion, byte implementationParameter, byte[]? sequenceCounter = null)
    {
        try
        {
            switch (scpVersion)
            {
                case 0x02:
                    if (sequenceCounter == null || sequenceCounter.Length != 2)
                        return SmartCardError.InvalidArgument("SCP02 requires a 2-byte sequence counter");
                    return CalculateScp02CardCryptogram(hostChallenge, cardChallenge, sequenceCounter, keys, implementationParameter);
                case 0x03:
                    if (sequenceCounter != null)
                        return SmartCardError.InvalidArgument("SCP03 does not use a separate sequence counter");
                    return CalculateScp03CardCryptogram(hostChallenge, cardChallenge, keys);
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
        byte[] hostChallenge, byte[] cardChallenge, IKeySet keys, byte scpVersion, byte implementationParameter, byte[]? sequenceCounter = null)
    {
        try
        {
            switch (scpVersion)
            {
                case 0x02:
                    if (sequenceCounter == null || sequenceCounter.Length != 2)
                        return SmartCardError.InvalidArgument("SCP02 requires a 2-byte sequence counter");
                    return CalculateScp02HostCryptogram(hostChallenge, cardChallenge, sequenceCounter, keys, implementationParameter);
                case 0x03:
                    if (sequenceCounter != null)
                        return SmartCardError.InvalidArgument("SCP03 does not use a separate sequence counter");
                    return CalculateScp03HostCryptogram(hostChallenge, cardChallenge, keys);
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
        _logger.LogDebug("Calculating cryptogram MAC using S-ENC session key");
        var result = Gp4Net.Domain.Protocol.Scp02ProtocolImpl.CalculateCryptogramMac(
            sessionKeys.SEnc,  // Use S-ENC session key, not static MAC key
            cryptogramDataResult.Value
        );
        
        if (result.IsSuccess)
        {
            _logger.LogDebug("Card cryptogram calculated successfully: {Cryptogram}", Convert.ToHexString(result.Value));
        }
        else
        {
            _logger.LogError("Failed to calculate card cryptogram: {Error}", result.Error.Message);
        }
        
        return result;
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
        return Gp4Net.Domain.Protocol.Scp02ProtocolImpl.CalculateCryptogramMac(
            sessionKeys.SEnc,  // Use S-ENC session key, not static MAC key
            cryptogramDataResult.Value
        );
    }

    private Result<Gp4Net.Domain.Keys.SessionKeys, SmartCardError> DeriveScp02SessionKeys(
        IKeySet baseKeys, byte[] hostChallenge, byte[] cardChallenge)
    {
        if (baseKeys is not Scp02KeySet scp02Keys)
            return SmartCardError.InvalidArgument("SCP02 requires SCP02 key set");

        try
        {
            // SCP02 session key derivation per GP specification
            var sequenceCounter = cardChallenge.Take(2).ToArray();
            
            // Build derivation data
            var derivationBase = new byte[16];
            Array.Copy(sequenceCounter, 0, derivationBase, 0, 2);
            Array.Copy(hostChallenge, 0, derivationBase, 2, 8);
            Array.Copy(cardChallenge, 2, derivationBase, 10, 6); // Skip sequence counter

            // Derive keys using 3DES
            var sessionEncKey = Derive3DesSessionKey(scp02Keys.EncKey, derivationBase, 0x01);
            var sessionMacKey = Derive3DesSessionKey(scp02Keys.MacKey, derivationBase, 0x02);
            var sessionDekKey = Derive3DesSessionKey(scp02Keys.DekKey, derivationBase, 0x03);

            // For SCP02, we use DEK for both S-RMAC and DEK since SCP02 doesn't have separate R-MAC
            return Result.Success<Gp4Net.Domain.Keys.SessionKeys, SmartCardError>(
                new Gp4Net.Domain.Keys.SessionKeys(
                    sEnc: sessionEncKey,
                    sMac: sessionMacKey,
                    sRMac: sessionDekKey, // SCP02 uses DEK for R-MAC
                    dek: sessionDekKey
                ));
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"Failed to derive SCP02 session keys: {ex.Message}");
        }
    }

    private byte[] Derive3DesSessionKey(byte[] staticKey, byte[] derivationData, byte keyType)
    {
        // SCP02 key derivation per GP specification
        var input = new byte[16];
        Array.Copy(derivationData, 0, input, 0, Math.Min(derivationData.Length, 15));
        input[15] = keyType;

        // 3DES ECB encryption
        var engine = new DesEdeEngine();
        var expandedKey = Expand3DesKey(staticKey);
        engine.Init(true, new KeyParameter(expandedKey));

        var output = new byte[16];
        engine.ProcessBlock(input, 0, output, 0);
        engine.ProcessBlock(input, 8, output, 8);

        return output;
    }

    // SCP03 Implementation

    private Result<byte[], SmartCardError> CalculateScp03CardCryptogram(
        byte[] hostChallenge, byte[] cardChallenge, IKeySet keys)
    {
        if (keys is not Scp03KeySet scp03Keys)
            return SmartCardError.InvalidArgument("SCP03 requires SCP03 key set");

        try
        {
            // First derive session keys
            var sessionKeysResult = DeriveScp03SessionKeys(keys, hostChallenge, cardChallenge);
            if (sessionKeysResult.IsFailure)
                return sessionKeysResult.Error;
            
            var sessionKeys = sessionKeysResult.Value;
            
            // Per GP SCP03 v1.1.1 Section 6.2.2.2:
            // Card cryptogram uses data derivation scheme with S-MAC key
            // Use the same KDF method as session key derivation
            
            // Build context: Host Challenge (8) || Card Challenge (8)
            var context = new byte[16];
            Array.Copy(hostChallenge, 0, context, 0, 8);
            Array.Copy(cardChallenge, 0, context, 8, 8);
            
            // Create cryptogram context for card cryptogram calculation
            var cryptogramContext = new Domain.Keys.CryptogramContext(
                ProtocolVersion: 0x03,  // SCP03
                Key: sessionKeys.SMac,
                Data: context,
                Type: Gp4Net.Cryptography.CryptogramType.CardCryptogram
            );
            
            // Use the key derivation service to calculate the cryptogram
            return _keyDerivationService.CalculateCryptogram(cryptogramContext);
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"Failed to calculate SCP03 card cryptogram: {ex.Message}");
        }
    }

    private Result<byte[], SmartCardError> CalculateScp03HostCryptogram(
        byte[] hostChallenge, byte[] cardChallenge, IKeySet keys)
    {
        if (keys is not Scp03KeySet scp03Keys)
            return SmartCardError.InvalidArgument("SCP03 requires SCP03 key set");

        try
        {
            // First derive session keys
            var sessionKeysResult = DeriveScp03SessionKeys(keys, hostChallenge, cardChallenge);
            if (sessionKeysResult.IsFailure)
                return sessionKeysResult.Error;
            
            var sessionKeys = sessionKeysResult.Value;
            
            // Per GP SCP03 v1.1.1 Section 6.2.2.3:
            // Host cryptogram uses data derivation scheme with S-MAC key
            // Use the same KDF method as session key derivation
            
            // Build context: Host Challenge (8) || Card Challenge (8)
            var context = new byte[16];
            Array.Copy(hostChallenge, 0, context, 0, 8);
            Array.Copy(cardChallenge, 0, context, 8, 8);
            
            // Create cryptogram context for host cryptogram calculation
            var cryptogramContext = new Domain.Keys.CryptogramContext(
                ProtocolVersion: 0x03,  // SCP03
                Key: sessionKeys.SMac,
                Data: context,
                Type: Gp4Net.Cryptography.CryptogramType.HostCryptogram
            );
            
            // Use the key derivation service to calculate the cryptogram
            return _keyDerivationService.CalculateCryptogram(cryptogramContext);
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"Failed to calculate SCP03 host cryptogram: {ex.Message}");
        }
    }

    private Result<Gp4Net.Domain.Keys.SessionKeys, SmartCardError> DeriveScp03SessionKeys(
        IKeySet baseKeys, byte[] hostChallenge, byte[] cardChallenge)
    {
        if (baseKeys is not Scp03KeySet scp03Keys)
            return SmartCardError.InvalidArgument("SCP03 requires SCP03 key set");

        try
        {
            // Build context for key derivation
            var context = BuildScp03Context(hostChallenge, cardChallenge);
            
            // Create key derivation context for SCP03
            var derivationContext = new Scp03KeyDerivationContext(
                scp03Keys,
                hostChallenge,
                cardChallenge
            );
            
            // Use key derivation service interface
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

    private Result<byte[], SmartCardError> Calculate3DesCbcMac(byte[] key, byte[] data)
    {
        try
        {
            var expandedKey = Expand3DesKey(key);
            var engine = new DesEdeEngine();
            var cipher = new CbcBlockCipher(engine);
            var mac = new byte[8];
            var iv = new byte[8]; // Zero IV for MAC

            cipher.Init(true, new ParametersWithIV(new KeyParameter(expandedKey), iv));

            // Process all blocks
            for (int i = 0; i < data.Length; i += 8)
            {
                cipher.ProcessBlock(data, i, mac, 0);
            }

            return Result.Success<byte[], SmartCardError>(mac);
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"3DES-CBC-MAC failed: {ex.Message}");
        }
    }

    public Result<byte[], SmartCardError> CalculateAesCmac(byte[] key, byte[] data)
    {
        try
        {
            var cmac = new CMac(new AesEngine(), 128);
            cmac.Init(new KeyParameter(key));
            cmac.BlockUpdate(data, 0, data.Length);
            
            var mac = new byte[16];
            cmac.DoFinal(mac, 0);
            
            return Result.Success<byte[], SmartCardError>(mac);
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"AES-CMAC failed: {ex.Message}");
        }
    }

    private byte[] Expand3DesKey(byte[] key)
    {
        if (key.Length == 24)
            return key;
        
        if (key.Length == 16)
        {
            // Expand to 24 bytes: K1 || K2 || K1
            var expanded = new byte[24];
            Array.Copy(key, 0, expanded, 0, 16);
            Array.Copy(key, 0, expanded, 16, 8);
            return expanded;
        }
        
        throw new ArgumentException($"Invalid 3DES key length: {key.Length}");
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
                var cmac = new CMac(new AesEngine(), 128);
                cmac.Init(new KeyParameter(context.Key));
                cmac.BlockUpdate(context.Data, 0, context.Data.Length);
                
                var mac = new byte[16];
                cmac.DoFinal(mac, 0);
                
                return Result.Success<byte[], SmartCardError>(mac.Take(8).ToArray()); // Return first 8 bytes
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
        public ScpVersion Protocol => ScpVersion.Scp03;
        public IKeySet KeySet { get; }
        public byte[] HostChallenge { get; }
        public byte[] CardChallenge { get; }
        public Maybe<byte[]> SequenceCounter => Maybe<byte[]>.None;
        public Maybe<Gp4Net.Domain.Protocol.ScpImplementation> Implementation => Maybe<Gp4Net.Domain.Protocol.ScpImplementation>.None;
        
        public Scp03KeyDerivationContext(IKeySet keySet, byte[] hostChallenge, byte[] cardChallenge)
        {
            KeySet = keySet;
            HostChallenge = hostChallenge;
            CardChallenge = cardChallenge;
        }
        
        public byte GetImplementationParameter()
        {
            // Default SCP03 implementation parameter
            return Implementation.GetValueOrDefault(Gp4Net.Domain.Protocol.ScpImplementation.Scp03PseudoRandom) switch
            {
                Gp4Net.Domain.Protocol.ScpImplementation.Scp03PseudoRandom => 0x70,
                Gp4Net.Domain.Protocol.ScpImplementation.Scp03RandomChallenge => 0x60,
                Gp4Net.Domain.Protocol.ScpImplementation.Scp03NoResponseMac => 0x11,
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
                System.Collections.Immutable.ImmutableArray.Create(macChainingValue),
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