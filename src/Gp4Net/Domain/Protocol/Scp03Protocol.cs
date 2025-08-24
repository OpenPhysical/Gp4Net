// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Security;
using JetBrains.Annotations;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Kdf.Modes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// Implements the SCP03 secure channel protocol.
/// </summary>
[PublicAPI]
public class Scp03Protocol : SecureChannelProtocolBase
{
    private readonly byte _implementation;

    /// <summary>
    /// Gets the protocol version identifier.
    /// </summary>
    public override byte ProtocolVersion
    {
        get
        {
            return ProtocolIdentifiers.Scp03;
        }
    }

    /// <summary>
    /// Gets the SCP03 implementation parameter.
    /// </summary>
    public byte Implementation
    {
        get
        {
            return _implementation;
        }
    }

    /// <summary>
    /// Initializes a new instance of the Scp03Protocol class.
    /// </summary>
    /// <param name="keySet">The static key set.</param>
    /// <param name="keyDerivationService">The key derivation service.</param>
    /// <param name="implementation">The SCP03 implementation parameter (default is 0x70).</param>
    public Scp03Protocol(IKeySet keySet, IKeyDerivationService keyDerivationService, byte implementation = 0x70)
        : this(keySet, keyDerivationService, NullLogger<Scp03Protocol>.Instance, implementation)
    {
    }

    /// <summary>
    /// Initializes a new instance of the Scp03Protocol class with logging.
    /// </summary>
    /// <param name="keySet">The static key set.</param>
    /// <param name="keyDerivationService">The key derivation service.</param>
    /// <param name="logger">The logger instance.</param>
    /// <param name="implementation">The SCP03 implementation parameter (default is 0x70).</param>
    public Scp03Protocol(IKeySet keySet, IKeyDerivationService keyDerivationService, ILogger<Scp03Protocol> logger, byte implementation = 0x70)
        : base(keySet, keyDerivationService, logger)
    {
        _implementation = implementation;

        // Validate that this is an SCP03-compatible key set
        if (keySet is not Scp03KeySet)
        {
            throw new ArgumentException("SCP03 protocol requires SCP03 key set");
        }

        // Validate implementation parameter
        if (!IsValidImplementation(implementation))
        {
            throw new ArgumentException("Invalid SCP03 implementation parameter");
        }

        _logger.LogDebug("Initialized SCP03 protocol with implementation parameter: {Implementation:X2}", implementation);
        _logger.LogDebug("Key set version: {KeyVersion:X2}", keySet.KeyVersion);
    }

    /// <summary>
    /// Validates if the implementation parameter is valid for SCP03.
    /// </summary>
    private static bool IsValidImplementation(byte implementation)
    {
        return implementation == 0x00
               || // No R-MAC, no R-ENC
               implementation == 0x10
               || // R-MAC
               implementation == 0x20
               || // R-ENC
               implementation == 0x60
               || // R-MAC and R-ENC with random card challenge
               implementation == 0x70; // R-MAC and R-ENC with pseudo-random card challenge
    }

    /// <inheritdoc />
    protected override Result<InitializeUpdateCommand, SmartCardError> CreateInitializeUpdateCommandImpl(byte[] hostChallenge)
    {
        _logger.LogDebug("Creating SCP03 INITIALIZE UPDATE command");
        _logger.LogDebug("Host challenge: {Challenge}", hostChallenge.ToHexString());

        // For SCP03, key identifier must be 0x00
        return InitializeUpdateCommand.Create(_keySet.KeyVersion, 0x00, hostChallenge)
            .Tap(cmd => _logger.LogDebug("Created INITIALIZE UPDATE: KeyVersion={KeyVersion:X2}, KeyId={KeyId:X2}", 
                cmd.P1, cmd.P2));
    }

    /// <inheritdoc />
    protected override Result<SecureChannelContext, SmartCardError> ProcessInitializeUpdateResponseImpl(
        InitializeUpdateResponse response,
        byte[] hostChallenge)
    {
        _logger.LogDebug("Processing INITIALIZE UPDATE response");
            
        if (response == null)
        {
            _logger.LogError("INITIALIZE UPDATE response is null");
            return SmartCardError.InvalidArgument("Response cannot be null");
        }

        if (hostChallenge?.Length != 8)
        {
            _logger.LogError("Invalid host challenge length in response processing");
            return SmartCardError.InvalidData("Host challenge must be 8 bytes");
        }

        _logger.LogDebug("Response SCP ID: {ScpId:X2}", response.ScpId);
        _logger.LogDebug("Card challenge: {Challenge}", response.CardChallenge.ToHexString());
        _logger.LogDebug("Card cryptogram: {Cryptogram}", response.CardCryptogram.ToHexString());

        // Verify the response is for SCP03
        if ((response.ScpId & ProtocolIdentifiers.ProtocolMask) != ProtocolIdentifiers.Scp03)
        {
            _logger.LogError("Invalid SCP version: expected SCP03, got SCP{ScpId:X2}", response.ScpId);
            return SmartCardError.InvalidResponse($"Expected 03 but received {response.ScpId:X2}");
        }

        // Extract implementation parameter from response (it's in the third byte of key information)
        var cardImplementation = response.ScpParameter;
        _logger.LogDebug("Card implementation parameter: {Implementation:X2}", cardImplementation);

        // Verify implementation matches what we expect
        if (cardImplementation != _implementation)
        {
            _logger.LogWarning("Card reports different implementation parameter: expected {Expected:X2}, got {Actual:X2}", 
                _implementation, cardImplementation);
            // Continue - card may report different i-value during protocol transition
        }

        // Determine key length from the static keys
        var keyLength = _keySet.EncKey.Length * 8;
        _logger.LogDebug("Key length: {KeyLength} bits", keyLength);

        // Create SCP03-specific key derivation context
        _logger.LogDebug("Creating SCP03 key derivation context...");
        var contextResult = KeyDerivationContext.CreateForScp03(
            keySet: _keySet,
            hostChallenge: hostChallenge,
            cardChallenge: response.CardChallenge,
            implementation: Maybe<ScpImplementation>.From(GetScpImplementation(cardImplementation))
        );

        if (contextResult.IsFailure)
        {
            _logger.LogError("Failed to create key derivation context: {Error}", contextResult.Error.Message);
            return contextResult.Error;
        }

        // Derive session keys using the key derivation service
        _logger.LogDebug("Deriving session keys...");
        var sessionKeysResult = _keyDerivationService.DeriveSessionKeys(contextResult.Value);
        if (sessionKeysResult.IsFailure)
        {
            _logger.LogError("Failed to derive session keys: {Error}", sessionKeysResult.Error.Message);
            return sessionKeysResult.Error;
        }
        var sessionKeys = sessionKeysResult.Value;
        _logger.LogDebug("Session keys derived successfully");
        _logger.LogTrace("S-ENC: {SEnc}", sessionKeys.SEnc.ToHexString());
        _logger.LogTrace("S-MAC: {SMac}", sessionKeys.SMac.ToHexString());
        _logger.LogTrace("S-RMAC: {SRMac}", sessionKeys.SrMac.ToHexString());

        // Strict spec: verify card cryptogram
        _logger.LogDebug("Verifying card cryptogram...");
        var cryptogramResult = base.VerifyCardCryptogram(response, hostChallenge, sessionKeys);
        if (cryptogramResult.IsFailure)
        {
            _logger.LogError("Failed to verify card cryptogram: {Error}", cryptogramResult.Error.Message);
            return cryptogramResult.Error;
        }
        
        if (!cryptogramResult.Value)
        {
            _logger.LogError("Card cryptogram verification failed!");
            _logger.LogError("Expected cryptogram based on context: HostChallenge={Host}, CardChallenge={Card}", 
                hostChallenge.ToHexString(), response.CardChallenge.ToHexString());
            return SmartCardError.SecurityError("Card cryptogram verification failed");
        }
        _logger.LogDebug("Card cryptogram verified successfully");

        var context = new SecureChannelContext(
            hostChallenge,
            response,
            sessionKeys,
            ProtocolVersion,
            _keySet
        );

        return Result.Success<SecureChannelContext, SmartCardError>(context);
    }

    /// <inheritdoc />
    protected override Result<ExternalAuthenticateCommand, SmartCardError> CreateExternalAuthenticateCommandImpl(
        SecureChannelContext context,
        SecurityLevel securityLevel)
    {
        if (context is null)
            return Result.Failure<ExternalAuthenticateCommand, SmartCardError>(
                SmartCardError.InvalidArgument("Context cannot be null"));

        // Calculate host cryptogram
        var hostCryptogram = CalculateHostCryptogram(
            context.InitializeUpdateResponse,
            context.HostChallenge,
            context.SessionKeys
        );

        // Use MacService for MAC calculation
        return ExternalAuthenticateCommand.CreateWithoutMac(securityLevel, hostCryptogram)
            .Bind(command =>
            {
                var apdu = BuildCommandApdu(command);
                var zeroChaining = new byte[16]; // Zero chaining value for EXTERNAL AUTHENTICATE
                
                // SCP03 C-MAC per GP SCP03 v1.1.1 Section 6.2.4:
                // "A C-MAC is generated...applied across the MAC chaining value concatenated with
                // the full APDU command being transmitted to the card"
                var macInput = new byte[zeroChaining.Length + apdu.Length];
                Array.Copy(zeroChaining, 0, macInput, 0, zeroChaining.Length);
                Array.Copy(apdu, 0, macInput, zeroChaining.Length, apdu.Length);
                
                var macService = new MacService();
                return macService.CalculateAesCmac(context.SessionKeys.SMac, macInput, 8)
                    .Map(mac => ExternalAuthenticateCommand.CreateWithMac(securityLevel, hostCryptogram, mac))
                    .Bind(result => result);
            });

        static byte[] BuildCommandApdu(ExternalAuthenticateCommand command)
        {
            // For EXTERNAL AUTHENTICATE, the Lc in the final APDU will always be 0x10 (16 bytes)
            // when C-MAC is used: 8 bytes host cryptogram + 8 bytes MAC
            // We need to build the APDU as it will appear for MAC calculation
            var apdu = new byte[5 + command.HostCryptogram.Length];
            apdu[0] = 0x84; // CLA with secure messaging
            apdu[1] = command.Ins;
            apdu[2] = command.P1;
            apdu[3] = command.P2;
            apdu[4] = 0x10; // Lc = 16 bytes (8 cryptogram + 8 MAC)
            Array.Copy(command.HostCryptogram, 0, apdu, 5, command.HostCryptogram.Length);
            return apdu;
        }
    }

    /// <inheritdoc />
    public override Result<Security.SecureChannelState, SmartCardError> CreateSecureChannelSession(
        SecureChannelContext context,
        SecurityLevel securityLevel)
    {
        if (context == null)
        {
            return SmartCardError.InvalidArgument("Context cannot be null");
        }

        // Calculate initial MAC chaining value using the new static service
        byte[] macChainingValue;
        if (securityLevel.HasCMac())
        {
            // Per GP SCP03 v1.1.1 Section 6.2.3 "Message Integrity Using Explicit Secure Channel Initiation":
            // "After the EXTERNAL AUTHENTICATE command MAC verification, the 'MAC chaining value'
            // becomes the full 16 byte C-MAC value calculated for that command"
            var hostCryptogram = CalculateHostCryptogram(
                context.InitializeUpdateResponse,
                context.HostChallenge,
                context.SessionKeys
            );

            var extAuthResult = ExternalAuthenticateCommand.CreateWithoutMac(securityLevel, hostCryptogram)
                .Bind(command =>
                {
                    // Build the EXTERNAL AUTHENTICATE APDU for MAC calculation
                    var apdu = new byte[5 + command.HostCryptogram.Length];
                    apdu[0] = 0x84; // CLA with secure messaging
                    apdu[1] = 0x82; // INS
                    apdu[2] = (byte)command.SecurityLevel; // P1 = security level
                    apdu[3] = 0x00; // P2
                    apdu[4] = 0x10; // Lc = 16 bytes (8 host cryptogram + 8 MAC)
                    Array.Copy(command.HostCryptogram, 0, apdu, 5, command.HostCryptogram.Length);
                    
                    // Calculate AES-CMAC over (zero_chaining_value || apdu)
                    // Per GP SCP03 v1.1.1 Section 6.2.3:
                    // "For the EXTERNAL AUTHENTICATE command MAC verification, the MAC chaining value is set to 16 bytes '00'"
                    var zeroChaining = new byte[16];
                    var macInput = new byte[zeroChaining.Length + apdu.Length];
                    Array.Copy(zeroChaining, 0, macInput, 0, zeroChaining.Length);
                    Array.Copy(apdu, 0, macInput, zeroChaining.Length, apdu.Length);
                    
                    var macService = new MacService();
                    return macService.CalculateAesCmac(context.SessionKeys.SMac, macInput, 16); // Full 16-byte MAC for chaining
                });

            if (extAuthResult.IsFailure)
            {
                return Result.Failure<Security.SecureChannelState, SmartCardError>(
                    SmartCardError.CryptographicError("Failed to calculate initial MAC chaining value"));
            }
            macChainingValue = extAuthResult.Value;
        }
        else
        {
            // If no C-MAC, start with zero
            macChainingValue = new byte[16];
        }

        // For SCP03, implementation parameter is in ScpParameter
        var implementationParameter = context.InitializeUpdateResponse.ScpParameter;

        _logger?.LogDebug(
            "Creating SCP03 secure channel session with security level {SecurityLevel} and implementation parameter {Implementation:X2}",
            securityLevel,
            implementationParameter
        );

        return Security.SecureChannelState.Create(
            context.SessionKeys,
            securityLevel,
            context.ProtocolVersion,
            macChainingValue,
            implementationParameter
        );
    }


    /// <summary>
    /// Verifies the card cryptogram.
    /// </summary>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <param name="hostChallenge">The host challenge.</param>
    /// <param name="sessionKeys">The session keys.</param>
    /// <returns>True if valid, false otherwise.</returns>
    public new bool VerifyCardCryptogram(
        InitializeUpdateResponse response,
        byte[] hostChallenge,
        SessionKeys sessionKeys)
    {
        // Delegate to the base class method
        var result = base.VerifyCardCryptogram(response, hostChallenge, sessionKeys);
        return result.IsSuccess && result.Value;
    }

    /// <summary>
    /// Calculates the host cryptogram.
    /// </summary>
    public byte[] CalculateHostCryptogram(
        InitializeUpdateResponse response,
        byte[] hostChallenge,
        SessionKeys sessionKeys
    )
    {
        // Build context for cryptogram calculation (host challenge + card challenge)
        var context = new byte[16];
        Array.Copy(hostChallenge, 0, context, 0, 8);
        Array.Copy(response.CardChallenge, 0, context, 8, 8);

        // Use the same KDF structure as session key derivation but with host cryptogram derivation constant
        // and length of 64 bits (8 bytes) for the cryptogram
        return DeriveScp03Cryptogram(
            sessionKeys.SMac,
            DerivationConstants.HostCryptogram,
            context,
            64  // 64 bits = 8 bytes for cryptogram
        );
    }


    /// <summary>
    /// Derives SCP03 cryptogram using the same KDF structure as session keys.
    /// Per GP SCP03 v1.1.1 Section 6.2.2.2 "Card Authentication Cryptogram" and
    /// Section 6.2.2.3 "Host Authentication Cryptogram":
    /// "calculated using the data derivation scheme defined in section 4.1.5"
    /// </summary>
    private static byte[] DeriveScp03Cryptogram(
        byte[] kdk,
        byte derivationConstant,
        byte[] context,
        int outputLengthBits
    )
    {
        // Build the "fixed input data" per GP SCP03 v1.1.1 Section 4.1.5:
        // Fixed input = Label || Separator || L
        // Where Label = 11 bytes '00' || derivation constant (Table 4-1)
        // Counter 'i' is inserted by KDF between fixed input and context
        var fixedInputBeforeCounter = new byte[11 + 1 + 1 + 2]; // Label + derivation + separator + L
        var offset = 0;

        // Label (11 bytes of 0x00 followed by derivation constant)
        Array.Copy(DerivationConstants.Scp03Label, 0, fixedInputBeforeCounter, offset, 11);
        offset += 11;
        fixedInputBeforeCounter[offset++] = derivationConstant;

        // Separator
        fixedInputBeforeCounter[offset++] = 0x00;

        // L (length in bits as 2-byte big-endian)
        fixedInputBeforeCounter[offset++] = (byte)(outputLengthBits >> 8);
        fixedInputBeforeCounter[offset++] = (byte)outputLengthBits;

        // Determine PRF type based on key length
        var prfType = kdk.Length switch
        {
            16 => PrfType.CmacAes128,
            24 => PrfType.CmacAes192,
            32 => PrfType.CmacAes256,
            _ => throw new ArgumentException($"Unsupported key length: {kdk.Length} bytes"),
        };

        // Configure KDF options for SCP03
        var options = new KdfOptions(
            prfType: prfType,
            counterLengthBits: 8, // SCP03 uses 8-bit counter
            useCounter: true,
            counterLocation: CounterLocation.MiddleFixed // Counter in the middle of fixed input
        );

        var kdf = new CounterModeKdf();

        // Use DeriveWithSplitFixedInput:
        // - fixedInputBeforeCounter goes before the counter
        // - context goes after the counter
        return kdf.DeriveWithSplitFixedInput(
            kdk,
            fixedInputBeforeCounter, // Label + derivation + separator + L
            context, // Context (host + card challenges)
            outputLengthBits,
            options
        );
    }

    /// <summary>
    /// Calculates a cryptogram using CMAC-AES.
    /// </summary>
    private static byte[] CalculateCryptogram(byte[] key, byte[] data)
    {
        var cmac = new CMac(new AesEngine(), 64); // 64-bit MAC
        cmac.Init(new KeyParameter(key));
        cmac.BlockUpdate(data, 0, data.Length);

        var cryptogram = new byte[8];
        _ = cmac.DoFinal(cryptogram, 0);

        return cryptogram;
    }

    /// <inheritdoc />
    protected override Result<byte[], SmartCardError> BuildCardCryptogramData(
        InitializeUpdateResponse response,
        byte[] hostChallenge)
    {
        return CryptogramBuilder.BuildScp03CardCryptogramData(response, hostChallenge);
    }

    /// <inheritdoc />
    protected override Result<byte[], SmartCardError> BuildHostCryptogramData(
        InitializeUpdateResponse response,
        byte[] hostChallenge)
    {
        return CryptogramBuilder.BuildScp03HostCryptogramData(response, hostChallenge);
    }

    /// <summary>
    /// Compares two byte arrays in constant time.
    /// </summary>
    private static bool CompareBytes(byte[] a, byte[] b)
    {
        return CryptographicOperations.CompareBytes(a, b);
    }

    private static ScpImplementation GetScpImplementation(byte implementationParameter)
    {
        return implementationParameter switch
        {
            0x70 => ScpImplementation.Scp03I70,
            0x60 => ScpImplementation.Scp03I60,
            0x11 => ScpImplementation.Scp03I11,
            _ => ScpImplementation.Scp03I70
        };
    }
}