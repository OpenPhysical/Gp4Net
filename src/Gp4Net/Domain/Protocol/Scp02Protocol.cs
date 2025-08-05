using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// Implements the SCP02 secure channel protocol.
/// Per GlobalPlatform Card Specification v2.3.1 Appendix E.4 "SCP02".
/// Supports various implementation options (i=04, i=05, i=15, etc.) as defined in Table E-2.
/// </summary>
[PublicAPI]
public class Scp02Protocol : SecureChannelProtocolBase
{
    /// <inheritdoc />
    public override byte ProtocolVersion => ProtocolIdentifiers.Scp02;

    /// <summary>
    /// Initializes a new instance of the Scp02Protocol class.
    /// </summary>
    /// <param name="keySet">The static key set.</param>
    /// <param name="keyDerivationService">The key derivation service.</param>
    /// <param name="logger">The logger.</param>
    public Scp02Protocol(
        IKeySet keySet,
        IKeyDerivationService keyDerivationService,
        ILogger<Scp02Protocol> logger
    ) : base(keySet, keyDerivationService, logger)
    {
        // Validate that this is an SCP02-compatible key set
        if (keySet is not Scp02KeySet)
        {
            throw new ArgumentException(
                "SCP02 protocol requires SCP02 key set",
                nameof(keySet)
            );
        }
    }

    /// <inheritdoc />
    protected override Result<InitializeUpdateCommand, SmartCardError> CreateInitializeUpdateCommandImpl(
        byte[] hostChallenge)
    {
        _logger.LogDebug("Creating SCP02 INITIALIZE UPDATE command");

        // For SCP02, key identifier can vary (0x00 is common)
        return InitializeUpdateCommand.Create(_keySet.KeyVersion, 0x00, hostChallenge);
    }

    /// <inheritdoc />
    protected override Result<SecureChannelContext, SmartCardError> ProcessInitializeUpdateResponseImpl(
        InitializeUpdateResponse response,
        byte[] hostChallenge
    )
    {
        _logger.LogDebug(
            "Processing SCP02 INITIALIZE UPDATE response with implementation option i={Option:X2}",
            response.ScpParameter
        );

        // For SCP02, we need the sequence counter from the response
        var validation = ProtocolValidation.ValidateSequenceCounter(response.SequenceCounter, 2);
        if (validation.IsFailure)
            return Result.Failure<SecureChannelContext, SmartCardError>(
                SmartCardError.InvalidResponse(validation.Error));
            
        return DeriveSessionKeysAndValidate(response, hostChallenge);

        Result<SecureChannelContext, SmartCardError> DeriveSessionKeysAndValidate(
            InitializeUpdateResponse response,
            byte[] hostChallenge)
        {
            // Validate sequence counter exists for SCP02
            if (response.SequenceCounter == null)
                return Result.Failure<SecureChannelContext, SmartCardError>(
                    SmartCardError.InvalidResponse("SCP02 requires sequence counter in INITIALIZE UPDATE response"));

            // Create SCP02-specific key derivation context
            var contextResult = KeyDerivationContext.CreateForScp02(
                keySet: _keySet,
                hostChallenge: hostChallenge,
                cardChallenge: response.CardChallenge,
                sequenceCounter: response.SequenceCounter,
                implementation: GetScp02Implementation(response.ScpParameter)
            );

            if (contextResult.IsFailure)
                return Result.Failure<SecureChannelContext, SmartCardError>(contextResult.Error);

            // Derive session keys
            var sessionKeysResult = _keyDerivationService.DeriveSessionKeys(contextResult.Value);
            if (sessionKeysResult.IsFailure)
                return sessionKeysResult.Error;
            var sessionKeys = sessionKeysResult.Value;

            // Verify card cryptogram using shared base class logic
            return VerifyCardCryptogram(response, hostChallenge, sessionKeys)
                .Bind(isValid => isValid
                    ? Result.Success<SecureChannelContext, SmartCardError>(CreateSecureChannelContext())
                    : SmartCardError.SecurityError("Card cryptogram verification failed")
                );

            SecureChannelContext CreateSecureChannelContext()
            {
                _logger.LogDebug("Successfully processed SCP02 INITIALIZE UPDATE response");

                return new SecureChannelContext(
                    hostChallenge,
                    response,
                    sessionKeys,
                    ProtocolVersion,
                    _keySet
                );
            }
        }
    }

    /// <inheritdoc />
    protected override Result<ExternalAuthenticateCommand, SmartCardError> CreateExternalAuthenticateCommandImpl(
        SecureChannelContext context,
        SecurityLevel securityLevel
    )
    {
        _logger.LogDebug(
            "Creating SCP02 EXTERNAL AUTHENTICATE command with security level {SecurityLevel}",
            securityLevel
        );

        // Calculate host cryptogram using shared base class logic
        return CalculateHostCryptogram(context)
            .Bind(hostCryptogram => CreateExternalAuthCommand(securityLevel, hostCryptogram, context));

        Result<ExternalAuthenticateCommand, SmartCardError> CreateExternalAuthCommand(
            SecurityLevel securityLevel, 
            byte[] hostCryptogram, 
            SecureChannelContext context)
        {
            // For SCP02, if C-MAC is requested, we need to calculate MAC over the command
            if (securityLevel.HasCMac())
            {
                // Create the command without MAC first to get the APDU structure
                return ExternalAuthenticateCommand.CreateWithoutMac(securityLevel, hostCryptogram)
                    .Bind(tempCommand =>
                    {
                        var commandApdu = CryptographicOperations.ConcatenateArrays(
                            new byte[] { tempCommand.Cla, tempCommand.Ins, tempCommand.P1, tempCommand.P2, (byte)tempCommand.Data!.Length },
                            tempCommand.Data!
                        );

                        // Calculate MAC over the command
                        var mac = CalculateCMacForCommand(commandApdu, context.SessionKeys.SMac);
                            
                        return ExternalAuthenticateCommand.CreateWithMac(securityLevel, hostCryptogram, mac);
                    });
            }

            return ExternalAuthenticateCommand.CreateWithoutMac(securityLevel, hostCryptogram);
        }
    }

    /// <inheritdoc />
    public override Result<Security.SecureChannelState, SmartCardError> CreateSecureChannelSession(
        SecureChannelContext context,
        SecurityLevel securityLevel
    )
    {
        if (context == null)
            return SmartCardError.InvalidArgument("Context cannot be null");

        // For SCP02, MAC chaining value starts with zero ICV
        // Per GP Card Specification v2.3.1 Section E.4.3:
        // "The ICV is a full DES block (8 bytes) of binary zeroes for the first command"
        var macChainingValue = new byte[8]; // 8 bytes for SCP02 (3DES block size)

        _logger?.LogDebug(
            "Creating SCP02 secure channel session with security level {SecurityLevel}",
            securityLevel
        );

        // Get implementation parameter from INITIALIZE UPDATE response
        var implementationParameter = context.InitializeUpdateResponse.ScpParameter;

        return Security.SecureChannelState.Create(
            context.SessionKeys,
            securityLevel,
            context.ProtocolVersion,
            macChainingValue,
            implementationParameter
        );
    }


    /// <summary>
    /// Calculates C-MAC for a command during authentication.
    /// Per GP Card Specification v2.3.1 Section E.4.3 "SCP02 - Message Integrity":
    /// "The MAC is the result of ISO 9797-1 MAC Algorithm 3 (Retail MAC)"
    /// </summary>
    private byte[] CalculateCMacForCommand(byte[] command, byte[] sMacKey)
    {
        // For SCP02 authentication, MAC is calculated over the command with zero ICV
        // Per GP Card Specification v2.3.1 Section E.4.3:
        // "ICV set to zero (binary) for the first command following application selection"
        var zeroIcv = new byte[8]; // 8 bytes for SCP02
        var macInput = CryptographicOperations.ConcatenateArrays(zeroIcv, command);

        var cryptogramContext = new CryptogramContext(
            ProtocolVersion,
            sMacKey,
            macInput,
            CryptogramType.CommandMac
        );

        var result = _keyDerivationService.CalculateCryptogram(cryptogramContext);
        return result.IsSuccess ? result.Value : new byte[8]; // Return empty MAC on failure
    }

    /// <inheritdoc />
    protected override Result<byte[], SmartCardError> BuildCardCryptogramData(
        InitializeUpdateResponse response,
        byte[] hostChallenge
    )
    {
        return CryptogramBuilder.BuildScp02CardCryptogramData(response, hostChallenge);
    }

    /// <inheritdoc />
    protected override Result<byte[], SmartCardError> BuildHostCryptogramData(
        InitializeUpdateResponse response,
        byte[] hostChallenge
    )
    {
        return CryptogramBuilder.BuildScp02HostCryptogramData(response, hostChallenge);
    }

    private static ScpImplementation GetScp02Implementation(byte implementationParameter)
    {
        return implementationParameter switch
        {
            0x15 => ScpImplementation.Scp02StaticMac,
            0x55 => ScpImplementation.Scp02CmacMult,
            0x1A => ScpImplementation.Scp02CmacXor,
            0x04 => ScpImplementation.Scp02ExplicitInitVector,
            0x05 => ScpImplementation.Scp02ImplicitInitVector,
            _ => ScpImplementation.Scp02StaticMac
        };
    }
}