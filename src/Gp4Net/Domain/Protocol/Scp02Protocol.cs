using System;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Security;
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
    public override byte ProtocolVersion
    {
        get
        {
            return ProtocolIdentifiers.Scp02;
        }
    }

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
        {
            return Result.Failure<SecureChannelContext, SmartCardError>(
                SmartCardError.InvalidResponse(validation.Error));
        }

        return DeriveSessionKeysAndValidate(response, hostChallenge);

        Result<SecureChannelContext, SmartCardError> DeriveSessionKeysAndValidate(
            InitializeUpdateResponse response,
            byte[] hostChallenge)
        {
            // Validate sequence counter exists for SCP02
            if (response.SequenceCounter == null)
            {
                return Result.Failure<SecureChannelContext, SmartCardError>(
                    SmartCardError.InvalidResponse("SCP02 requires sequence counter in INITIALIZE UPDATE response"));
            }

            // Create SCP02-specific key derivation context
            var implementationResult = GetScp02Implementation(response.ScpParameter);
            if (implementationResult.IsFailure)
            {
                return Result.Failure<SecureChannelContext, SmartCardError>(implementationResult.Error);
            }

            var contextResult = KeyDerivationContext.CreateForScp02(
                keySet: _keySet,
                hostChallenge: hostChallenge,
                cardChallenge: response.CardChallenge,
                sequenceCounter: response.SequenceCounter,
                implementation: implementationResult.Value
            );

            if (contextResult.IsFailure)
            {
                return Result.Failure<SecureChannelContext, SmartCardError>(contextResult.Error);
            }

            // Derive session keys
            var sessionKeysResult = _keyDerivationService.DeriveSessionKeys(contextResult.Value);
            if (sessionKeysResult.IsFailure)
            {
                return sessionKeysResult.Error;
            }

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
                        // For EXTERNAL AUTHENTICATE, use the specialized MAC calculation
                        // that builds the proper APDU structure per GP Card Specification
                        var macResult = Scp02ProtocolService.CalculateInitialMacChainingValue(
                            tempCommand, 
                            context.SessionKeys.SMac);
                        
                        if (macResult.IsFailure)
                        {
                            return Result.Failure<ExternalAuthenticateCommand, SmartCardError>(
                                macResult.Error);
                        }
                        
                        // The MAC for EXTERNAL AUTHENTICATE is the full 8-byte result
                        var mac = macResult.Value;
                            
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
        {
            return SmartCardError.InvalidArgument("Context cannot be null");
        }

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
        var implementationResult = GetScp02Implementation(implementationParameter);
        if (implementationResult.IsFailure)
        {
            return Result.Failure<SecureChannelState, SmartCardError>(implementationResult.Error);
        }
        var implementation = implementationResult.Value;

        // For SCP02, adjust security level based on implementation parameter capabilities
        // Per GP Card Specification v2.3.1 Table E-1, R-MAC support is indicated by bit b6
        var adjustedSecurityLevel = AdjustSecurityLevelForScp02Capabilities(securityLevel, implementation);

        _logger?.LogDebug(
            "SCP02 implementation i={Implementation:X2} supports R-MAC: {SupportsRMac}, " +
            "adjusted security level from {RequestedLevel} to {AdjustedLevel}",
            implementationParameter, implementation.HasRMacSupport(), securityLevel, adjustedSecurityLevel
        );

        return Security.SecureChannelState.Create(
            context.SessionKeys,
            adjustedSecurityLevel,
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

        // Use Retail MAC directly for C-MAC calculation
        // Per GP Card Spec v2.3.1 Section E.4.3: C-MAC uses ISO 9797-1 Algorithm 3 (Retail MAC)
        var result = CryptographicOperations.CalculateRetailMac(sMacKey, macInput);
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

    /// <summary>
    /// Converts implementation parameter byte to ScpImplementation enum value.
    /// Per GP Card Specification v2.3.1 Table E-1, all SCP02 i= parameters follow bitmap structure.
    /// Fails hard if the implementation parameter is not recognized - no defaults allowed.
    /// </summary>
    /// <param name="implementationParameter">The i= parameter from INITIALIZE UPDATE response</param>
    /// <returns>The corresponding ScpImplementation enum value</returns>
    /// <exception cref="ArgumentException">Thrown when implementation parameter is not a valid SCP02 implementation</exception>
    public static Result<ScpImplementation, SmartCardError> GetScp02Implementation(byte implementationParameter)
    {
        // Check if this is a valid SCP02 implementation by trying to cast to enum
        if (Enum.IsDefined(typeof(ScpImplementation), implementationParameter))
        {
            var impl = (ScpImplementation)implementationParameter;
            if (impl.IsScp02())
            {
                return Result.Success<ScpImplementation, SmartCardError>(impl);
            }
        }
        
        // Return error - no defaults allowed
        return Result.Failure<ScpImplementation, SmartCardError>(
            new UnsupportedImplementationError(
                $"SCP02 i={implementationParameter:X2} (valid: 00, 02, 04, 05, 15, 35, 55, 75)"));
    }

    /// <summary>
    /// Adjusts the requested security level based on SCP02 implementation capabilities.
    /// Per GP Card Specification v2.3.1 Table E-1, some features may not be available.
    /// </summary>
    /// <param name="requestedLevel">The security level requested by the caller</param>
    /// <param name="implementation">The SCP02 implementation from the card</param>
    /// <returns>The adjusted security level that respects card capabilities</returns>
    private SecurityLevel AdjustSecurityLevelForScp02Capabilities(SecurityLevel requestedLevel, ScpImplementation implementation)
    {
        var adjustedLevel = requestedLevel;

        // Check R-MAC capability - if card doesn't support R-MAC, remove it from security level
        if (requestedLevel.HasRMac() && !implementation.HasRMacSupport())
        {
            _logger.LogWarning(
                "SCP02 implementation i={Implementation:X2} does not support R-MAC. Removing R-MAC from security level.",
                (byte)implementation
            );
            
            // Remove R-MAC flag from security level
            adjustedLevel = (SecurityLevel)((int)adjustedLevel & ~(int)SecurityLevel.RMac);
        }

        // For SCP02, R-ENC is not supported independently - it would be tied to R-MAC in practice
        // If R-ENC was requested but R-MAC isn't supported, also remove R-ENC
        if (requestedLevel.HasREncryption() && !implementation.HasRMacSupport())
        {
            _logger.LogWarning(
                "SCP02 implementation i={Implementation:X2} does not support R-MAC, also removing R-ENC as it requires R-MAC.",
                (byte)implementation
            );
            
            // Remove R-ENC flag from security level  
            adjustedLevel = (SecurityLevel)((int)adjustedLevel & ~(int)SecurityLevel.REncryption);
        }

        return adjustedLevel;
    }
}