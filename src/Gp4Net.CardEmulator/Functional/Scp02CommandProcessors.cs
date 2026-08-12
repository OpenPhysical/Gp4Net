using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Domain;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using static Gp4Net.CardEmulator.Domain.CommandRequests;
using static Gp4Net.Constants.Constants;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// SCP02-specific command processors for the virtual card emulator.
/// Implements the SCP02 protocol flow according to GlobalPlatform Card Specification v2.2.1.
/// </summary>
[PublicAPI]
public static class Scp02CommandProcessors
{
    /// <summary>
    /// Processes an INITIALIZE UPDATE command for SCP02.
    /// </summary>
    public static Result<(ApduResponse, CardState), SmartCardError> ProcessScp02InitializeUpdate(
        byte[] command,
        CardState state,
        CardConfiguration config,
        IRngContext rngContext,
        LoggingService logging
    )
    {
        logging.LogDebug("=== Starting ProcessScp02InitializeUpdate ===");
        logging.LogDebug("Command length: {Length}", command.Length);
        logging.LogDebug("Command hex: {Command}", Convert.ToHexString(command));
        logging.LogDebug("Card state - SCP version: 0x{Scp:X2}", state.ScpVersion);
        logging.LogDebug("Card state - SCP implementation: {Impl}", state.ScpImplementation);
        logging.LogDebug("Card selected: {Selected}", state.IsSelected);
        logging.LogDebug(
            "Secure channel established: {Established}",
            state.IsSecureChannelEstablished
        );

        logging.LogDebug("About to parse INITIALIZE UPDATE command");
        var result = ParseInitializeUpdateCommand(command)
            .TapError(error => logging.LogError("Failed to parse command: {Error}", error.Message))
            .Tap(_ => logging.LogDebug("Command parsed successfully"))
            .Tap(request =>
                logging.LogDebug(
                    "Parsed INITIALIZE UPDATE - KeyVersion: 0x{KeyVersion:X2}, KeyId: 0x{KeyId:X2}, HostChallenge: {Challenge}",
                    request.KeyVersion,
                    request.KeyIdentifier,
                    Convert.ToHexString(request.HostChallenge)
                )
            )
            .TapError(error =>
                logging.LogError(
                    "Failed to parse INITIALIZE UPDATE command: {Error}",
                    error.Message
                )
            )
            .Bind(request => ValidateScp02Preconditions(request, state, config, logging))
            .Tap(_ => logging.LogDebug("Preconditions validated successfully"))
            .TapError(error =>
                logging.LogError("Precondition validation failed: {Error}", error.Message)
            )
            .Bind(request =>
                GenerateScp02CardChallenge(request, state, config, rngContext, logging)
            )
            .Tap(data =>
                logging.LogDebug(
                    "Card challenge generated - CardChallenge: {Challenge}, SequenceCounter: {Counter}",
                    Convert.ToHexString(data.CardChallenge),
                    Convert.ToHexString(data.SequenceCounter)
                )
            )
            .TapError(error =>
                logging.LogError("Failed to generate card challenge: {Error}", error.Message)
            )
            .Bind(data => CalculateScp02CardCryptogram(data, state, config, rngContext, logging))
            .Tap(result =>
                logging.LogDebug(
                    "Card cryptogram calculated - Cryptogram: {Cryptogram}",
                    Convert.ToHexString(result.CardCryptogram)
                )
            )
            .TapError(error =>
                logging.LogError("Failed to calculate card cryptogram: {Error}", error.Message)
            )
            .Map(result =>
            {
                logging.LogDebug("About to create SCP02 INITIALIZE UPDATE response");
                return CreateScp02InitializeUpdateResponse(result, state, config, logging);
            })
            .TapError(error =>
                logging.LogError("SCP02 INITIALIZE UPDATE failed: {Error}", error.Message)
            );

        logging.LogDebug(
            "=== ProcessScp02InitializeUpdate completed with {Status} ===",
            result.IsSuccess ? "SUCCESS" : "FAILURE"
        );

        return result;
    }

    /// <summary>
    /// Processes an EXTERNAL AUTHENTICATE command for SCP02.
    /// </summary>
    public static Result<
        (ApduResponse, CardState),
        SmartCardError
    > ProcessScp02ExternalAuthenticate(
        byte[] command,
        CardState state,
        CardConfiguration config,
        IRngContext rngContext,
        LoggingService logging
    )
    {
        logging.LogDebug("Processing SCP02 EXTERNAL AUTHENTICATE command");
        logging.LogDebug("SCP02 EXTERNAL AUTHENTICATE: Starting processing");
        logging.LogDebug("Command: {Command}", Convert.ToHexString(command));
        return ParseExternalAuthenticateCommand(command)
            .Tap(request => logging.LogDebug("SCP02 ParseExternalAuthenticateCommand: SUCCESS"))
            .TapError(error =>
                logging.LogDebug(
                    "SCP02 ParseExternalAuthenticateCommand: FAILED - {Error}",
                    error.Message
                )
            )
            .Bind(request => ValidateScp02ExternalAuthPreconditions(request, state))
            .Tap(request =>
                logging.LogDebug("SCP02 ValidateScp02ExternalAuthPreconditions: SUCCESS")
            )
            .TapError(error =>
                logging.LogDebug(
                    "SCP02 ValidateScp02ExternalAuthPreconditions: FAILED - {Error}",
                    error.Message
                )
            )
            .Bind(request => VerifyScp02HostCryptogram(request, state, rngContext, command))
            .Tap(request => logging.LogDebug("SCP02 VerifyScp02HostCryptogram: SUCCESS"))
            .TapError(error =>
                logging.LogDebug("SCP02 VerifyScp02HostCryptogram: FAILED - {Error}", error.Message)
            )
            .Bind(request => DeriveScp02SessionKeys(request, state, rngContext))
            .Tap(sessionKeys => logging.LogDebug("SCP02 DeriveScp02SessionKeys: SUCCESS"))
            .TapError(error =>
                logging.LogDebug("SCP02 DeriveScp02SessionKeys: FAILED - {Error}", error.Message)
            )
            .Map(sessionKeys => CreateScp02ExternalAuthResponse(sessionKeys, state));
    }

    // Helper methods and data structures

    private record Scp02ChallengeData(
        CommandRequests.InitializeUpdateRequest Request,
        byte[] CardChallenge,
        byte[] SequenceCounter
    );

    private record Scp02CryptogramData(
        byte KeyVersion,
        ScpImplementation Implementation,
        byte[] HostChallenge,
        byte[] CardChallenge,
        byte[] SequenceCounter,
        byte[] CardCryptogram,
        IKeySet Keys
    );

    private static Result<InitializeUpdateRequest, SmartCardError> ParseInitializeUpdateCommand(
        byte[] command
    )
    {
        if (command.Length < 13) // CLA INS P1 P2 LC + 8 bytes challenge
        {
            return SmartCardError.WrongLength();
        }

        if (
            command[0] != GlobalPlatform.Cla.GP_STANDARD
            || command[1] != GlobalPlatform.Ins.INITIALIZE_UPDATE
        )
        {
            return SmartCardError.InstructionNotSupported();
        }

        byte keyVersion = command[2];
        byte keyIdentifier = command[3];
        byte lc = command[4];

        // Accept either 13 bytes (no Le) or 14 bytes (with Le)
        if (lc != 8 || command.Length != 13 && command.Length != 14)
        {
            return SmartCardError.WrongLength();
        }

        byte[] hostChallenge = command.Skip(5).Take(8).ToArray();

        return Result.Success<InitializeUpdateRequest, SmartCardError>(
            new InitializeUpdateRequest(keyVersion, keyIdentifier, hostChallenge)
        );
    }

    private static Result<InitializeUpdateRequest, SmartCardError> ValidateScp02Preconditions(
        InitializeUpdateRequest request,
        CardState state,
        CardConfiguration config,
        LoggingService logger
    )
    {
        logger.LogDebug(
            "Validating SCP02 preconditions - Selected: {Selected}, SCP: 0x{Scp:X2}",
            state.IsSelected,
            state.ScpVersion
        );

        // Per GP Card Spec v2.3.1 Section 6.4.1: ISD is implicitly selected by default
        // No need to check IsSelected since ISD is always available for INITIALIZE UPDATE
        logger.LogDebug(
            "ISD is implicitly selected per GP Card Spec v2.3.1 - INIT UPDATE can proceed"
        );

        // Verify SCP02 is configured
        if (state.ScpVersion != 0x02)
        {
            logger.LogWarning(
                "Card not configured for SCP02 - current version: {Scp:X2}",
                state.ScpVersion
            );
            return SmartCardError.InvalidArgument("Card is not configured for SCP02");
        }

        logger.LogDebug("SCP02 preconditions validated successfully");
        return Result.Success<InitializeUpdateRequest, SmartCardError>(request);
    }

    private static Result<Scp02ChallengeData, SmartCardError> GenerateScp02CardChallenge(
        InitializeUpdateRequest request,
        CardState state,
        CardConfiguration config,
        IRngContext rngContext,
        LoggingService logger
    )
    {
        logger.LogDebug("=== GenerateScp02CardChallenge ===");
        logger.LogDebug(
            "Generating SCP02 card challenge for key version 0x{KeyVersion:X2}",
            request.KeyVersion
        );

        // Get sequence counter for the key version
        byte[] sequenceCounter = state.GetSequenceCounter(request.KeyVersion);
        logger.LogDebug(
            "Sequence counter: {SequenceCounter}",
            Convert.ToHexString(sequenceCounter)
        );

        if (!rngContext.HasEnoughEntropy(16))
        {
            logger.LogError("Insufficient entropy available for SCP02 card challenge generation");
            return Result.Failure<Scp02ChallengeData, SmartCardError>(
                SmartCardError.SecurityError("Insufficient entropy for card challenge")
            );
        }

        // SCP02 card challenge is 6 random bytes (sequence counter is separate)
        logger.LogDebug("Calling rngContext.GenerateBytes(6)");
        var challengeResult = rngContext.GenerateBytes(6);

        return challengeResult.Match(
            cardChallenge =>
            {
                logger.LogDebug(
                    "Generated card challenge: {Challenge}",
                    Convert.ToHexString(cardChallenge)
                );
                var result = new Scp02ChallengeData(request, cardChallenge, sequenceCounter);
                logger.LogDebug("=== GenerateScp02CardChallenge completed successfully ===");
                return Result.Success<Scp02ChallengeData, SmartCardError>(result);
            },
            error =>
            {
                logger.LogError("Failed to generate card challenge: {Error}", error.Message);
                return Result.Failure<Scp02ChallengeData, SmartCardError>(error);
            }
        );
    }

    private static Result<Scp02CryptogramData, SmartCardError> CalculateScp02CardCryptogram(
        Scp02ChallengeData data,
        CardState state,
        CardConfiguration config,
        IRngContext rngContext,
        LoggingService logger
    )
    {
        logger.LogDebug("=== CalculateScp02CardCryptogram ===");
        logger.LogDebug("Calculating SCP02 card cryptogram");
        // Determine effective key version
        byte effectiveKeyVersion = data.Request.KeyVersion;
        logger.LogDebug("Requested key version: 0x{KeyVersion:X2}", data.Request.KeyVersion);

        if (effectiveKeyVersion == 0x00)
        {
            logger.LogDebug("Key version 0x00 requested - looking for default key");
            effectiveKeyVersion = state.DefaultKeyVersion;
            logger.LogDebug("State default key version: 0x{KeyVersion:X2}", effectiveKeyVersion);

            if (effectiveKeyVersion == 0xFF)
            {
                logger.LogDebug("No default key version set - using first available static key");
                // Use first available key when no default is set
                effectiveKeyVersion = config.StaticKeys.Keys.Any()
                    ? config.StaticKeys.Keys.First()
                    : (byte)0x00;
                logger.LogDebug(
                    "First available static key version: 0x{KeyVersion:X2}",
                    effectiveKeyVersion
                );
            }
        }

        logger.LogDebug("Looking up key set for version: 0x{KeyVersion:X2}", effectiveKeyVersion);
        // Get the appropriate keys
        // Use functional key resolution
        return ResolveKeySet(effectiveKeyVersion, state, config, logger)
            .Bind(keys =>
            {
                logger.LogDebug(
                    "Found key set for version 0x{KeyVersion:X2}, type: {KeyType}",
                    effectiveKeyVersion,
                    keys.GetType().Name
                );
                return ProcessScp02InitializeUpdateWithKeys(
                    (data.Request, data.SequenceCounter, data.CardChallenge),
                    keys,
                    effectiveKeyVersion,
                    state,
                    rngContext,
                    logger
                );
            });
    }

    private static Result<Scp02CryptogramData, SmartCardError> ProcessScp02InitializeUpdateWithKeys(
        (InitializeUpdateRequest Request, byte[] SequenceCounter, byte[] CardChallenge) data,
        IKeySet keys,
        byte effectiveKeyVersion,
        CardState state,
        IRngContext rngContext,
        LoggingService logger
    )
    {
        // Build SCP02 card cryptogram data
        // Format: Host Challenge (8) || Sequence Counter (2) || Card Challenge (6) || Padding
        byte[] cryptogramData = new byte[24]; // Will be padded to 3DES block size
        Array.Copy(data.Request.HostChallenge, 0, cryptogramData, 0, 8);
        Array.Copy(data.SequenceCounter, 0, cryptogramData, 8, 2);
        Array.Copy(data.CardChallenge, 0, cryptogramData, 10, 6);
        // Apply ISO 7816-4 padding
        cryptogramData[16] = 0x80;
        // Rest is already zeros

        logger.LogDebug(
            "Calling rngContext.CalculateCardCryptogram with SCP version 0x02, implementation: {Impl}",
            state.ScpImplementation
        );

        logger.LogDebug("Cryptogram calculation parameters:");
        logger.LogDebug(
            "  Host challenge: {HostChallenge}",
            Convert.ToHexString(data.Request.HostChallenge)
        );
        logger.LogDebug(
            "  Card challenge (6 bytes random): {CardChallenge}",
            Convert.ToHexString(data.CardChallenge)
        );
        logger.LogDebug(
            "  Sequence counter: {SeqCounter}",
            Convert.ToHexString(data.SequenceCounter)
        );
        logger.LogDebug("  SCP version: 0x02");
        logger.LogDebug("  Implementation: 0x{Impl:X2}", (byte)state.ScpImplementation);

        // Calculate card cryptogram using unified crypto service
        // Per GP Card Spec v2.3.1 Section E.4.2
        var cryptogramResult = CryptoService.Cryptogram.CalculateCardCryptogram(
            data.Request.HostChallenge,
            data.CardChallenge,
            keys,
            0x02,
            (byte)state.ScpImplementation,
            Maybe<byte[]>.From(data.SequenceCounter)
        );

        return cryptogramResult.Match(
            cryptogram =>
            {
                logger.LogDebug(
                    "Cryptogram calculation successful: {Cryptogram}",
                    Convert.ToHexString(cryptogram)
                );

                var result = new Scp02CryptogramData(
                    effectiveKeyVersion,
                    state.ScpImplementation,
                    data.Request.HostChallenge,
                    data.CardChallenge,
                    data.SequenceCounter,
                    cryptogram,
                    keys
                );

                logger.LogDebug("=== CalculateScp02CardCryptogram completed successfully ===");
                return Result.Success<Scp02CryptogramData, SmartCardError>(result);
            },
            error =>
            {
                logger.LogError("Cryptogram calculation failed: {Error}", error.Message);
                return Result.Failure<Scp02CryptogramData, SmartCardError>(error);
            }
        );
    }

    private static (ApduResponse, CardState) CreateScp02InitializeUpdateResponse(
        Scp02CryptogramData data,
        CardState state,
        CardConfiguration config,
        LoggingService logger
    )
    {
        logger.LogDebug("=== CreateScp02InitializeUpdateResponse ===");
        logger.LogDebug("Creating SCP02 INITIALIZE UPDATE response");
        logger.LogDebug(
            "Response data - KeyVersion: 0x{KeyVersion:X2}, Implementation: 0x{Impl:X2}",
            data.KeyVersion,
            (byte)data.Implementation
        );
        logger.LogDebug(
            "Sequence counter: {SeqCounter}, Card challenge: {CardChallenge}, Card cryptogram: {Cryptogram}",
            Convert.ToHexString(data.SequenceCounter),
            Convert.ToHexString(data.CardChallenge),
            Convert.ToHexString(data.CardCryptogram)
        );

        // Build SCP02 INITIALIZE UPDATE response per GP spec Table E-8
        byte[] response = new byte[28]; // Fixed size for SCP02
        int offset = 0;

        logger.LogDebug("Creating response with {Length} bytes", response.Length);

        // Key diversification data (10 bytes)
        Array.Fill<byte>(response, 0x00, offset, 10);
        logger.LogDebug(
            "Added key diversification data (10 bytes of 0x00) at offset {Offset}",
            offset
        );
        offset += 10;

        // Key information (2 bytes) - Key version and SCP ID only
        response[offset++] = data.KeyVersion;
        response[offset++] = 0x02; // SCP02
        logger.LogDebug(
            "Added key info - version: 0x{KeyVersion:X2}, SCP: 0x02 at offset {Offset}",
            data.KeyVersion,
            offset - 2
        );
        // Note: Implementation parameter is NOT part of the response

        // Sequence counter (2 bytes)
        Array.Copy(data.SequenceCounter, 0, response, offset, 2);
        logger.LogDebug("Added sequence counter at offset {Offset}", offset);
        offset += 2;

        // Card challenge (6 bytes)
        Array.Copy(data.CardChallenge, 0, response, offset, 6);
        logger.LogDebug("Added card challenge at offset {Offset}", offset);
        offset += 6;

        // Card cryptogram (8 bytes)
        Array.Copy(data.CardCryptogram, 0, response, offset, 8);
        logger.LogDebug("Added card cryptogram at offset {Offset}", offset);

        logger.LogDebug("Response constructed - Final length: {Length}", response.Length);
        logger.LogDebug("Full response data: {Response}", Convert.ToHexString(response));

        // Per GP Card Spec v2.3.1 Section E.2.2: Store challenges and keys for session key derivation during EXTERNAL AUTHENTICATE
        byte[] fullCardChallenge = CombineSequenceAndChallenge(
            data.SequenceCounter,
            data.CardChallenge
        );
        var newState = state
            .WithChallenges(
                Maybe<byte[]>.From(data.HostChallenge),
                Maybe<byte[]>.From(fullCardChallenge)
            )
            .WithKeys(data.Keys)
            .WithIncrementedSequenceCounter(data.KeyVersion); // Increment for next use

        logger.LogDebug(
            "State updated with challenges and keys for EXTERNAL AUTHENTICATE session key derivation"
        );
        logger.LogDebug("=== CreateScp02InitializeUpdateResponse completed ===");
        logger.LogDebug("Returning SCP02 response with SW 9000");
        return (new ApduResponse(response, StatusWords.Success), newState);
    }

    private static Result<
        ExternalAuthenticateRequest,
        SmartCardError
    > ParseExternalAuthenticateCommand(byte[] command)
    {
        if (command.Length < 5)
            return SmartCardError.WrongLength();

        if (
            command[0] != GlobalPlatform.Cla.SECURED && command[0] != GlobalPlatform.Cla.STANDARD
            || command[1] != Gp4Net.Constants.Apdu.Instructions.EXTERNAL_AUTHENTICATE
        )
            return SmartCardError.InstructionNotSupported();

        byte securityLevel = command[2];
        byte p2 = command[3];
        byte lc = command[4];

        // For SCP02, EXTERNAL AUTHENTICATE command format depends on secure messaging:
        // - CLA=0x00 (no secure messaging): 5 bytes header + 8 bytes host cryptogram = 13 bytes total
        // - CLA=0x84 (secure messaging): 5 bytes header + 8 bytes host cryptogram + 8 bytes MAC = 21 bytes total
        if (command[0] == GlobalPlatform.Cla.SECURED) // Secure messaging with MAC
        {
            if (lc != 16 || command.Length != 21) // LC includes both host cryptogram (8) and MAC (8)
                return SmartCardError.WrongLength();

            byte[] hostCryptogram = command.Skip(5).Take(8).ToArray();
            byte[] hostMac = command.Skip(13).Take(8).ToArray(); // MAC follows the host cryptogram

            return Result.Success<ExternalAuthenticateRequest, SmartCardError>(
                new ExternalAuthenticateRequest(securityLevel, hostCryptogram, hostMac)
            );
        }
        else // No secure messaging (CLA=0x00)
        {
            if (lc != 8 || command.Length != 13) // Only host cryptogram
                return SmartCardError.WrongLength();

            byte[] hostCryptogram = command.Skip(5).Take(8).ToArray();
            byte[] hostMac = []; // No MAC for non-secure messaging

            return Result.Success<ExternalAuthenticateRequest, SmartCardError>(
                new ExternalAuthenticateRequest(securityLevel, hostCryptogram, hostMac)
            );
        }
    }

    private static Result<
        ExternalAuthenticateRequest,
        SmartCardError
    > ValidateScp02ExternalAuthPreconditions(ExternalAuthenticateRequest request, CardState state)
    {
        if (!state.IsSelected)
            return SmartCardError.ConditionsNotSatisfied();

        if (state.HostChallenge.HasNoValue || state.CardChallenge.HasNoValue)
            return SmartCardError.ConditionsNotSatisfied();

        if (state.CurrentKeys.HasNoValue)
            return SmartCardError.ConditionsNotSatisfied();

        // Validate security level for SCP02
        int[] validLevels = [0x00, 0x01, 0x03]; // None, C-MAC, C-DECRYPTION
        if (!validLevels.Contains(request.SecurityLevel))
            return SmartCardError.InvalidArgument(
                $"Invalid security level for SCP02: {request.SecurityLevel:X2}"
            );

        return Result.Success<ExternalAuthenticateRequest, SmartCardError>(request);
    }

    private static Result<ExternalAuthenticateRequest, SmartCardError> VerifyScp02HostCryptogram(
        ExternalAuthenticateRequest request,
        CardState state,
        IRngContext rngContext,
        byte[] originalCommand
    )
    {
        if (
            state.HostChallenge.HasNoValue
            || state.CardChallenge.HasNoValue
            || state.CurrentKeys.HasNoValue
        )
            return SmartCardError.ConditionsNotSatisfied();

        return state.HostChallenge.Match(
            hostChallenge =>
                state.CardChallenge.Match(
                    cardChallenge =>
                        state.CurrentKeys.Match(
                            currentKeys =>
                                PerformScp02CryptogramVerification(
                                    request,
                                    hostChallenge,
                                    cardChallenge,
                                    currentKeys,
                                    state,
                                    rngContext,
                                    originalCommand
                                ),
                            () =>
                                Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                                    SmartCardError.ConditionsNotSatisfied()
                                )
                        ),
                    () =>
                        Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                            SmartCardError.ConditionsNotSatisfied()
                        )
                ),
            () =>
                Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                    SmartCardError.ConditionsNotSatisfied()
                )
        );
    }

    private static Result<
        ExternalAuthenticateRequest,
        SmartCardError
    > PerformScp02CryptogramVerification(
        ExternalAuthenticateRequest request,
        byte[] hostChallenge,
        byte[] cardChallenge,
        IKeySet currentKeys,
        CardState state,
        IRngContext rngContext,
        byte[] originalCommand
    )
    {
        // Extract sequence counter from the card challenge (first 2 bytes)
        byte[] sequenceCounter = cardChallenge.Take(2).ToArray();
        byte[] cardChallengeRandom = cardChallenge.Skip(2).Take(6).ToArray();

        // Calculate expected host cryptogram using unified crypto service
        // Per GP Card Spec v2.3.1 Section E.4.2 - host cryptogram has different order
        return CryptoService
            .Cryptogram.CalculateHostCryptogram(
                hostChallenge,
                cardChallengeRandom,
                currentKeys,
                0x02,
                (byte)state.ScpImplementation,
                Maybe<byte[]>.From(sequenceCounter)
            )
            .Bind(expectedCryptogram =>
                ValidateScp02CryptogramMatch(
                    request,
                    expectedCryptogram,
                    originalCommand,
                    state,
                    rngContext
                )
            );
    }

    private static Result<ExternalAuthenticateRequest, SmartCardError> ValidateScp02CryptogramMatch(
        ExternalAuthenticateRequest request,
        byte[] expectedCryptogram,
        byte[] originalCommand,
        CardState state,
        IRngContext rngContext
    )
    {
        if (!CryptoService.Utils.CompareBytes(request.HostCryptogram, expectedCryptogram))
            return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                SmartCardError.SecurityStatusNotSatisfied()
            );

        // GP Card Specification v2.3.1, Appendix E.3.2.
        return originalCommand.Length > 0 && originalCommand[0] == GlobalPlatform.Cla.SECURED
            ? VerifyScp02CommandMac(request, state, rngContext)
            : Result.Success<ExternalAuthenticateRequest, SmartCardError>(request);
    }

    /// <summary>
    /// Verifies the C-MAC on EXTERNAL AUTHENTICATE command per GlobalPlatform Card Specification v2.3.1.
    /// Per GP Card Spec v2.3.1 Section E.3.2: "For the EXTERNAL AUTHENTICATE command MAC verification, the ICV is set to zero."
    /// Uses the same session keys that were derived during INITIALIZE UPDATE.
    /// </summary>
    private static Result<ExternalAuthenticateRequest, SmartCardError> VerifyScp02CommandMac(
        ExternalAuthenticateRequest request,
        CardState state,
        IRngContext rngContext
    )
    {
        // Only verify MAC if it was provided (secure messaging with CLA=0x84)
        if (request.HostMac.Length == 0)
        {
            return Result.Success<ExternalAuthenticateRequest, SmartCardError>(request);
        }

        // Per GP Card Spec v2.3.1 Section E.3.2: Use the same session key derivation as during INITIALIZE UPDATE
        return ValidateScp02SessionKeyDerivationPreconditions(state)
            .Bind(validatedData =>
                KeyDerivationContext
                    .CreateForScp02(
                        validatedData.currentKeys,
                        validatedData.hostChallenge,
                        validatedData.cardRandom,
                        validatedData.sequenceCounter,
                        ScpImplementation.Scp02I15
                    )
                    .Bind(context => CryptoService.KeyDerivation.DeriveSessionKeys(context))
            )
            .Bind(sessionKeys =>
            {
                // GP Card Specification v2.3.1, Appendix E.3.2 and Table E-9.
                byte[] commandHeader =
                [
                    GlobalPlatform.Cla.SECURED,
                    Gp4Net.Constants.Apdu.Instructions.EXTERNAL_AUTHENTICATE,
                    request.SecurityLevel,
                    0x00,
                    0x10,
                ];
                byte[] macInput = commandHeader.Concat(request.HostCryptogram).ToArray();
                byte[] icv = new byte[8];
                return CryptoService
                    .Mac.CalculateScp02CommandMac(sessionKeys.SMac, macInput, icv)
                    .Bind(expectedMac =>
                        CryptoService.Utils.CompareBytes(request.HostMac, expectedMac)
                            ? Result.Success<ExternalAuthenticateRequest, SmartCardError>(request)
                            : Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                                SmartCardError.SecurityStatusNotSatisfied()
                            )
                    );
            });
    }

    /// <summary>
    /// Derives SCP02 session keys according to GlobalPlatform Card Specification v2.3.1.
    /// Per GP Card Spec v2.3.1 Section E.3.2: "SCP02 mandates the use of a MAC on the EXTERNAL AUTHENTICATE command"
    /// and "For the EXTERNAL AUTHENTICATE command MAC verification, the ICV is set to zero."
    /// Session-derived MAC keys are always used for EXTERNAL AUTHENTICATE command verification.
    /// </summary>
    private static Result<SessionKeys, SmartCardError> DeriveScp02SessionKeys(
        ExternalAuthenticateRequest request,
        CardState state,
        IRngContext rngContext
    )
    {
        return ValidateScp02SessionKeyDerivationPreconditions(state)
            .Bind(validatedData =>
            {
                // Derive session keys according to GP Card Specification v2.3.1 Section E.2.2
                if (validatedData.currentKeys is not Scp02KeySet)
                    return Result.Failure<SessionKeys, SmartCardError>(
                        SmartCardError.InvalidArgument("SCP02 requires SCP02 key set")
                    );

                return KeyDerivationContext
                    .CreateForScp02(
                        validatedData.currentKeys,
                        validatedData.hostChallenge,
                        validatedData.cardRandom,
                        validatedData.sequenceCounter,
                        ScpImplementation.Scp02I15
                    )
                    .Bind(context => CryptoService.KeyDerivation.DeriveSessionKeys(context));
            });
    }

    /// <summary>
    /// Validates preconditions for SCP02 session key derivation.
    /// Per GP Card Spec v2.3.1 Section E.2: Challenges must be available before session key derivation.
    /// Per CryptographicService interface: SCP02 requires 6-byte card challenge (random part only).
    /// </summary>
    private static Result<
        (IKeySet currentKeys, byte[] hostChallenge, byte[] sequenceCounter, byte[] cardRandom),
        SmartCardError
    > ValidateScp02SessionKeyDerivationPreconditions(CardState state)
    {
        var hostChallenge = state.HostChallenge;
        var cardChallenge = state.CardChallenge;
        var currentKeys = state.CurrentKeys;

        return hostChallenge
            .ToResult(SmartCardError.ConditionsNotSatisfied())
            .Bind(host =>
                cardChallenge
                    .ToResult(SmartCardError.ConditionsNotSatisfied())
                    .Map(card => (host, card))
            )
            .Bind(challenges =>
                currentKeys
                    .ToResult(SmartCardError.ConditionsNotSatisfied())
                    .Map(keys =>
                    {
                        byte[] fullCardChallenge = challenges.card;
                        byte[] sequenceCounter;
                        byte[] cardChallengeRandom;

                        if (fullCardChallenge.Length >= 8)
                        {
                            sequenceCounter = fullCardChallenge[..2];
                            cardChallengeRandom = fullCardChallenge[2..8];
                        }
                        else
                        {
                            sequenceCounter =
                                fullCardChallenge.Length >= 2
                                    ? fullCardChallenge[..2]
                                    : fullCardChallenge;
                            cardChallengeRandom =
                                fullCardChallenge.Length > 2
                                    ? fullCardChallenge[2..]
                                    : Array.Empty<byte>();
                        }

                        return (
                            currentKeys: keys,
                            hostChallenge: challenges.host,
                            sequenceCounter,
                            cardRandom: cardChallengeRandom
                        );
                    })
            );
    }

    private static (ApduResponse, CardState) CreateScp02ExternalAuthResponse(
        SessionKeys sessionKeys,
        CardState state
    )
    {
        // Create functional secure channel state for SCP02
        var securityLevel = (SecurityLevel)0x01; // Basic C-MAC
        var secureChannelStateResult = SecureChannelState.Create(
            sessionKeys: sessionKeys,
            securityLevel: securityLevel,
            protocolVersion: (CryptoService.ScpVersion)GlobalPlatform.Protocols.SCP02,
            initialMacChainingValue: new byte[8], // Initialize with zeros for SCP02
            implementationParameter: (byte)state.ScpImplementation
        );

        return secureChannelStateResult.Match(
            secureChannelState =>
            {
                // Update state with established secure channel and store session keys
                // This enables end-to-end secure channel establishment working properly
                var newState = state
                    .WithSecureChannel(secureChannelState)
                    .WithSessionKeys(sessionKeys); // Store session keys for pipeline integration

                // SCP02 EXTERNAL AUTHENTICATE response is typically empty on success
                return (new ApduResponse([], StatusWords.Success), newState);
            },
            error =>
                (
                    new ApduResponse([], StatusWords.CheckingErrors.AuthenticationMethodBlocked),
                    state
                )
        );
    }

    // Utility methods

    /// <summary>
    /// Resolves key set without side effects.
    /// </summary>
    private static Result<IKeySet, SmartCardError> ResolveKeySet(
        byte keyVersion,
        CardState state,
        CardConfiguration config,
        LoggingService logger
    )
    {
        // Log available keys
        string installedKeyVersions = string.Join(
            ", ",
            state.InstalledKeys.Keys.Select(k => $"0x{k:X2}")
        );
        string staticKeyVersions = string.Join(
            ", ",
            config.StaticKeys.Keys.Select(k => $"0x{k:X2}")
        );
        logger.LogDebug(
            "Available keys - Installed: [{InstalledKeys}], Static: [{StaticKeys}]",
            installedKeyVersions,
            staticKeyVersions
        );

        // Check installed keys first using functional pattern
        var installedKeySet = state.InstalledKeys.ContainsKey(keyVersion)
            ? Maybe<IKeySet>.From(state.InstalledKeys[keyVersion])
            : Maybe<IKeySet>.None;
        if (installedKeySet.HasValue)
        {
            logger.LogDebug("Found key 0x{KeyVersion:X2} in installed keys", keyVersion);
            return installedKeySet.ToResult(SmartCardError.ReferencedDataNotFound());
        }

        // Then check static keys
        var staticKeySet = config.StaticKeys.ContainsKey(keyVersion)
            ? Maybe<IKeySet>.From(config.StaticKeys[keyVersion])
            : Maybe<IKeySet>.None;
        if (staticKeySet.HasValue)
        {
            logger.LogDebug("Found key 0x{KeyVersion:X2} in static keys", keyVersion);
            return staticKeySet.ToResult(SmartCardError.ReferencedDataNotFound());
        }

        // If key version is 0x00 or 0xFF, use first available key
        if (keyVersion is 0x00 or 0xFF && config.StaticKeys.Values.Any())
        {
            logger.LogDebug(
                "Key version 0x{KeyVersion:X2} is default marker - using first available key",
                keyVersion
            );
            var firstAvailableKey = config.StaticKeys.Values.First();
            logger.LogDebug("Using first available static key");
            return Result.Success<IKeySet, SmartCardError>(firstAvailableKey);
        }

        logger.LogWarning(
            "Key version 0x{KeyVersion:X2} not found in installed or static keys",
            keyVersion
        );
        return Result.Failure<IKeySet, SmartCardError>(SmartCardError.ReferencedDataNotFound());
    }

    private static byte[] CombineSequenceAndChallenge(byte[] sequenceCounter, byte[] cardChallenge)
    {
        // SCP02 full card challenge is sequence counter (2 bytes) + random (6 bytes)
        byte[] fullChallenge = new byte[8];
        Array.Copy(sequenceCounter, 0, fullChallenge, 0, 2);
        Array.Copy(cardChallenge, 0, fullChallenge, 2, 6);
        return fullChallenge;
    }

    /// <summary>
    /// Checks if a command should be processed as SCP02.
    /// </summary>
    public static bool IsScp02Command(byte[] command, CardState state, ILogger logger)
    {
        if (command.Length < 2)
        {
            logger.LogTrace("Command too short for SCP check");
            return false;
        }

        // Check if it's INITIALIZE UPDATE or EXTERNAL AUTHENTICATE
        byte cla = command[0];
        byte ins = command[1];

        logger.LogTrace(
            "Checking SCP02 command: CLA={Cla:X2} INS={Ins:X2}, card SCP={Scp:X2}",
            cla,
            ins,
            state.ScpVersion
        );

        if (
            cla == GlobalPlatform.Cla.GP_STANDARD && ins == GlobalPlatform.Ins.INITIALIZE_UPDATE
            || cla is GlobalPlatform.Cla.SECURED or GlobalPlatform.Cla.STANDARD
                && ins == Gp4Net.Constants.Apdu.Instructions.EXTERNAL_AUTHENTICATE
        )
        {
            // Check if card is configured for SCP02
            bool isScp02 = state.ScpVersion == 0x02;
            logger.LogDebug(
                "INITIALIZE UPDATE/EXTERNAL AUTHENTICATE detected, SCP02 check: {IsScp02}",
                isScp02
            );
            return isScp02;
        }

        // Check if secure channel is established with SCP02
        bool result = state is { IsSecureChannelEstablished: true, ScpVersion: 0x02 };
        logger.LogTrace("Other command, SCP02 secure channel check: {Result}", result);
        return result;
    }
}
