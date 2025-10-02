// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Security;
using Gp4Net.Extensions;
using Gp4Net.Shared;
using Gp4Net.Transport;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using WSCT.ISO7816;
using static Gp4Net.Constants.Constants;

namespace Gp4Net.Services;

/// <summary>
/// Security operations for the unified SCP service.
/// ONLY orchestrates by calling CryptoService - contains NO crypto logic itself.
/// </summary>
public static partial class ScpService
{
    /// <summary>
    /// Secure command and response processing operations.
    /// Orchestrates security application by delegating to CryptoService.
    /// </summary>
    [PublicAPI]
    public static class Security
    {
#if DEBUG
        private static readonly ILogger Logger = NullLoggerFactory.Instance.CreateLogger(
            "Gp4Net.Services.ScpService.Security"
        );

        [Conditional("DEBUG")]
        private static void DebugLog(string message)
        {
            Logger.LogDebug(message);
            Debug.WriteLine(message);
        }
#else
        private static readonly ILogger Logger = NullLoggerFactory.Instance.CreateLogger(
            "Gp4Net.Services.ScpService.Security"
        );

        [Conditional("DEBUG")]
        private static void DebugLog(string message) { }
#endif

        /// <summary>
        /// Applies command security (MAC and/or encryption) to a command APDU.
        /// Orchestrates by calling the appropriate CryptoService operations.
        /// </summary>
        /// <param name="command">The command APDU to secure.</param>
        /// <param name="state">The current secure channel state.</param>
        /// <returns>The secured command and new state.</returns>
        public static Result<
            (CommandAPDU securedCommand, SecureChannelState newState),
            SmartCardError
        > ApplyCommandSecurity(CommandAPDU command, SecureChannelState state)
        {
            return state.Protocol switch
            {
                CryptoService.ScpVersion.Scp02 => ApplyScp02CommandSecurity(command, state),
                CryptoService.ScpVersion.Scp03 => ApplyScp03CommandSecurity(command, state),
                _
                    => Result.Failure<(CommandAPDU, SecureChannelState), SmartCardError>(
                        SmartCardError.InvalidArgument($"Unsupported protocol: {state.Protocol}")
                    ),
            };
        }

        /// <summary>
        /// Processes response security (MAC verification and/or decryption) for a response APDU.
        /// Orchestrates by calling the appropriate CryptoService operations.
        /// </summary>
        /// <param name="response">The response APDU to process.</param>
        /// <param name="state">The current secure channel state.</param>
        /// <returns>The processed response and new state.</returns>
        public static Result<
            (ResponseAPDU processedResponse, SecureChannelState newState),
            SmartCardError
        > ProcessResponseSecurity(ResponseAPDU response, SecureChannelState state)
        {
            // Check if response security should be applied
            ushort statusWord = response.StatusWord;
            if (!Scp.StatusWords.ShouldApplyResponseSecurity(statusWord))
                return Result.Success<(ResponseAPDU, SecureChannelState), SmartCardError>(
                    (response, state)
                );

            return state.Protocol switch
            {
                CryptoService.ScpVersion.Scp02 => ProcessScp02ResponseSecurity(response, state),
                CryptoService.ScpVersion.Scp03 => ProcessScp03ResponseSecurity(response, state),
                _
                    => Result.Failure<(ResponseAPDU, SecureChannelState), SmartCardError>(
                        SmartCardError.InvalidArgument($"Unsupported protocol: {state.Protocol}")
                    ),
            };
        }

        /// <summary>
        /// Removes command security (MAC verification and/or decryption) from a secured command APDU.
        /// This is the reverse of ApplyCommandSecurity - used for trace decryption.
        /// </summary>
        /// <param name="securedCommand">The secured command APDU.</param>
        /// <param name="state">The current secure channel state.</param>
        /// <returns>The plaintext command and new state, or error if MAC verification fails.</returns>
        public static Result<
            (CommandAPDU plaintextCommand, SecureChannelState newState),
            SmartCardError
        > RemoveCommandSecurity(CommandAPDU securedCommand, SecureChannelState state)
        {
            return state.Protocol switch
            {
                CryptoService.ScpVersion.Scp02 => RemoveScp02CommandSecurity(securedCommand, state),
                CryptoService.ScpVersion.Scp03 => RemoveScp03CommandSecurity(securedCommand, state),
                _
                    => Result.Failure<(CommandAPDU, SecureChannelState), SmartCardError>(
                        SmartCardError.InvalidArgument($"Unsupported protocol: {state.Protocol}")
                    ),
            };
        }

        /// <summary>
        /// Removes response security (MAC verification and/or decryption) from a secured response APDU.
        /// This is the reverse of ProcessResponseSecurity - used for trace decryption.
        /// </summary>
        /// <param name="securedResponse">The secured response APDU.</param>
        /// <param name="state">The current secure channel state.</param>
        /// <returns>The plaintext response and new state, or error if MAC verification fails.</returns>
        public static Result<
            (ResponseAPDU plaintextResponse, SecureChannelState newState),
            SmartCardError
        > RemoveResponseSecurity(ResponseAPDU securedResponse, SecureChannelState state)
        {
            // Check if response security should be removed
            ushort statusWord = securedResponse.StatusWord;
            if (!Scp.StatusWords.ShouldApplyResponseSecurity(statusWord))
                return Result.Success<(ResponseAPDU, SecureChannelState), SmartCardError>(
                    (securedResponse, state)
                );

            return state.Protocol switch
            {
                CryptoService.ScpVersion.Scp02
                    => RemoveScp02ResponseSecurity(securedResponse, state),
                CryptoService.ScpVersion.Scp03
                    => RemoveScp03ResponseSecurity(securedResponse, state),
                _
                    => Result.Failure<(ResponseAPDU, SecureChannelState), SmartCardError>(
                        SmartCardError.InvalidArgument($"Unsupported protocol: {state.Protocol}")
                    ),
            };
        }

        /// <summary>
        /// Executes a secure command by applying security, sending, and processing the response.
        /// Complete secure command pipeline using CryptoService operations.
        /// </summary>
        /// <param name="cardService">The card service for communication.</param>
        /// <param name="command">The command APDU to execute.</param>
        /// <param name="state">The current secure channel state.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The command result with response and new state.</returns>
        public static async Task<
            Result<Types.SecureCommandResult, SmartCardError>
        > ExecuteSecureCommandAsync(
            ISmartCardService cardService,
            CommandAPDU command,
            SecureChannelState state,
            CancellationToken cancellationToken = default
        )
        {
            return await ApplyCommandSecurity(command, state)
                .Bind(async secured =>
                {
                    var (securedCommand, intermediateState) = secured;
                    return await cardService
                        .SendCommandAsync(securedCommand.BinaryCommand, cancellationToken)
                        .Bind(response =>
                            RemoveResponseSecurity(
                                    new ResponseAPDU(response.Data),
                                    intermediateState
                                )
                                .Map(processed =>
                                {
                                    var (processedResponse, finalState) = processed;
                                    return new Types.SecureCommandResult(
                                        processedResponse.ToBytes(),
                                        finalState,
                                        new StatusWord(processedResponse.StatusWord)
                                    );
                                })
                        );
                });
        }

        private static Result<
            (CommandAPDU, SecureChannelState),
            SmartCardError
        > ApplyScp02CommandSecurity(CommandAPDU command, SecureChannelState state)
        {
            if (!state.HasCommandMac)
                return Result.Success<(CommandAPDU, SecureChannelState), SmartCardError>(
                    (command, state)
                );

            // For SCP02, ICV must be encrypted when C-MAC is enabled
            // EXCEPT for EXTERNAL AUTHENTICATE (0x82) which always uses unencrypted ICV
            var icvToUse =
                (command.Ins == 0x82 || !state.HasCommandMac)
                    ? Result.Success<byte[], SmartCardError>(state.MacChainingValue)
                    : CryptoService.Mac.EncryptScp02Icv(
                        state.MacChainingValue,
                        state.SessionKeys.SMac
                    );

            return command
                .GetMacInput()
                .Bind(macInput =>
                    icvToUse.Bind(icv =>
                        CryptoService.Mac.CalculateScp02CommandMac(
                            state.SessionKeys.SMac,
                            macInput.Bytes,
                            icv
                        )
                    )
                )
                .Bind(mac =>
                    command
                        .WithMac(mac)
                        .Bind(secured =>
                            MacChainingState
                                .Create(mac, state.ProtocolVersion, 0x00)
                                .Bind(newChaining => state.UpdateMacChaining(newChaining))
                                .Map(newState => (secured, newState))
                        )
                );
        }

        private static Result<
            (CommandAPDU, SecureChannelState),
            SmartCardError
        > ApplyScp03CommandSecurity(CommandAPDU command, SecureChannelState state)
        {
            if (!state.HasCommandMac)
                return Result.Success<(CommandAPDU, SecureChannelState), SmartCardError>(
                    (command, state)
                );

            return command
                .GetMacInput()
                .Bind(macInput =>
                    CryptoService
                        .ScpOperations.Scp03.CalculateCommandMac(
                            macInput.Bytes,
                            state.SessionKeys.SMac,
                            state.MacChainingValue
                        )
                        .Map(fullMac => (fullMac, macInput))
                )
                .Bind(tuple =>
                {
                    var (fullMac, macInput) = tuple;
                    var truncatedMac = fullMac[..Scp.Scp03.MAC_SIZE];

                    return command
                        .WithMac(truncatedMac)
                        .Bind(secured =>
                            MacChainingState
                                .Create(fullMac, state.ProtocolVersion, 0x00)
                                .Bind(newChaining => state.UpdateMacChaining(newChaining))
                                .Map(newState => newState.IncrementEncryptionCounter())
                                .Map(newState => (secured, newState))
                        );
                });
        }

        private static Result<
            (ResponseAPDU, SecureChannelState),
            SmartCardError
        > ProcessScp02ResponseSecurity(ResponseAPDU response, SecureChannelState state)
        {
            if (!state.HasResponseMac)
                return Result.Success<(ResponseAPDU, SecureChannelState), SmartCardError>(
                    (response, state)
                );

            var responseBytes = response.ToBytes();
            // This method should VERIFY response protection, not generate it.
            // Defer to RemoveScp02ResponseSecurity for verification and optional decryption.
            return RemoveScp02ResponseSecurity(response, state);
        }

        private static Result<
            (ResponseAPDU, SecureChannelState),
            SmartCardError
        > ProcessScp03ResponseSecurity(ResponseAPDU response, SecureChannelState state)
        {
            if (!state.HasResponseMac)
                return Result.Success<(ResponseAPDU, SecureChannelState), SmartCardError>(
                    (response, state)
                );

            var responseBytes = response.ToBytes();
            byte[] processedResponse = responseBytes;

            // Apply R-ENCRYPTION if required
            if (
                state.HasResponseEncryption
                && CryptoService.ScpOperations.Common.HasResponseData(responseBytes)
            )
            {
                var encryptResult = CryptoService.ScpOperations.Scp03.ApplyResponseEncryption(
                    processedResponse,
                    state.SessionKeys.SEnc,
                    state.EncryptionCounter
                );
                if (encryptResult.IsFailure)
                    return encryptResult.Error;
                processedResponse = encryptResult.Value;
            }

            // Apply R-MAC
            return CryptoService
                .ScpOperations.Scp03.CalculateResponseMac(
                    processedResponse,
                    state.SessionKeys.SrMac,
                    state.MacChainingValue
                )
                .Bind(mac =>
                {
                    // Insert R-MAC before status word
                    int statusOffset = processedResponse.Length - 2;
                    byte[] securedResponse = new byte[
                        processedResponse.Length + Scp.Scp03.MAC_SIZE
                    ];
                    Array.Copy(processedResponse, 0, securedResponse, 0, statusOffset);
                    Array.Copy(mac, 0, securedResponse, statusOffset, Scp.Scp03.MAC_SIZE);
                    Array.Copy(
                        processedResponse,
                        statusOffset,
                        securedResponse,
                        securedResponse.Length - 2,
                        2
                    );

                    // SCP03 uses full MAC for chaining and increments counter
                    byte[] fullMac = CreateScp03FullMac(mac);
                    return MacChainingState
                        .Create(fullMac, state.ProtocolVersion, 0x00)
                        .Bind(newChaining => state.UpdateMacChaining(newChaining))
                        .Map(newState => newState.IncrementEncryptionCounter())
                        .Map(newState => (new ResponseAPDU(securedResponse), newState));
                });
        }

        /// <summary>
        /// Removes SCP02 command security (MAC verification and optional decryption).
        /// Uses WSCT to properly handle command structure including Le bytes.
        /// </summary>
        private static Result<
            (CommandAPDU, SecureChannelState),
            SmartCardError
        > RemoveScp02CommandSecurity(CommandAPDU securedCommand, SecureChannelState state)
        {
            // SCP02 C-MAC: Command has 8-byte MAC appended
            if (!state.SecurityLevel.HasCMac())
                return Result.Success<(CommandAPDU, SecureChannelState), SmartCardError>(
                    (securedCommand, state)
                );

            // Extract MAC input and verify using type-safe approach
            return CommandMacData
                .Create(securedCommand, state)
                .Bind(macData =>
                {
                    // Extract MAC from secured command
                    var udc = securedCommand.Udc ?? [];
                    if (udc.Length < Scp.Scp02.MAC_SIZE)
                        return Result.Failure<(CommandAPDU, SecureChannelState), SmartCardError>(
                            SmartCardError.InvalidData("Command too short for MAC")
                        );

                    var receivedMac = new byte[Scp.Scp02.MAC_SIZE];
                    Array.Copy(
                        udc,
                        udc.Length - Scp.Scp02.MAC_SIZE,
                        receivedMac,
                        0,
                        Scp.Scp02.MAC_SIZE
                    );

                    // Calculate expected MAC using type-safe data
                    // ICV: zero for EXTERNAL AUTH, else encrypted ICV per E.3.4
                    var icvResult =
                        securedCommand.Ins
                        == Constants.Constants.Scp.Common.EXTERNAL_AUTHENTICATE_INS
                            ? Result.Success<byte[], SmartCardError>(new byte[8])
                            : CryptoService.Mac.EncryptScp02Icv(
                                state.MacChainingValue,
                                macData.ValidatedKeys.SMac
                            );

                    return icvResult
                        .Bind(icv =>
                            CryptoService.Mac.CalculateScp02CommandMac(
                                macData.ValidatedKeys.SMac,
                                macData.CalculationBytes.ToArray(),
                                icv
                            )
                        )
                        .Bind(expectedMac =>
                        {
                            // Verify MAC matches
                            if (!expectedMac[..Scp.Scp02.MAC_SIZE].SequenceEqual(receivedMac))
                            {
                                return Result.Failure<
                                    (CommandAPDU, SecureChannelState),
                                    SmartCardError
                                >(ErrorFactory.MacVerificationFailed());
                            }

                            // Get plaintext command without MAC
                            return securedCommand
                                .WithoutMac(Scp.Scp02.MAC_SIZE)
                                .Bind(plaintext =>
                                {
                                    // Decrypt if C-DECRYPTION is enabled (card side)
                                    var decryptedCommand = state.SecurityLevel.HasCDecryption()
                                        ? Maybe<byte[]>
                                            .From(plaintext.Udc)
                                            .Where(data => data.Length > 0)
                                            .Match(
                                                Some: data =>
                                                    DecryptCommandData(
                                                        plaintext,
                                                        data,
                                                        state.SessionKeys.SEnc
                                                    ),
                                                None: () =>
                                                    Result.Success<CommandAPDU, SmartCardError>(
                                                        plaintext
                                                    )
                                            )
                                        : Result.Success<CommandAPDU, SmartCardError>(plaintext);

                                    return decryptedCommand.Bind(finalCommand =>
                                    {
                                        // Update MAC chaining with the verified MAC
                                        var updateState = MacChainingState
                                            .Create(expectedMac, state.ProtocolVersion, 0x00)
                                            .Bind(newChaining =>
                                                state.UpdateMacChaining(newChaining)
                                            )
                                            .Bind(newState =>
                                                newState.UpdateLastStrippedCommand(
                                                    macData.CalculationBytes.ToArray()
                                                )
                                            );

                                        return updateState.Map(newState =>
                                            (finalCommand, newState)
                                        );
                                    });
                                });
                        });
                });
        }

        private static Result<CommandAPDU, SmartCardError> DecryptCommandData(
            CommandAPDU command,
            byte[] encryptedData,
            byte[] sEncKey
        )
        {
            return CryptoService
                .ScpOperations.Scp02.RemoveCommandEncryption(command.BinaryCommand, sEncKey)
                .Map(decryptedBytes => new CommandAPDU(decryptedBytes));
        }

        /// <summary>
        /// Removes SCP03 command security (MAC verification and optional decryption).
        /// Per GP spec, C-MAC is calculated over command including Le (if present) but MAC itself is excluded.
        /// </summary>
        private static Result<
            (CommandAPDU, SecureChannelState),
            SmartCardError
        > RemoveScp03CommandSecurity(CommandAPDU securedCommand, SecureChannelState state)
        {
            // SCP03 C-MAC: Command has 8-byte MAC appended
            if (!state.SecurityLevel.HasCMac())
                return Result.Success<(CommandAPDU, SecureChannelState), SmartCardError>(
                    (securedCommand, state)
                );
            var udc = securedCommand.Udc ?? [];
            if (udc.Length < Scp.Scp03.MAC_SIZE)
                return Result.Failure<(CommandAPDU, SecureChannelState), SmartCardError>(
                    SmartCardError.InvalidData("Command too short for SCP03 MAC")
                );

            var mac = udc[^Scp.Scp03.MAC_SIZE..];

            return CommandMacData
                .Create(securedCommand, state)
                .Bind(macData =>
                    CryptoService
                        .ScpOperations.Scp03.CalculateCommandMac(
                            macData.CalculationBytes.ToArray(),
                            state.SessionKeys.SMac,
                            state.MacChainingValue
                        )
                        .Bind(expectedMacFull =>
                        {
#if DEBUG
                            DebugLog(
                                $"SCP03 command MAC chaining={Convert.ToHexString(state.MacChainingValue)} input={Convert.ToHexString(macData.CalculationBytes.ToArray())}"
                            );
#endif
                            if (!expectedMacFull[..Scp.Scp03.MAC_SIZE].SequenceEqual(mac))
                                return Result.Failure<
                                    (CommandAPDU, SecureChannelState),
                                    SmartCardError
                                >(
                                    SmartCardError.SecurityStatusNotSatisfied(
                                        $"SCP03 Command MAC verification failed (expected {Convert.ToHexString(expectedMacFull[..Scp.Scp03.MAC_SIZE])}, received {Convert.ToHexString(mac)})"
                                    )
                                );

                            var withoutMacResult = securedCommand.WithoutMac(Scp.Scp03.MAC_SIZE);

                            return withoutMacResult.Bind(commandWithoutMac =>
                            {
                                uint currentCounter = state.EncryptionCounter;
                                uint nextCounter = state.SecurityLevel.HasCEncryption()
                                    ? currentCounter + 1
                                    : currentCounter;

#if DEBUG
                                DebugLog($"SCP03 command decrypt uses counter {currentCounter}");
#endif
                                var decryptedCommandResult =
                                    state.SecurityLevel.HasCEncryption()
                                    && commandWithoutMac.Ins
                                        != Constants.Constants.Scp.Common.EXTERNAL_AUTHENTICATE_INS
                                        ? CryptoService
                                            .ScpOperations.Scp03.RemoveCommandEncryption(
                                                commandWithoutMac.BinaryCommand,
                                                state.SessionKeys.SEnc,
                                                currentCounter
                                            )
                                            .Map(bytes => new CommandAPDU(bytes))
                                        : Result.Success<CommandAPDU, SmartCardError>(
                                            commandWithoutMac
                                        );

                                return decryptedCommandResult.Bind(finalCommand =>
                                {
                                    var updateState = MacChainingState
                                        .Create(expectedMacFull, state.ProtocolVersion, 0x00)
                                        .Bind(newChaining =>
                                            state.UpdateCounterAndMac(nextCounter, newChaining)
                                        )
                                        .Bind(newState =>
                                            newState.UpdateLastStrippedCommand(
                                                macData.CalculationBytes.ToArray()
                                            )
                                        );

#if DEBUG
                                    updateState = updateState.Tap(newState =>
                                        DebugLog(
                                            $"SCP03 command state updated: mac={Convert.ToHexString(newState.MacChainingValue)} counter={newState.EncryptionCounter}"
                                        )
                                    );
#endif
                                    return updateState.Map(newState => (finalCommand, newState));
                                });
                            });
                        })
                );
        }

        /// <summary>
        /// Removes SCP02 response security (MAC verification and optional decryption).
        /// </summary>
        private static Result<
            (ResponseAPDU, SecureChannelState),
            SmartCardError
        > RemoveScp02ResponseSecurity(ResponseAPDU securedResponse, SecureChannelState state)
        {
            if (!state.HasResponseMac)
                return Result.Success<(ResponseAPDU, SecureChannelState), SmartCardError>(
                    (securedResponse, state)
                );

            var responseBytes = securedResponse.ToBytes();
            if (responseBytes.Length < Scp.Scp02.MAC_SIZE + 2) // MAC + SW
                return Result.Failure<(ResponseAPDU, SecureChannelState), SmartCardError>(
                    SmartCardError.InvalidData("Response too short for SCP02 R-MAC")
                );

            // Extract MAC (8 bytes before status word)
            int macOffset = responseBytes.Length - Scp.Scp02.MAC_SIZE - 2;
            byte[] receivedMac = responseBytes[macOffset..(macOffset + Scp.Scp02.MAC_SIZE)];

            // Separate response data and SW
            byte[] statusWord = responseBytes[^2..];
            byte[] responseDataWithMac = responseBytes[..^2];
            byte[] responseData = responseDataWithMac[..^Scp.Scp02.MAC_SIZE];

            // Decrypt response data first if R-ENC is enabled (E.4.6)
            var plaintextResponseDataResult =
                state.HasResponseEncryption && responseData.Length > 0
                    ? CryptoService.Cipher.Decrypt3DesCbc(
                        state.SessionKeys.SEnc,
                        Constants.Constants.Scp.Common.ZeroIv8,
                        responseData
                    )
                    : Result.Success<byte[], SmartCardError>(responseData);

            if (plaintextResponseDataResult.IsFailure)
                return plaintextResponseDataResult.Error;

            var plaintextResponseData = plaintextResponseDataResult.Value;

            // Build R-MAC input: stripped command || Li || response data (plain) || SW
            var strippedCmd = state.LastStrippedCommand.IsDefaultOrEmpty
                ? Array.Empty<byte>()
                : state.LastStrippedCommand.ToArray();

            byte li = (byte)(plaintextResponseData.Length % 256);
            byte[] rmacInput = new byte[strippedCmd.Length + 1 + plaintextResponseData.Length + 2];
            int pos = 0;
            Array.Copy(strippedCmd, 0, rmacInput, pos, strippedCmd.Length);
            pos += strippedCmd.Length;
            rmacInput[pos++] = li;
            Array.Copy(plaintextResponseData, 0, rmacInput, pos, plaintextResponseData.Length);
            pos += plaintextResponseData.Length;
            Array.Copy(statusWord, 0, rmacInput, pos, 2);

            // Verify MAC
            return CryptoService
                .Mac.CalculateScp02ResponseMac(
                    state.SessionKeys.SrMac,
                    rmacInput,
                    state.MacChainingValue
                )
                .Bind(expectedMac =>
                {
                    if (!expectedMac[..Scp.Scp02.MAC_SIZE].SequenceEqual(receivedMac))
                        return Result.Failure<(ResponseAPDU, SecureChannelState), SmartCardError>(
                            ErrorFactory.MacVerificationFailed()
                        );

                    // Combine plaintext response data with SW for return
                    byte[] plaintextFull = new byte[plaintextResponseData.Length + 2];
                    Array.Copy(
                        plaintextResponseData,
                        0,
                        plaintextFull,
                        0,
                        plaintextResponseData.Length
                    );
                    Array.Copy(statusWord, 0, plaintextFull, plaintextResponseData.Length, 2);

                    var updateResult = MacChainingState
                        .Create(expectedMac, state.ProtocolVersion, 0x00)
                        .Bind(newChaining => UpdateResponseMacChaining(state, newChaining));

                    return updateResult.Map(newState =>
                        (new ResponseAPDU(plaintextFull), newState)
                    );
                });
        }

        /// <summary>
        /// Removes SCP03 response security (MAC verification and optional decryption).
        /// </summary>
        private static Result<
            (ResponseAPDU, SecureChannelState),
            SmartCardError
        > RemoveScp03ResponseSecurity(ResponseAPDU securedResponse, SecureChannelState state)
        {
            if (!state.HasResponseMac)
                return Result.Success<(ResponseAPDU, SecureChannelState), SmartCardError>(
                    (securedResponse, state)
                );

            var responseBytes = securedResponse.ToBytes();
            if (responseBytes.Length < Scp.Scp03.MAC_SIZE + 2) // MAC + SW
                return Result.Failure<(ResponseAPDU, SecureChannelState), SmartCardError>(
                    SmartCardError.InvalidData("Response too short for SCP03 R-MAC")
                );

            // Extract MAC (8 bytes before status word)
            int macOffset = responseBytes.Length - Scp.Scp03.MAC_SIZE - 2;
            byte[] receivedMac = responseBytes[macOffset..(macOffset + Scp.Scp03.MAC_SIZE)];

            // Response without MAC for verification/decryption
            byte[] responseWithoutMac = new byte[responseBytes.Length - Scp.Scp03.MAC_SIZE];
            Array.Copy(responseBytes, 0, responseWithoutMac, 0, macOffset);
            Array.Copy(responseBytes, responseBytes.Length - 2, responseWithoutMac, macOffset, 2);

            var macCalculationResult = CryptoService
                .ScpOperations.Scp03.CalculateResponseMac(
                    responseWithoutMac,
                    state.SessionKeys.SrMac,
                    state.MacChainingValue
                )
#if DEBUG
                .Tap(expected =>
                    DebugLog(
                        $"SCP03 response MAC chaining={Convert.ToHexString(state.MacChainingValue)} expected={Convert.ToHexString(expected[..Scp.Scp03.MAC_SIZE])} actual={Convert.ToHexString(receivedMac)} input={Convert.ToHexString(responseWithoutMac)} srmac={Convert.ToHexString(state.SessionKeys.SrMac)}"
                    )
                )
#endif
            ;

            var plaintextResult =
                state.HasResponseEncryption
                && CryptoService.ScpOperations.Common.HasResponseData(responseWithoutMac)
                    ? CryptoService.ScpOperations.Scp03.RemoveResponseEncryption(
                        responseWithoutMac,
                        state.SessionKeys.SEnc,
                        state.EncryptionCounter
                    )
                    : Result.Success<byte[], SmartCardError>(responseWithoutMac);

            return macCalculationResult.Bind(expectedMacFull =>
            {
                if (!expectedMacFull[..Scp.Scp03.MAC_SIZE].SequenceEqual(receivedMac))
                    return Result.Failure<(ResponseAPDU, SecureChannelState), SmartCardError>(
                        SmartCardError.SecurityStatusNotSatisfied(
                            $"SCP03 Response MAC verification failed (expected {Convert.ToHexString(expectedMacFull[..Scp.Scp03.MAC_SIZE])}, received {Convert.ToHexString(receivedMac)})"
                        )
                    );

                return plaintextResult.Bind(plaintext =>
                    MacChainingState
                        .Create(expectedMacFull, state.ProtocolVersion, 0x00)
                        .Bind(newChaining => UpdateResponseMacChaining(state, newChaining))
                        .Map(newState => (new ResponseAPDU(plaintext), newState))
                );
            });
        }

        /// <summary>
        /// Helper method to create SCP03 full MAC (16 bytes) from truncated MAC (8 bytes).
        /// </summary>
        private static byte[] CreateScp03FullMac(byte[] truncatedMac)
        {
            byte[] fullMac = new byte[Scp.Scp03.FULL_MAC_SIZE];
            Array.Copy(truncatedMac, 0, fullMac, 0, Scp.Scp03.MAC_SIZE);
            return fullMac;
        }

        private static Result<SecureChannelState, SmartCardError> UpdateResponseMacChaining(
            SecureChannelState state,
            MacChainingState newChaining
        )
        {
            return state.MacChaining.ShouldUpdateChainingAfterRMac()
                ? state.UpdateMacChaining(newChaining)
                : Result.Success<SecureChannelState, SmartCardError>(state);
        }
    }

    /// <summary>
    /// Protocol validation operations for secure channel protocols.
    /// Provides common validation logic used across SCP02, SCP03, and other protocols.
    /// Moved from Domain.Protocol.ProtocolValidation to consolidate SCP logic.
    /// </summary>
    [PublicAPI]
    public static class Validation
    {
        /// <summary>
        /// Validates that a host challenge is exactly 8 bytes.
        /// </summary>
        /// <param name="hostChallenge">The host challenge to validate.</param>
        /// <returns>Success if valid, error if invalid.</returns>
        public static UnitResult<SmartCardError> ValidateHostChallenge(byte[] hostChallenge)
        {
            if (hostChallenge is null)
                return UnitResult.Failure(ErrorFactory.NullArgument("Host challenge"));

            return hostChallenge.Length == 8
                ? UnitResult.Success<SmartCardError>()
                : UnitResult.Failure(
                    ErrorFactory.InvalidLength("Host challenge", 8, hostChallenge.Length)
                );
        }

        /// <summary>
        /// Validates that a card challenge meets the minimum length requirement.
        /// </summary>
        /// <param name="cardChallenge">The card challenge to validate.</param>
        /// <param name="expectedLength">The expected minimum length.</param>
        /// <returns>Success if valid, error if invalid.</returns>
        public static UnitResult<SmartCardError> ValidateCardChallenge(
            byte[] cardChallenge,
            int expectedLength
        )
        {
            if (cardChallenge is null)
                return UnitResult.Failure(ErrorFactory.NullArgument("Card challenge"));

            return cardChallenge.Length >= expectedLength
                ? UnitResult.Success<SmartCardError>()
                : UnitResult.Failure(
                    SmartCardError.InvalidResponse(
                        $"Card challenge must be at least {expectedLength} bytes, got {cardChallenge.Length}"
                    )
                );
        }

        /// <summary>
        /// Validates that a sequence counter meets the expected length requirement.
        /// </summary>
        /// <param name="sequenceCounter">The sequence counter to validate.</param>
        /// <param name="expectedLength">The expected minimum length.</param>
        /// <returns>Success if valid, error if invalid.</returns>
        public static UnitResult<SmartCardError> ValidateSequenceCounter(
            byte[] sequenceCounter,
            int expectedLength
        )
        {
            if (sequenceCounter is null)
                return UnitResult.Failure(ErrorFactory.NullArgument("Sequence counter"));

            return sequenceCounter.Length >= expectedLength
                ? UnitResult.Success<SmartCardError>()
                : UnitResult.Failure(
                    SmartCardError.InvalidResponse(
                        $"Sequence counter must be at least {expectedLength} bytes, got {sequenceCounter.Length}"
                    )
                );
        }

        /// <summary>
        /// Validates that a response is for the expected secure channel protocol.
        /// </summary>
        /// <param name="responseScpId">The SCP ID from the response.</param>
        /// <param name="expectedProtocol">The expected protocol version.</param>
        /// <returns>Success if valid, error if invalid.</returns>
        public static UnitResult<SmartCardError> ValidateProtocolVersion(
            Maybe<CryptoService.ScpVersion> responseScpId,
            CryptoService.ScpVersion expectedProtocol
        ) =>
            responseScpId.Match(
                actualProtocol =>
                    actualProtocol == expectedProtocol
                        ? UnitResult.Success<SmartCardError>()
                        : UnitResult.Failure(
                            SmartCardError.InvalidResponse(
                                $"Expected {expectedProtocol:X2} but received {actualProtocol:X2}"
                            )
                        ),
                () =>
                    UnitResult.Failure(
                        SmartCardError.InvalidResponse("Response SCP ID not provided")
                    )
            );

        /// <summary>
        /// Validates that a key set is compatible with the specified protocol.
        /// </summary>
        /// <param name="keySet">The key set to validate.</param>
        /// <param name="expectedType">The expected key set type.</param>
        /// <returns>Success if valid, error if invalid.</returns>
        public static UnitResult<SmartCardError> ValidateKeySetType(
            object keySet,
            Type expectedType
        )
        {
            if (keySet is null)
                return UnitResult.Failure(ErrorFactory.NullArgument("Key set"));

            return keySet.GetType() == expectedType
                ? UnitResult.Success<SmartCardError>()
                : UnitResult.Failure(
                    SmartCardError.InvalidArgument(
                        $"Expected {expectedType.Name} but got {keySet.GetType().Name}"
                    )
                );
        }
    }
}
