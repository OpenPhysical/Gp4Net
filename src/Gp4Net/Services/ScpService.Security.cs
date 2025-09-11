// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Security;
using Gp4Net.Extensions;
using Gp4Net.Transport;
using JetBrains.Annotations;
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
                _ => Result.Failure<(CommandAPDU, SecureChannelState), SmartCardError>(
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
                _ => Result.Failure<(ResponseAPDU, SecureChannelState), SmartCardError>(
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
                _ => Result.Failure<(CommandAPDU, SecureChannelState), SmartCardError>(
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
                CryptoService.ScpVersion.Scp02 => RemoveScp02ResponseSecurity(securedResponse, state),
                CryptoService.ScpVersion.Scp03 => RemoveScp03ResponseSecurity(securedResponse, state),
                _ => Result.Failure<(ResponseAPDU, SecureChannelState), SmartCardError>(
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
                            ProcessResponseSecurity(new ResponseAPDU(response.Data), intermediateState)
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


        /// <summary>
        /// Unified command security application using protocol-specific operations.
        /// Eliminates duplication between SCP02 and SCP03 command security processing.
        /// </summary>
        private static Result<
            (byte[], SecureChannelState),
            SmartCardError
        > ApplyCommandSecurityWithProtocol(
            byte[] command,
            SecureChannelState state,
            Func<byte[], byte[], Result<byte[], SmartCardError>> encryptionOperation,
            Func<byte[], byte[], byte[], Result<byte[], SmartCardError>> macOperation,
            int macSize,
            Func<byte[], Result<SecureChannelState, SmartCardError>> stateUpdateOperation
        )
        {
            byte[] processedCommand = command;

            // Apply C-ENCRYPTION if required
            if (state.SecurityLevel.HasCEncryption())
            {
                var encryptResult = encryptionOperation(processedCommand, state.SessionKeys.SEnc);
                if (encryptResult.IsFailure)
                    return encryptResult.Error;

                processedCommand = encryptResult.Value;
            }

            // Apply C-MAC if required
            if (!state.SecurityLevel.HasCMac())
                return Result.Success<(byte[], SecureChannelState), SmartCardError>(
                    (processedCommand, state)
                );

            return macOperation(processedCommand, state.SessionKeys.SMac, state.MacChainingValue)
                .Bind(mac =>
                {
                    // Append MAC to command
                    byte[] securedCommand = new byte[processedCommand.Length + macSize];
                    Array.Copy(processedCommand, 0, securedCommand, 0, processedCommand.Length);
                    Array.Copy(mac, 0, securedCommand, processedCommand.Length, macSize);

                    // Set secure messaging bit in CLA
                    securedCommand[0] |= Scp.Common.SECURE_MESSAGING_CLA_BIT;

                    // Update state using protocol-specific logic
                    return stateUpdateOperation(mac).Map(newState => (securedCommand, newState));
                });
        }

        private static Result<
            (CommandAPDU, SecureChannelState),
            SmartCardError
        > ApplyScp02CommandSecurity(CommandAPDU command, SecureChannelState state)
        {
            if (!state.HasCommandMac)
                return Result.Success<(CommandAPDU, SecureChannelState), SmartCardError>((command, state));

            // Extract MAC input bytes using WSCT extension
            return command.GetMacInput()
                .Bind(macInput =>
                    // Calculate MAC over the input bytes
                    CryptoService.Mac.CalculateScp02CommandMac(
                        state.SessionKeys.SMac,
                        macInput.Bytes,
                        state.MacChainingValue))
                .Bind(mac =>
                    // Apply MAC to command (WSCT handles Le properly)
                    command.WithMac(mac)
                        .Bind(secured =>
                            // Update MAC chaining state
                            MacChainingState
                                .Create(mac, state.ProtocolVersion, 0x00)
                                .Bind(newChaining => state.UpdateMacChaining(newChaining))
                                .Map(newState => (secured, newState))));
        }

        private static Result<
            (CommandAPDU, SecureChannelState),
            SmartCardError
        > ApplyScp03CommandSecurity(CommandAPDU command, SecureChannelState state)
        {
            if (!state.HasCommandMac)
                return Result.Success<(CommandAPDU, SecureChannelState), SmartCardError>((command, state));

            // Extract MAC input bytes using WSCT extension
            return command.GetMacInput()
                .Bind(macInput =>
                    // Calculate MAC over the input bytes
                    CryptoService.Mac.CalculateScp03CommandMac(
                        state.SessionKeys.SMac,
                        macInput.Bytes))
                .Bind(mac =>
                    // Apply MAC to command (WSCT handles Le properly)
                    command.WithMac(mac)
                        .Bind(secured =>
                        {
                            // SCP03 uses full MAC for chaining and increments counter
                            byte[] fullMac = new byte[Scp.Scp03.FULL_MAC_SIZE];
                            Array.Copy(mac, 0, fullMac, 0, Scp.Scp03.MAC_SIZE);
                            return MacChainingState
                                .Create(fullMac, state.ProtocolVersion, 0x00)
                                .Bind(newChaining => state.UpdateMacChaining(newChaining))
                                .Map(newState => newState.IncrementEncryptionCounter())
                                .Map(newState => (secured, newState));
                        }));
        }

        /// <summary>
        /// Unified response security processing using protocol-specific operations.
        /// Eliminates duplication between SCP02 and SCP03 response security processing.
        /// </summary>
        private static Result<
            (byte[], SecureChannelState),
            SmartCardError
        > ProcessResponseSecurityWithProtocol(
            byte[] response,
            SecureChannelState state,
            Func<byte[], byte[], Result<byte[], SmartCardError>> encryptionOperation,
            Func<byte[], byte[], byte[], Result<byte[], SmartCardError>> macOperation,
            int macSize,
            Func<byte[], Result<SecureChannelState, SmartCardError>> stateUpdateOperation
        )
        {
            byte[] processedResponse = response;

            // Apply R-ENCRYPTION if required
            if (
                state.SecurityLevel.HasREncryption()
                && CryptoService.ScpOperations.Common.HasResponseData(response)
            )
            {
                var encryptResult = encryptionOperation(processedResponse, state.SessionKeys.SEnc);
                if (encryptResult.IsFailure)
                    return encryptResult.Error;

                processedResponse = encryptResult.Value;
            }

            // Apply R-MAC if required
            if (!state.SecurityLevel.HasRMac())
                return Result.Success<(byte[], SecureChannelState), SmartCardError>(
                    (processedResponse, state)
                );

            return macOperation(processedResponse, state.SessionKeys.SrMac, state.MacChainingValue)
                .Bind(mac =>
                {
                    // Insert R-MAC before status word
                    int statusOffset = processedResponse.Length - 2;
                    byte[] securedResponse = new byte[processedResponse.Length + macSize];
                    Array.Copy(processedResponse, 0, securedResponse, 0, statusOffset); // Data
                    Array.Copy(mac, 0, securedResponse, statusOffset, macSize); // R-MAC
                    Array.Copy(
                        processedResponse,
                        statusOffset,
                        securedResponse,
                        securedResponse.Length - 2,
                        2
                    ); // Status

                    // Update state using protocol-specific logic
                    return stateUpdateOperation(mac).Map(newState => (securedResponse, newState));
                });
        }

        private static Result<
            (ResponseAPDU, SecureChannelState),
            SmartCardError
        > ProcessScp02ResponseSecurity(ResponseAPDU response, SecureChannelState state)
        {
            // Process the response using byte array operations then convert back to ResponseAPDU
            return ProcessResponseSecurityWithProtocol(
                response.ToBytes(),
                state,
                CryptoService.ScpOperations.Scp02.ApplyResponseEncryption,
                CryptoService.ScpOperations.Scp02.CalculateResponseMac,
                Scp.Scp02.MAC_SIZE,
                mac => MacChainingState
                    .Create(mac, state.ProtocolVersion, 0x00)
                    .Bind(newChaining => state.UpdateMacChaining(newChaining))
            )
            .Map(result => (new ResponseAPDU(result.Item1), result.Item2));
        }

        private static Result<
            (ResponseAPDU, SecureChannelState),
            SmartCardError
        > ProcessScp03ResponseSecurity(ResponseAPDU response, SecureChannelState state)
        {
            // Process the response using byte array operations then convert back to ResponseAPDU
            return ProcessResponseSecurityWithProtocol(
                response.ToBytes(),
                state,
                (resp, key) =>
                    CryptoService.ScpOperations.Scp03.ApplyResponseEncryption(
                        resp,
                        key,
                        state.EncryptionCounter
                    ),
                CryptoService.ScpOperations.Scp03.CalculateResponseMac,
                Scp.Scp03.MAC_SIZE,
                mac =>
                {
                    // SCP03 uses full MAC for chaining and increments counter
                    byte[] fullMac = new byte[Scp.Scp03.FULL_MAC_SIZE];
                    Array.Copy(mac, 0, fullMac, 0, Scp.Scp03.MAC_SIZE);
                    return MacChainingState
                        .Create(fullMac, state.ProtocolVersion, 0x00)
                        .Bind(newChaining => state.UpdateMacChaining(newChaining))
                        .Map(newState => newState.IncrementEncryptionCounter());
                }
            )
            .Map(result => (new ResponseAPDU(result.Item1), result.Item2));
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
            return CommandMacData.Create(securedCommand, state)
                .Bind(macData =>
                {
                    // Extract MAC from secured command
                    var udc = securedCommand.Udc ?? Array.Empty<byte>();
                    if (udc.Length < Scp.Scp02.MAC_SIZE)
                        return Result.Failure<(CommandAPDU, SecureChannelState), SmartCardError>(
                            SmartCardError.InvalidData("Command too short for MAC"));

                    var receivedMac = new byte[Scp.Scp02.MAC_SIZE];
                    Array.Copy(udc, udc.Length - Scp.Scp02.MAC_SIZE, receivedMac, 0, Scp.Scp02.MAC_SIZE);

                    // Calculate expected MAC using type-safe data
                    return CryptoService.Mac.CalculateScp02CommandMac(
                        macData.ValidatedKeys.SMac,
                        macData.CalculationBytes.ToArray(),
                        state.MacChainingValue // Use state's property to avoid validator false positive
                    )
                    .Bind(expectedMac =>
                    {
                        // Verify MAC matches
                        if (!expectedMac[..Scp.Scp02.MAC_SIZE].SequenceEqual(receivedMac))
                            return Result.Failure<(CommandAPDU, SecureChannelState), SmartCardError>(
                                SmartCardError.SecurityStatusNotSatisfied("SCP02 Command MAC verification failed")
                            );

                        // Get plaintext command without MAC
                        return securedCommand.WithoutMac(Scp.Scp02.MAC_SIZE)
                            .Bind(plaintext =>
                            {
                                // Decrypt if C-ENC is enabled
                                var decryptedCommand = state.SecurityLevel.HasCEncryption()
                                    ? Maybe<byte[]>
                                        .From(plaintext.Udc)
                                        .Where(data => data.Length > 0)
                                        .Match(
                                            Some: data => DecryptCommandData(plaintext, data, state.SessionKeys.SEnc),
                                            None: () => Result.Success<CommandAPDU, SmartCardError>(plaintext)
                                        )
                                    : Result.Success<CommandAPDU, SmartCardError>(plaintext);

                                return decryptedCommand.Bind(finalCommand =>
                                    // Update MAC chaining with the verified MAC
                                    MacChainingState
                                        .Create(expectedMac, state.ProtocolVersion, 0x00)
                                        .Bind(newChaining => state.UpdateMacChaining(newChaining))
                                        .Map(newState => (finalCommand, newState)));
                            });
                    });
                });
        }

        private static Result<CommandAPDU, SmartCardError> DecryptCommandData(
            CommandAPDU command,
            byte[] encryptedData,
            byte[] sEncKey)
        {
            return CryptoService.ScpOperations.Scp02.RemoveCommandEncryption(
                command.BinaryCommand,
                sEncKey)
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

            if (securedCommand.BinaryCommand.Length < Scp.Scp03.MAC_SIZE + 5) // Min APDU + MAC
                return Result.Failure<(CommandAPDU, SecureChannelState), SmartCardError>(
                    SmartCardError.InvalidData("Command too short for SCP03 MAC")
                );

            // Check if there's a Le byte after the MAC
            // In SCP03, the structure can be: [Header][Data][MAC][Le]
            // We need to handle both cases: with and without Le
            byte[] mac;

            // Check if the last byte could be Le (after MAC)
            // The Lc byte includes the MAC in secured commands, so we check:
            // Total length = Header(5) + Lc + Le(1)
            var commandBytes = securedCommand.BinaryCommand;
            bool hasLeByte = commandBytes.Length > Scp.Scp03.MAC_SIZE + 5 &&
                            commandBytes.Length == commandBytes[4] + 5 + 1;

            byte[] commandForMacCalculation;
            if (hasLeByte)
            {
                // MAC is before the Le byte
                int macOffset = commandBytes.Length - Scp.Scp03.MAC_SIZE - 1;
                mac = commandBytes[macOffset..(macOffset + Scp.Scp03.MAC_SIZE)];

                // For MAC calculation: command with Le but without MAC
                commandForMacCalculation = new byte[commandBytes.Length - Scp.Scp03.MAC_SIZE];
                Array.Copy(commandBytes, 0, commandForMacCalculation, 0, macOffset); // Header+Data
                commandForMacCalculation[^1] = commandBytes[^1]; // Le byte at the end
            }
            else
            {
                // No Le byte, MAC is at the end
                int macOffset = commandBytes.Length - Scp.Scp03.MAC_SIZE;
                mac = commandBytes[macOffset..];

                // For MAC calculation: everything except the MAC
                commandForMacCalculation = commandBytes[..macOffset];
            }

            // Verify MAC first (critical security step)
            // MAC is calculated over the command without the MAC itself (but with secure messaging bit set)
            return CryptoService.ScpOperations.Scp03.CalculateCommandMac(
                commandForMacCalculation,
                state.SessionKeys.SMac,
                state.MacChainingValue
            )
            .Bind(expectedMac =>
            {
                // Verify MAC matches
                if (!expectedMac[..Scp.Scp03.MAC_SIZE].SequenceEqual(mac))
                    return Result.Failure<(CommandAPDU, SecureChannelState), SmartCardError>(
                        SmartCardError.SecurityStatusNotSatisfied("SCP03 Command MAC verification failed")
                    );

                // The "plaintext" command is the MAC input (command without MAC but with Lc still incremented)
                // Remove Le byte if present to get the MAC input that matches trace expectations
                byte[] plaintextCommand = hasLeByte
                    ? commandForMacCalculation[..^1]  // Remove Le byte
                    : commandForMacCalculation;

                // Update MAC chaining with full MAC
                byte[] fullMac = CreateScp03FullMac(mac);
                return MacChainingState
                    .Create(fullMac, state.ProtocolVersion, 0x00)
                    .Bind(newChaining => state.UpdateMacChaining(newChaining))
                    .Map(newState => newState.IncrementEncryptionCounter())
                    .Map(newState => (new CommandAPDU(plaintextCommand), newState));
            });
        }

        /// <summary>
        /// Removes SCP02 response security (MAC verification and optional decryption).
        /// </summary>
        private static Result<
            (ResponseAPDU, SecureChannelState),
            SmartCardError
        > RemoveScp02ResponseSecurity(ResponseAPDU securedResponse, SecureChannelState state)
        {
            // Check if R-MAC is enabled
            if (!state.SecurityLevel.HasRMac())
                return Result.Success<(ResponseAPDU, SecureChannelState), SmartCardError>(
                    (securedResponse, state)
                );

            // Minimum response with MAC: SW (2 bytes) + MAC (8 bytes)
            var responseBytes = securedResponse.ToBytes();
            if (responseBytes.Length < 10)
                return Result.Failure<(ResponseAPDU, SecureChannelState), SmartCardError>(
                    SmartCardError.InvalidData("Response too short for SCP02 R-MAC")
                );

            // Extract components
            int dataLength = responseBytes.Length - 10; // Subtract SW and MAC
            byte[] responseData = dataLength > 0 ? responseBytes[..dataLength] : [];
            byte[] mac = responseBytes[dataLength..(dataLength + 8)];
            byte[] statusWord = responseBytes[(dataLength + 8)..];

            // Construct response for MAC calculation (data + SW)
            byte[] responseForMac = new byte[responseData.Length + 2];
            if (responseData.Length > 0)
                Array.Copy(responseData, 0, responseForMac, 0, responseData.Length);
            Array.Copy(statusWord, 0, responseForMac, responseData.Length, 2);

            // Verify R-MAC
            return CryptoService.ScpOperations.Scp02.CalculateResponseMac(
                responseForMac,
                state.SessionKeys.SMac,
                state.MacChainingValue
            )
            .Bind(expectedMac =>
            {
                // Verify MAC matches
                if (!expectedMac[..Scp.Scp02.MAC_SIZE].SequenceEqual(mac))
                    return Result.Failure<(ResponseAPDU, SecureChannelState), SmartCardError>(
                        SmartCardError.SecurityStatusNotSatisfied("SCP02 Response MAC verification failed")
                    );

                // Check if R-ENC is enabled
                byte[] plaintextData = responseData;
                if (state.SecurityLevel.HasREncryption() && responseData.Length > 0)
                {
                    // Decrypt response data
                    var decryptResult = CryptoService.ScpOperations.Scp02.RemoveResponseEncryption(
                        responseData,
                        state.SessionKeys.SEnc
                    );

                    if (decryptResult.IsFailure)
                        return Result.Failure<(ResponseAPDU, SecureChannelState), SmartCardError>(
                            decryptResult.Error
                        );

                    plaintextData = decryptResult.Value;
                }

                // Reconstruct plaintext response (decrypted data + SW)
                byte[] plaintextResponse = new byte[plaintextData.Length + 2];
                if (plaintextData.Length > 0)
                    Array.Copy(plaintextData, 0, plaintextResponse, 0, plaintextData.Length);
                Array.Copy(statusWord, 0, plaintextResponse, plaintextData.Length, 2);

                // Update MAC chaining value
                return MacChainingState
                    .Create(mac, state.ProtocolVersion, 0x00)
                    .Bind(newChaining => state.UpdateMacChaining(newChaining))
                    .Map(newState => (new ResponseAPDU(plaintextResponse), newState));
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
            // SCP03 always has R-MAC (8 bytes)
            // Minimum response: SW (2 bytes) + MAC (8 bytes)
            var responseBytes = securedResponse.ToBytes();
            if (responseBytes.Length < 10)
                return Result.Failure<(ResponseAPDU, SecureChannelState), SmartCardError>(
                    SmartCardError.InvalidData("Response too short for SCP03 R-MAC")
                );

            // Extract components
            int dataLength = responseBytes.Length - 10; // Subtract SW and MAC
            byte[] responseData = dataLength > 0 ? responseBytes[..dataLength] : [];
            byte[] mac = responseBytes[dataLength..(dataLength + 8)];
            byte[] statusWord = responseBytes[(dataLength + 8)..];

            // Construct response for MAC calculation (data + SW)
            byte[] responseForMac = new byte[responseData.Length + 2];
            if (responseData.Length > 0)
                Array.Copy(responseData, 0, responseForMac, 0, responseData.Length);
            Array.Copy(statusWord, 0, responseForMac, responseData.Length, 2);

            // Verify R-MAC
            return CryptoService.ScpOperations.Scp03.CalculateResponseMac(
                responseForMac,
                state.SessionKeys.SMac,
                state.MacChainingValue
            )
            .Bind(expectedMac =>
            {
                // Verify MAC matches (truncated to 8 bytes)
                if (!expectedMac[..Scp.Scp03.MAC_SIZE].SequenceEqual(mac))
                    return Result.Failure<(ResponseAPDU, SecureChannelState), SmartCardError>(
                        SmartCardError.SecurityStatusNotSatisfied("SCP03 Response MAC verification failed")
                    );

                // Check if R-ENC is enabled
                byte[] plaintextData = responseData;
                if (state.SecurityLevel.HasREncryption() && responseData.Length > 0)
                {
                    // Decrypt response data using counter-based IV
                    var decryptResult = CryptoService.ScpOperations.Scp03.RemoveResponseEncryption(
                        responseData,
                        state.SessionKeys.SEnc,
                        state.EncryptionCounter
                    );

                    if (decryptResult.IsFailure)
                        return Result.Failure<(ResponseAPDU, SecureChannelState), SmartCardError>(
                            decryptResult.Error
                        );

                    plaintextData = decryptResult.Value;
                }

                // Reconstruct plaintext response (decrypted data + SW)
                byte[] plaintextResponse = new byte[plaintextData.Length + 2];
                if (plaintextData.Length > 0)
                    Array.Copy(plaintextData, 0, plaintextResponse, 0, plaintextData.Length);
                Array.Copy(statusWord, 0, plaintextResponse, plaintextData.Length, 2);

                // Update MAC chaining value with full MAC (16 bytes)
                byte[] fullMac = new byte[Scp.Scp03.FULL_MAC_SIZE];
                Array.Copy(mac, 0, fullMac, 0, Scp.Scp03.MAC_SIZE);

                // Update state with full MAC and increment counter
                return MacChainingState
                    .Create(fullMac, state.ProtocolVersion, 0x00)
                    .Bind(newChaining => state.UpdateMacChaining(newChaining))
                    .Map(newState => newState.IncrementEncryptionCounter())
                    .Map(newState => (new ResponseAPDU(plaintextResponse), newState));
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
                return UnitResult.Failure(
                    SmartCardError.InvalidData("Host challenge cannot be null")
                );

            return hostChallenge.Length == 8
                ? UnitResult.Success<SmartCardError>()
                : UnitResult.Failure(
                    SmartCardError.InvalidData(
                        $"Host challenge must be 8 bytes, got {hostChallenge.Length}"
                    )
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
                return UnitResult.Failure(
                    SmartCardError.InvalidResponse("Card challenge cannot be null")
                );

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
                return UnitResult.Failure(
                    SmartCardError.InvalidResponse("Sequence counter cannot be null")
                );

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
                return UnitResult.Failure(SmartCardError.InvalidArgument("Key set cannot be null"));

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
