// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Protocol;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Services;

public static partial class ScpService
{
    /// <summary>
    /// Command and response security operations  
    /// Consolidates 13+ ApplyCommandSecurity methods into single implementation
    /// Replaces all duplicate implementations from:
    /// - SecureChannelService.WrapCommand/UnwrapResponse
    /// - ScpChannelProcessor.ApplyCommandSecurity/ApplyResponseSecurity  
    /// - Scp02Protocol.ApplyCommandSecurity/ApplyResponseSecurity
    /// - Scp03Protocol.ApplyCommandSecurity/ApplyResponseSecurity
    /// </summary>
    [PublicAPI]
    public static class Security
    {
        /// <summary>
        /// Applies command security (C-MAC, C-ENC) based on secure channel state.
        /// CONSOLIDATES: All duplicate ApplyCommandSecurity/WrapCommand implementations.
        /// </summary>
        /// <param name="command">The APDU command to secure.</param>
        /// <param name="state">The current secure channel state.</param>
        /// <returns>Secured command bytes and updated state, or error.</returns>
        public static Result<(byte[] SecuredCommand, SecureChannelState NewState), SmartCardError> ApplyCommandSecurity(
            IApduCommand command,
            SecureChannelState state
        )
        {
            return ValidateInputs(command, state)
                .Bind(_ => state.ProtocolVersion switch
                {
                    CryptoService.ScpVersion.Scp02 => ApplyScp02CommandSecurity(command, state),
                    CryptoService.ScpVersion.Scp03 => ApplyScp03CommandSecurity(command, state),
                    _ => Result.Failure<(byte[], SecureChannelState), SmartCardError>(
                        SmartCardError.InvalidArgument($"Unsupported protocol: {state.ProtocolVersion}")
                    )
                });
        }

        /// <summary>
        /// Processes response security (R-MAC verification, R-ENC decryption).
        /// CONSOLIDATES: All duplicate ApplyResponseSecurity/ProcessResponse/UnwrapResponse implementations.
        /// </summary>
        /// <param name="response">The response bytes to process.</param>
        /// <param name="state">The current secure channel state.</param>
        /// <returns>Processed response bytes and updated state, or error.</returns>
        public static Result<(byte[] ProcessedResponse, SecureChannelState NewState), SmartCardError> ProcessResponse(
            byte[] response,
            SecureChannelState state
        )
        {
            return ValidateResponseInputs(response, state)
                .Bind(_ => state.ProtocolVersion switch
                {
                    CryptoService.ScpVersion.Scp02 => ProcessScp02Response(response, state),
                    CryptoService.ScpVersion.Scp03 => ProcessScp03Response(response, state),
                    _ => Result.Failure<(byte[], SecureChannelState), SmartCardError>(
                        SmartCardError.InvalidArgument($"Unsupported protocol: {state.ProtocolVersion}")
                    )
                });
        }

        // Private implementation methods - delegate to CryptoService
        private static Result<(byte[], SecureChannelState), SmartCardError> ApplyScp02CommandSecurity(
            IApduCommand command, 
            SecureChannelState state)
        {
            var commandBytes = command.ToByteArray();
            
            // Apply C-MAC if required
            var macOperation = state.HasCommandMac 
                ? CryptoService.Mac.CalculateScp02CommandMac(state.SessionKeys.SMac, commandBytes)
                : Result.Success<byte[], SmartCardError>(Array.Empty<byte>());
                
            return macOperation
                .Bind(mac => state.HasCommandEncryption
                    ? CryptoService.Cipher.Encrypt3DesCbc(command.Data, state.SessionKeys.SEnc, new byte[8])
                        .Bind(encryptedData => BuildScp02SecureCommand(commandBytes, mac, encryptedData)
                            .Map(secureCommand => (secureCommand, state))
                        )
                    : BuildScp02SecureCommand(commandBytes, mac, command.Data)
                        .Map(secureCommand => (secureCommand, state))
                );
        }

        private static Result<(byte[], SecureChannelState), SmartCardError> ApplyScp03CommandSecurity(
            IApduCommand command,
            SecureChannelState state)
        {
            var commandBytes = command.ToByteArray();
            
            // Apply C-MAC if required
            var macOperation = state.HasCommandMac
                ? CryptoService.Mac.CalculateScp03CommandMac(state.SessionKeys.SMac, commandBytes)
                : Result.Success<byte[], SmartCardError>(Array.Empty<byte>());
                
            return macOperation
                .Bind(mac => state.HasCommandEncryption
                    ? CryptoService.Cipher.EncryptAesCbc(
                        command.Data, 
                        state.SessionKeys.SEnc, 
                        GenerateScp03EncryptionIv(state.EncryptionCounter)
                    )
                        .Bind(encryptedData => BuildScp03SecureCommand(commandBytes, mac, encryptedData)
                            .Map(secureCommand => (secureCommand, state.IncrementEncryptionCounter()))
                        )
                    : BuildScp03SecureCommand(commandBytes, mac, command.Data)
                        .Map(secureCommand => (secureCommand, state))
                );
        }

        private static Result<(byte[], SecureChannelState), SmartCardError> ProcessScp02Response(
            byte[] response,
            SecureChannelState state)
        {
            if (response.Length < 2)
            {
                return Result.Failure<(byte[], SecureChannelState), SmartCardError>(
                    SmartCardError.InvalidData("Response too short for SCP02 processing")
                );
            }

            var statusWordBytes = new[] { response[^2], response[^1] };
            var responseData = response[..^2];

            if (state.HasResponseMac && response.Length >= 10)
            {
                var responseMac = responseData[^8..];
                var dataWithoutMac = responseData[..^8];
                
                return CryptoService.Mac.CalculateScp02ResponseMac(
                        state.SessionKeys.SrMac,
                        dataWithoutMac.Concat(statusWordBytes).ToArray()
                    )
                    .Bind(expectedMac => responseMac.SequenceEqual(expectedMac)
                        ? ProcessScp02Decryption(dataWithoutMac, state, statusWordBytes)
                        : Result.Failure<(byte[], SecureChannelState), SmartCardError>(
                            SmartCardError.SecurityError("SCP02 R-MAC verification failed"))
                    );
            }

            return ProcessScp02Decryption(responseData, state, statusWordBytes);
        }

        private static Result<(byte[], SecureChannelState), SmartCardError> ProcessScp03Response(
            byte[] response,
            SecureChannelState state)
        {
            if (response.Length < 2)
            {
                return Result.Failure<(byte[], SecureChannelState), SmartCardError>(
                    SmartCardError.InvalidData("Response too short for SCP03 processing")
                );
            }

            var statusWordBytes = new[] { response[^2], response[^1] };
            var responseData = response[..^2];

            if (state.HasResponseMac && response.Length >= 10)
            {
                var responseMac = responseData[^8..];
                var dataWithoutMac = responseData[..^8];
                
                return CryptoService.Mac.CalculateScp03ResponseMac(
                        state.SessionKeys.SrMac,
                        dataWithoutMac.Concat(statusWordBytes).ToArray()
                    )
                    .Bind(expectedMac => responseMac.SequenceEqual(expectedMac)
                        ? ProcessScp03Decryption(dataWithoutMac, state, statusWordBytes)
                        : Result.Failure<(byte[], SecureChannelState), SmartCardError>(
                            SmartCardError.SecurityError("SCP03 R-MAC verification failed"))
                    );
            }

            return ProcessScp03Decryption(responseData, state, statusWordBytes);
        }

        // Validation methods
        private static Result<bool, SmartCardError> ValidateInputs(IApduCommand command, SecureChannelState state)
        {
            if (command.Data.Length > 255)
            {
                return Result.Failure<bool, SmartCardError>(
                    SmartCardError.InvalidArgument($"Command data too long: {command.Data.Length} bytes")
                );
            }

            return state.Validate()
                .Map(_ => true);
        }

        private static Result<bool, SmartCardError> ValidateResponseInputs(byte[] response, SecureChannelState state)
        {
            if (response.Length < 2)
            {
                return Result.Failure<bool, SmartCardError>(
                    SmartCardError.InvalidData("Response too short - missing status word")
                );
            }

            return state.Validate()
                .Map(_ => true);
        }

        // Helper methods for building secured commands
        private static Result<byte[], SmartCardError> BuildScp02SecureCommand(
            byte[] originalCommand,
            byte[] mac,
            byte[] data)
        {
            if (originalCommand.Length < 4)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidData("Command too short for SCP02 processing")
                );
            }

            var cla = (byte)(originalCommand[0] | 0x04); // Set secure messaging bit
            var ins = originalCommand[1];
            var p1 = originalCommand[2];
            var p2 = originalCommand[3];
            
            var newLc = (byte)(data.Length + mac.Length);
            var result = new byte[4 + 1 + newLc];
            
            result[0] = cla;
            result[1] = ins;
            result[2] = p1;
            result[3] = p2;
            result[4] = newLc;
            
            Array.Copy(data, 0, result, 5, data.Length);
            Array.Copy(mac, 0, result, 5 + data.Length, mac.Length);
            
            return Result.Success<byte[], SmartCardError>(result);
        }

        private static Result<byte[], SmartCardError> BuildScp03SecureCommand(
            byte[] originalCommand,
            byte[] mac,
            byte[] data)
        {
            if (originalCommand.Length < 4)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidData("Command too short for SCP03 processing")
                );
            }

            var cla = (byte)(originalCommand[0] | 0x04); // Set secure messaging bit
            var ins = originalCommand[1];
            var p1 = originalCommand[2];
            var p2 = originalCommand[3];
            
            var newLc = (byte)(data.Length + mac.Length);
            var result = new byte[4 + 1 + newLc];
            
            result[0] = cla;
            result[1] = ins;
            result[2] = p1;
            result[3] = p2;
            result[4] = newLc;
            
            Array.Copy(data, 0, result, 5, data.Length);
            Array.Copy(mac, 0, result, 5 + data.Length, mac.Length);
            
            return Result.Success<byte[], SmartCardError>(result);
        }

        private static byte[] GenerateScp03EncryptionIv(uint counter)
        {
            var iv = new byte[16];
            iv[12] = (byte)(counter >> 24);
            iv[13] = (byte)(counter >> 16);
            iv[14] = (byte)(counter >> 8);
            iv[15] = (byte)(counter & 0xFF);
            return iv;
        }

        private static Result<(byte[], SecureChannelState), SmartCardError> ProcessScp02Decryption(
            byte[] data,
            SecureChannelState state,
            byte[] statusWordBytes)
        {
            if (state.HasResponseEncryption && data.Length > 0)
            {
                return CryptoService.Cipher.Decrypt3DesCbc(data, state.SessionKeys.SEnc, new byte[8])
                    .Map(decryptedData => (decryptedData.Concat(statusWordBytes).ToArray(), state));
            }

            return Result.Success<(byte[], SecureChannelState), SmartCardError>((data.Concat(statusWordBytes).ToArray(), state));
        }

        private static Result<(byte[], SecureChannelState), SmartCardError> ProcessScp03Decryption(
            byte[] data,
            SecureChannelState state,
            byte[] statusWordBytes)
        {
            if (state.HasResponseEncryption && data.Length > 0)
            {
                return CryptoService.Cipher.DecryptAesCbc(
                        data, 
                        state.SessionKeys.SEnc, 
                        GenerateScp03EncryptionIv(state.EncryptionCounter)
                    )
                    .Map(decryptedData => (decryptedData.Concat(statusWordBytes).ToArray(), state));
            }

            return Result.Success<(byte[], SecureChannelState), SmartCardError>((data.Concat(statusWordBytes).ToArray(), state));
        }
    }
}