// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;
using static Gp4Net.Constants.Constants;

namespace Gp4Net.Cryptography;

/// <summary>
/// SCP-specific cryptographic operations consolidated from all SCP protocol classes.
/// All methods are pure functional and delegate to existing CryptoService operations.
/// Per GlobalPlatform Card Specification v2.3.1 Appendix E "Secure Channel Protocol".
/// </summary>
public static partial class CryptoService
{
    /// <summary>
    /// SCP02 and SCP03 cryptographic operations.
    /// Consolidates all crypto logic from Scp02Protocol and Scp03Protocol classes.
    /// </summary>
    [PublicAPI]
    public static class ScpOperations
    {
        /// <summary>
        /// SCP02 specific cryptographic operations.
        /// Per GP Card Spec v2.3.1 Section E.4 "SCP02".
        /// </summary>
        [PublicAPI]
        public static class Scp02
        {
            /// <summary>
            /// Derives a SCP02 session key using 3DES-CBC encryption.
            /// Per GP Card Spec v2.3.1 Section E.4.1 and Figure E-2.
            /// </summary>
            /// <param name="baseKey">The static base key (16 bytes).</param>
            /// <param name="derivationConstant">The derivation constant (2 bytes).</param>
            /// <param name="sequenceCounter">The sequence counter (2 bytes).</param>
            /// <returns>The derived session key (16 bytes).</returns>
            public static Result<byte[], SmartCardError> DeriveScp02SessionKey(
                byte[] baseKey,
                byte[] derivationConstant,
                byte[] sequenceCounter
            )
            {
                if (baseKey.Length != Scp.Scp02.SESSION_KEY_SIZE)
                    return Result.Failure<byte[], SmartCardError>(
                        new InvalidLengthError("baseKey", Scp.Scp02.SESSION_KEY_SIZE, baseKey.Length)
                    );

                if (derivationConstant.Length != 2)
                    return Result.Failure<byte[], SmartCardError>(
                        new InvalidLengthError("derivationConstant", 2, derivationConstant.Length)
                    );

                if (sequenceCounter.Length != Scp.Scp02.SEQUENCE_COUNTER_SIZE)
                    return Result.Failure<byte[], SmartCardError>(
                        new InvalidLengthError(
                            "sequenceCounter",
                            Scp.Scp02.SEQUENCE_COUNTER_SIZE,
                            sequenceCounter.Length
                        )
                    );

                // Build derivation data per Figure E-2:
                // Constant (2) || Sequence Counter (2) || Padding (12 zeros)
                byte[] derivationData = new byte[Scp.Scp02.KEY_DERIVATION_DATA_SIZE];
                Array.Copy(derivationConstant, 0, derivationData, 0, 2);
                Array.Copy(sequenceCounter, 0, derivationData, 2, 2);
                // Remaining 12 bytes are already zeros

                // Encrypt using 3DES-CBC with zero IV
                return Cipher.Encrypt3DesCbc(baseKey, Scp.Common.ZeroIv8, derivationData);
            }

            /// <summary>
            /// Calculates SCP02 cryptogram using Full 3DES MAC.
            /// Per GP Card Spec v2.3.1 Section B.1.2.1 "Full Triple DES".
            /// Used only for card/host cryptogram calculation with S-ENC key.
            /// </summary>
            /// <param name="key">The S-ENC session key (16 bytes).</param>
            /// <param name="data">The cryptogram data (24 bytes, already includes padding).</param>
            /// <returns>The cryptogram value (8 bytes).</returns>
            public static Result<byte[], SmartCardError> CalculateCryptogram(
                byte[] key,
                byte[] data
            )
            {
                if (key.Length != Scp.Scp02.SESSION_KEY_SIZE)
                    return Result.Failure<byte[], SmartCardError>(
                        new InvalidLengthError("key", Scp.Scp02.SESSION_KEY_SIZE, key.Length)
                    );

                if (data.Length != Scp.Scp02.CRYPTOGRAM_DATA_SIZE)
                    return Result.Failure<byte[], SmartCardError>(
                        new InvalidLengthError("data", Scp.Scp02.CRYPTOGRAM_DATA_SIZE, data.Length)
                    );

                // Use existing cryptogram calculation from CryptoService
                return Cryptogram.CalculateScp02Cryptogram(key, data);
            }

            /// <summary>
            /// Calculates Retail MAC (Single DES + Final Triple DES) for SCP02.
            /// Per GP Card Spec v2.3.1 Section B.1.2.2 "Single DES Plus Final Triple DES".
            /// Used for C-MAC and R-MAC calculation.
            /// </summary>
            /// <param name="key">The MAC key (16 bytes).</param>
            /// <param name="data">The data to MAC (will be padded internally).</param>
            /// <returns>The MAC value (8 bytes).</returns>
            public static Result<byte[], SmartCardError> CalculateMac(byte[] key, byte[] data)
            {
                // Legacy overload for backward compatibility - uses zero ICV
                return CalculateMac(key, data, new byte[8]);
            }
            
            public static Result<byte[], SmartCardError> CalculateMac(byte[] key, byte[] data, byte[] icv)
            {
                if (key.Length != Scp.Scp02.SESSION_KEY_SIZE)
                    return Result.Failure<byte[], SmartCardError>(
                        new InvalidLengthError("key", Scp.Scp02.SESSION_KEY_SIZE, key.Length)
                    );

                if (data.Length == 0)
                    return Result.Failure<byte[], SmartCardError>(
                        SmartCardError.InvalidArgument("Data cannot be empty")
                    );

                if (icv.Length != Scp.Scp02.CHAINING_VALUE_SIZE)
                    return Result.Failure<byte[], SmartCardError>(
                        new InvalidLengthError("icv", Scp.Scp02.CHAINING_VALUE_SIZE, icv.Length)
                    );

                // Use existing MAC calculation from CryptoService with ICV
                return Mac.CalculateScp02CommandMac(key, data, icv);
            }

            /// <summary>
            /// Calculates command MAC for SCP02.
            /// Per GP Card Specification v2.3.1 Section E.4.3.
            /// </summary>
            /// <param name="command">The command APDU.</param>
            /// <param name="macKey">The MAC key.</param>
            /// <param name="chainingValue">The MAC chaining value.</param>
            /// <returns>The calculated MAC.</returns>
            public static Result<byte[], SmartCardError> CalculateCommandMac(
                byte[] command,
                byte[] macKey,
                byte[] chainingValue
            )
            {
                if (chainingValue.Length != Scp.Scp02.CHAINING_VALUE_SIZE)
                    return Result.Failure<byte[], SmartCardError>(
                        new InvalidLengthError(
                            "chainingValue",
                            Scp.Scp02.CHAINING_VALUE_SIZE,
                            chainingValue.Length
                        )
                    );

                // SCP02 C-MAC: Pass command data and ICV separately to MAC function
                // The MAC function will use ICV as initialization vector, not concatenate it
                return CalculateMac(macKey, command, chainingValue);
            }

            /// <summary>
            /// Calculates response MAC for SCP02.
            /// Per GP Card Specification v2.3.1 Section E.4.3.
            /// </summary>
            /// <param name="response">The response APDU.</param>
            /// <param name="rMacKey">The R-MAC key.</param>
            /// <param name="chainingValue">The MAC chaining value.</param>
            /// <returns>The calculated R-MAC.</returns>
            public static Result<byte[], SmartCardError> CalculateResponseMac(
                byte[] response,
                byte[] rMacKey,
                byte[] chainingValue
            )
            {
                if (chainingValue.Length != Scp.Scp02.CHAINING_VALUE_SIZE)
                    return Result.Failure<byte[], SmartCardError>(
                        new InvalidLengthError(
                            "chainingValue",
                            Scp.Scp02.CHAINING_VALUE_SIZE,
                            chainingValue.Length
                        )
                    );

                // SCP02 R-MAC: Pass response data and ICV separately to MAC function
                // The MAC function will use ICV as initialization vector, not concatenate it
                return Mac.CalculateScp02ResponseMac(rMacKey, response, chainingValue);
            }

            /// <summary>
            /// Applies command encryption for SCP02.
            /// Per GP Card Specification v2.3.1 Section E.4.3.
            /// </summary>
            /// <param name="command">The command APDU to encrypt.</param>
            /// <param name="sEncKey">The S-ENC session key.</param>
            /// <returns>The command with encrypted data portion.</returns>
            public static Result<byte[], SmartCardError> ApplyCommandEncryption(
                byte[] command,
                byte[] sEncKey
            )
            {
                if (command.Length <= 5) // No data to encrypt
                    return Result.Success<byte[], SmartCardError>(command);

                byte lc = command[4];
                if (lc == 0 || command.Length < 5 + lc)
                    return Result.Success<byte[], SmartCardError>(command);

                // Extract data to encrypt
                byte[] dataToEncrypt = new byte[lc];
                Array.Copy(command, 5, dataToEncrypt, 0, lc);

                // For SCP02 C-ENC, use zero IV with automatic padding
                return Cipher
                    .Encrypt3DesCbcWithPadding(sEncKey, Scp.Common.ZeroIv8, dataToEncrypt)
                    .Map(encryptedData =>
                    {
                        // Build new command with encrypted data
                        byte[] newCommand = new byte[
                            5 + encryptedData.Length + (command.Length > 5 + lc ? 1 : 0)
                        ];
                        Array.Copy(command, 0, newCommand, 0, 4); // CLA INS P1 P2
                        newCommand[0] |= Scp.Common.SECURE_MESSAGING_CLA_BIT; // Set secure messaging bit
                        newCommand[4] = (byte)(encryptedData.Length + Scp.Scp02.MAC_SIZE); // New Lc includes MAC
                        Array.Copy(encryptedData, 0, newCommand, 5, encryptedData.Length);

                        // Copy Le if present
                        if (command.Length > 5 + lc)
                            newCommand[^1] = command[^1];

                        return newCommand;
                    });
            }

            /// <summary>
            /// Applies response encryption for SCP02.
            /// Per GP Card Specification v2.3.1 Section E.4.3.
            /// </summary>
            /// <param name="response">The response APDU to encrypt.</param>
            /// <param name="sEncKey">The S-ENC session key.</param>
            /// <returns>The response with encrypted data portion.</returns>
            public static Result<byte[], SmartCardError> ApplyResponseEncryption(
                byte[] response,
                byte[] sEncKey
            )
            {
                int statusOffset = response.Length - 2;
                if (statusOffset <= 0) // No data to encrypt
                    return Result.Success<byte[], SmartCardError>(response);

                byte[] responseData = new byte[statusOffset];
                Array.Copy(response, 0, responseData, 0, statusOffset);

                // For SCP02 R-ENC, use zero IV with automatic padding
                return Cipher
                    .Encrypt3DesCbcWithPadding(sEncKey, Scp.Common.ZeroIv8, responseData)
                    .Map(encryptedData =>
                    {
                        // Combine encrypted data with original status word
                        byte[] result = new byte[encryptedData.Length + 2];
                        Array.Copy(encryptedData, 0, result, 0, encryptedData.Length);
                        Array.Copy(response, statusOffset, result, encryptedData.Length, 2);
                        return result;
                    });
            }

            /// <summary>
            /// Removes SCP02 command encryption (decrypts the data portion).
            /// Inverse operation of ApplyCommandEncryption.
            /// </summary>
            /// <param name="command">The encrypted command APDU.</param>
            /// <param name="sEncKey">The S-ENC session key.</param>
            /// <returns>The command with decrypted data portion.</returns>
            public static Result<byte[], SmartCardError> RemoveCommandEncryption(
                byte[] command,
                byte[] sEncKey
            )
            {
                if (command.Length <= 5) // No data to decrypt
                    return Result.Success<byte[], SmartCardError>(command);

                byte lc = command[4];
                if (lc == 0 || command.Length < 5 + lc)
                    return Result.Success<byte[], SmartCardError>(command);

                // Extract data portion
                byte[] encryptedData = new byte[lc];
                Array.Copy(command, 5, encryptedData, 0, lc);

                // Decrypt using zero IV with automatic padding removal
                return Cipher
                    .Decrypt3DesCbcWithPadding(sEncKey, Scp.Common.ZeroIv8, encryptedData)
                    .Map(decryptedData =>
                    {
                        // Reconstruct command with decrypted data
                        byte[] result = new byte[5 + decryptedData.Length];
                        Array.Copy(command, 0, result, 0, 4); // CLA, INS, P1, P2
                        result[4] = (byte)decryptedData.Length; // Update Lc
                        Array.Copy(decryptedData, 0, result, 5, decryptedData.Length);
                        return result;
                    });
            }

            /// <summary>
            /// Removes SCP02 response encryption (decrypts the data portion).
            /// Inverse operation of ApplyResponseEncryption.
            /// </summary>
            /// <param name="response">The encrypted response APDU.</param>
            /// <param name="sEncKey">The S-ENC session key.</param>
            /// <returns>The response with decrypted data portion.</returns>
            public static Result<byte[], SmartCardError> RemoveResponseEncryption(
                byte[] response,
                byte[] sEncKey
            )
            {
                int statusOffset = response.Length - 2;
                if (statusOffset <= 0) // No data to decrypt
                    return Result.Success<byte[], SmartCardError>(response);

                byte[] encryptedData = new byte[statusOffset];
                Array.Copy(response, 0, encryptedData, 0, statusOffset);

                // Decrypt using zero IV with automatic padding removal
                return Cipher
                    .Decrypt3DesCbcWithPadding(sEncKey, Scp.Common.ZeroIv8, encryptedData)
                    .Map(decryptedData =>
                    {
                        // Combine decrypted data with original status word
                        byte[] result = new byte[decryptedData.Length + 2];
                        Array.Copy(decryptedData, 0, result, 0, decryptedData.Length);
                        Array.Copy(response, statusOffset, result, decryptedData.Length, 2);
                        return result;
                    });
            }
        }

        /// <summary>
        /// SCP03 specific cryptographic operations.
        /// Per GP Card Spec v2.3.1 Section E.5 "SCP03".
        /// </summary>
        [PublicAPI]
        public static class Scp03
        {
            /// <summary>
            /// Calculates SCP03 command MAC using AES-CMAC.
            /// Per GP Card Specification v2.3.1 Section E.5.3.
            /// </summary>
            /// <param name="command">The command APDU.</param>
            /// <param name="macKey">The MAC key.</param>
            /// <param name="chainingValue">The MAC chaining value.</param>
            /// <returns>The calculated MAC (truncated to 8 bytes).</returns>
            public static Result<byte[], SmartCardError> CalculateCommandMac(
                byte[] command,
                byte[] macKey,
                byte[] chainingValue
            )
            {
                if (chainingValue.Length != Scp.Scp03.CHAINING_VALUE_SIZE)
                    return Result.Failure<byte[], SmartCardError>(
                        new InvalidLengthError(
                            "chainingValue",
                            Scp.Scp03.CHAINING_VALUE_SIZE,
                            chainingValue.Length
                        )
                    );

                // SCP03 C-MAC: AES-CMAC over (chaining_value || command)
                byte[] macInput = new byte[chainingValue.Length + command.Length];
                Array.Copy(chainingValue, 0, macInput, 0, chainingValue.Length);
                Array.Copy(command, 0, macInput, chainingValue.Length, command.Length);

                return Mac.CalculateScp03CommandMac(macKey, macInput)
                    .Map(fullMac => fullMac.Take(Scp.Scp03.MAC_SIZE).ToArray()); // Truncate to 8 bytes
            }

            /// <summary>
            /// Calculates SCP03 response MAC using AES-CMAC.
            /// Per GP Card Specification v2.3.1 Section E.5.3.
            /// </summary>
            /// <param name="response">The response APDU.</param>
            /// <param name="rMacKey">The R-MAC key.</param>
            /// <param name="chainingValue">The MAC chaining value.</param>
            /// <returns>The calculated R-MAC (truncated to 8 bytes).</returns>
            public static Result<byte[], SmartCardError> CalculateResponseMac(
                byte[] response,
                byte[] rMacKey,
                byte[] chainingValue
            )
            {
                if (chainingValue.Length != Scp.Scp03.CHAINING_VALUE_SIZE)
                    return Result.Failure<byte[], SmartCardError>(
                        new InvalidLengthError(
                            "chainingValue",
                            Scp.Scp03.CHAINING_VALUE_SIZE,
                            chainingValue.Length
                        )
                    );

                // SCP03 R-MAC: AES-CMAC over (chaining_value || response)
                byte[] macInput = new byte[chainingValue.Length + response.Length];
                Array.Copy(chainingValue, 0, macInput, 0, chainingValue.Length);
                Array.Copy(response, 0, macInput, chainingValue.Length, response.Length);

                return Mac.CalculateScp03ResponseMac(rMacKey, macInput)
                    .Map(fullMac => fullMac.Take(Scp.Scp03.MAC_SIZE).ToArray()); // Truncate to 8 bytes
            }

            /// <summary>
            /// Applies command encryption for SCP03.
            /// Per GP Card Specification v2.3.1 Section E.5.3.
            /// </summary>
            /// <param name="command">The command APDU to encrypt.</param>
            /// <param name="sEncKey">The S-ENC session key.</param>
            /// <param name="encryptionCounter">The encryption counter for IV.</param>
            /// <returns>The command with encrypted data portion.</returns>
            public static Result<byte[], SmartCardError> ApplyCommandEncryption(
                byte[] command,
                byte[] sEncKey,
                uint encryptionCounter
            )
            {
                if (command.Length <= 5) // No data to encrypt
                    return Result.Success<byte[], SmartCardError>(command);

                byte lc = command[4];
                if (lc == 0 || command.Length < 5 + lc)
                    return Result.Success<byte[], SmartCardError>(command);

                // Extract data to encrypt
                byte[] dataToEncrypt = new byte[lc];
                Array.Copy(command, 5, dataToEncrypt, 0, lc);

                // For SCP03 C-ENC, use counter-based IV
                byte[] iv = BuildScp03Iv(encryptionCounter);

                return Cipher
                    .EncryptAesCbcWithPadding(sEncKey, iv, dataToEncrypt)
                    .Map(encryptedData =>
                    {
                        // Build new command with encrypted data
                        byte[] newCommand = new byte[
                            5 + encryptedData.Length + (command.Length > 5 + lc ? 1 : 0)
                        ];
                        Array.Copy(command, 0, newCommand, 0, 4); // CLA INS P1 P2
                        newCommand[0] |= Scp.Common.SECURE_MESSAGING_CLA_BIT; // Set secure messaging bit
                        newCommand[4] = (byte)(encryptedData.Length + Scp.Scp03.MAC_SIZE); // New Lc includes MAC
                        Array.Copy(encryptedData, 0, newCommand, 5, encryptedData.Length);

                        // Copy Le if present
                        if (command.Length > 5 + lc)
                            newCommand[^1] = command[^1];

                        return newCommand;
                    });
            }

            /// <summary>
            /// Applies response encryption for SCP03.
            /// Per GP Card Specification v2.3.1 Section E.5.3.
            /// </summary>
            /// <param name="response">The response APDU to encrypt.</param>
            /// <param name="sEncKey">The S-ENC session key.</param>
            /// <param name="encryptionCounter">The encryption counter for IV.</param>
            /// <returns>The response with encrypted data portion.</returns>
            public static Result<byte[], SmartCardError> ApplyResponseEncryption(
                byte[] response,
                byte[] sEncKey,
                uint encryptionCounter
            )
            {
                int statusOffset = response.Length - 2;
                if (statusOffset <= 0) // No data to encrypt
                    return Result.Success<byte[], SmartCardError>(response);

                byte[] responseData = new byte[statusOffset];
                Array.Copy(response, 0, responseData, 0, statusOffset);

                // For SCP03 R-ENC, use counter-based IV
                byte[] iv = BuildScp03Iv(encryptionCounter);

                return Cipher
                    .EncryptAesCbcWithPadding(sEncKey, iv, responseData)
                    .Map(encryptedData =>
                    {
                        // Combine encrypted data with original status word
                        byte[] result = new byte[encryptedData.Length + 2];
                        Array.Copy(encryptedData, 0, result, 0, encryptedData.Length);
                        Array.Copy(response, statusOffset, result, encryptedData.Length, 2);
                        return result;
                    });
            }

            /// <summary>
            /// Removes SCP03 command encryption (decrypts the data portion).
            /// Inverse operation of ApplyCommandEncryption.
            /// </summary>
            /// <param name="command">The encrypted command APDU.</param>
            /// <param name="sEncKey">The S-ENC session key.</param>
            /// <param name="encryptionCounter">The encryption counter for IV.</param>
            /// <returns>The command with decrypted data portion.</returns>
            public static Result<byte[], SmartCardError> RemoveCommandEncryption(
                byte[] command,
                byte[] sEncKey,
                uint encryptionCounter
            )
            {
                if (command.Length <= 5) // No data to decrypt
                    return Result.Success<byte[], SmartCardError>(command);

                byte lc = command[4];
                if (lc == 0 || command.Length < 5 + lc)
                    return Result.Success<byte[], SmartCardError>(command);

                // Extract encrypted data
                byte[] encryptedData = new byte[lc];
                Array.Copy(command, 5, encryptedData, 0, lc);

                // Use counter-based IV for decryption
                byte[] iv = BuildScp03Iv(encryptionCounter);

                return Cipher
                    .DecryptAesCbcWithPadding(sEncKey, iv, encryptedData)
                    .Map(decryptedData =>
                    {
                        // Build new command with decrypted data
                        byte[] result = new byte[5 + decryptedData.Length];
                        Array.Copy(command, 0, result, 0, 4); // CLA, INS, P1, P2
                        result[4] = (byte)decryptedData.Length; // Update Lc
                        Array.Copy(decryptedData, 0, result, 5, decryptedData.Length);
                        return result;
                    });
            }

            /// <summary>
            /// Removes SCP03 response encryption (decrypts the data portion).
            /// Inverse operation of ApplyResponseEncryption.
            /// </summary>
            /// <param name="response">The encrypted response APDU.</param>
            /// <param name="sEncKey">The S-ENC session key.</param>
            /// <param name="encryptionCounter">The encryption counter for IV.</param>
            /// <returns>The response with decrypted data portion.</returns>
            public static Result<byte[], SmartCardError> RemoveResponseEncryption(
                byte[] response,
                byte[] sEncKey,
                uint encryptionCounter
            )
            {
                int statusOffset = response.Length - 2;
                if (statusOffset <= 0) // No data to decrypt
                    return Result.Success<byte[], SmartCardError>(response);

                byte[] encryptedData = new byte[statusOffset];
                Array.Copy(response, 0, encryptedData, 0, statusOffset);

                // Use counter-based IV for decryption
                byte[] iv = BuildScp03Iv(encryptionCounter);

                return Cipher
                    .DecryptAesCbcWithPadding(sEncKey, iv, encryptedData)
                    .Map(decryptedData =>
                    {
                        // Combine decrypted data with original status word
                        byte[] result = new byte[decryptedData.Length + 2];
                        Array.Copy(decryptedData, 0, result, 0, decryptedData.Length);
                        Array.Copy(response, statusOffset, result, decryptedData.Length, 2);
                        return result;
                    });
            }

            /// <summary>
            /// Builds SCP03 IV from encryption counter.
            /// Per GP Card Specification v2.3.1 Section E.5.3.
            /// </summary>
            /// <param name="counter">The encryption counter.</param>
            /// <returns>The 16-byte IV for AES operations.</returns>
            private static byte[] BuildScp03Iv(uint counter)
            {
                byte[] iv = new byte[Scp.Scp03.BLOCK_SIZE];
                // Counter in big-endian format in the last 4 bytes
                iv[12] = (byte)(counter >> 24);
                iv[13] = (byte)(counter >> 16);
                iv[14] = (byte)(counter >> 8);
                iv[15] = (byte)counter;
                return iv;
            }
        }

        /// <summary>
        /// Common utility operations used by both SCP02 and SCP03.
        /// </summary>
        [PublicAPI]
        public static class Common
        {
            /// <summary>
            /// Checks if a response has data (more than just status word).
            /// </summary>
            /// <param name="response">The response APDU.</param>
            /// <returns>True if response has data, false if only status word.</returns>
            public static bool HasResponseData(byte[] response) => response.Length > 2;

            /// <summary>
            /// Validates SCP02 implementation parameter.
            /// </summary>
            /// <param name="implementation">The implementation parameter to validate.</param>
            /// <returns>True if valid SCP02 implementation.</returns>
            public static bool IsValidScp02Implementation(byte implementation) =>
                Scp.Scp02.Implementations.All.Contains(implementation);

            /// <summary>
            /// Validates SCP03 implementation parameter.
            /// </summary>
            /// <param name="implementation">The implementation parameter to validate.</param>
            /// <returns>True if valid SCP03 implementation.</returns>
            public static bool IsValidScp03Implementation(byte implementation) =>
                Scp.Scp03.Implementations.All.Contains(implementation);

            /// <summary>
            /// Gets the appropriate zero chaining value for the protocol.
            /// </summary>
            /// <param name="protocol">The SCP protocol version.</param>
            /// <returns>The zero chaining value (8 bytes for SCP02, 16 bytes for SCP03).</returns>
            public static Result<byte[], SmartCardError> GetZeroChainingValue(
                ScpVersion protocol
            ) =>
                protocol switch
                {
                    ScpVersion.Scp02 => Result.Success<byte[], SmartCardError>(
                        Scp.Common.ZeroChaining8
                    ),
                    ScpVersion.Scp03 => Result.Success<byte[], SmartCardError>(
                        Scp.Common.ZeroChaining16
                    ),
                    _ => Result.Failure<byte[], SmartCardError>(
                        SmartCardError.InvalidArgument($"Unsupported protocol: {protocol}")
                    ),
                };

            /// <summary>
            /// Gets the MAC size for the protocol.
            /// </summary>
            /// <param name="protocol">The SCP protocol version.</param>
            /// <returns>The MAC size (8 bytes for both SCP02 and SCP03).</returns>
            public static Result<int, SmartCardError> GetMacSize(ScpVersion protocol) =>
                protocol switch
                {
                    ScpVersion.Scp02 => Result.Success<int, SmartCardError>(Scp.Scp02.MAC_SIZE),
                    ScpVersion.Scp03 => Result.Success<int, SmartCardError>(Scp.Scp03.MAC_SIZE),
                    _ => Result.Failure<int, SmartCardError>(
                        SmartCardError.InvalidArgument($"Unsupported protocol: {protocol}")
                    ),
                };

            /// <summary>
            /// Gets the chaining value size for the protocol.
            /// </summary>
            /// <param name="protocol">The SCP protocol version.</param>
            /// <returns>The chaining value size (8 bytes for SCP02, 16 bytes for SCP03).</returns>
            public static Result<int, SmartCardError> GetChainingValueSize(ScpVersion protocol) =>
                protocol switch
                {
                    ScpVersion.Scp02 => Result.Success<int, SmartCardError>(
                        Scp.Scp02.CHAINING_VALUE_SIZE
                    ),
                    ScpVersion.Scp03 => Result.Success<int, SmartCardError>(
                        Scp.Scp03.CHAINING_VALUE_SIZE
                    ),
                    _ => Result.Failure<int, SmartCardError>(
                        SmartCardError.InvalidArgument($"Unsupported protocol: {protocol}")
                    ),
                };
        }
    }
}
