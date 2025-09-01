using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using static Gp4Net.Cryptography.CryptoService;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// Pure functional SCP02 secure channel protocol implementation.
/// Per GlobalPlatform Card Specification v2.3.1 Appendix E.4 "SCP02".
/// All operations are stateless and deterministic for testing with known values.
/// Uses existing BouncyCastle abstractions from UnifiedCryptoService.Cipher.
/// </summary>
[PublicAPI]
public static class Scp02Protocol
{
    /// <summary>
    /// The SCP02 protocol version constant.
    /// </summary>
    public static ScpVersion ProtocolVersion => ScpVersion.Scp02;

    /// <summary>
    /// The SCP02 block size for 3DES operations.
    /// </summary>
    public static int BlockSize => 8;

    /// <summary>
    /// The SCP02 MAC size.
    /// </summary>
    public static int MacSize => 8;

    /// <summary>
    /// The SCP02 chaining value size.
    /// </summary>
    public static int ChainingValueSize => 8;

    /// <summary>
    /// The SCP02 card challenge length.
    /// </summary>
    public static int CardChallengeLength => 6;

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
        if (baseKey.Length != 16)
            return Result.Failure<byte[], SmartCardError>(
                new InvalidLengthError("baseKey", 16, baseKey.Length)
            );

        if (derivationConstant.Length != 2)
            return Result.Failure<byte[], SmartCardError>(
                new InvalidLengthError("derivationConstant", 2, derivationConstant.Length)
            );

        if (sequenceCounter.Length != 2)
            return Result.Failure<byte[], SmartCardError>(
                new InvalidLengthError("sequenceCounter", 2, sequenceCounter.Length)
            );

        // Build derivation data per Figure E-2:
        // Constant (2) || Sequence Counter (2) || Padding (12 zeros)
        byte[] derivationData = new byte[16];
        Array.Copy(derivationConstant, 0, derivationData, 0, 2);
        Array.Copy(sequenceCounter, 0, derivationData, 2, 2);
        // Remaining 12 bytes are already zeros

        // Encrypt using 3DES-CBC with zero IV using existing abstractions
        byte[] zeroIv = new byte[8];
        return CryptoService.Cipher.Encrypt3DesCbc(baseKey, zeroIv, derivationData);
    }

    /// <summary>
    /// Calculates Full 3DES MAC for SCP02 cryptograms.
    /// Per GP Card Spec v2.3.1 Section B.1.2.1 "Full Triple DES".
    /// Used only for card/host cryptogram calculation with S-ENC key.
    /// </summary>
    /// <param name="key">The S-ENC session key (16 bytes).</param>
    /// <param name="data">The cryptogram data (24 bytes, already includes padding).</param>
    /// <returns>The cryptogram value (8 bytes).</returns>
    public static Result<byte[], SmartCardError> CalculateScp02Cryptogram(byte[] key, byte[] data)
    {
        if (key.Length != 16)
            return Result.Failure<byte[], SmartCardError>(
                new InvalidLengthError("key", 16, key.Length)
            );

        if (data.Length != 24)
            return Result.Failure<byte[], SmartCardError>(
                new InvalidLengthError("data", 24, data.Length)
            );

        // Calculate SCP02 cryptogram using UnifiedCryptoService
        return CryptoService.Cryptogram.CalculateScp02Cryptogram(key, data);
    }

    /// <summary>
    /// Calculates Retail MAC (Single DES + Final Triple DES) for SCP02.
    /// Per GP Card Spec v2.3.1 Section B.1.2.2 "Single DES Plus Final Triple DES".
    /// Used for C-MAC and R-MAC calculation.
    /// </summary>
    /// <param name="key">The MAC key (16 bytes).</param>
    /// <param name="data">The data to MAC (will be padded internally).</param>
    /// <returns>The MAC value (8 bytes).</returns>
    public static Result<byte[], SmartCardError> CalculateScp02Mac(byte[] key, byte[] data)
    {
        if (key.Length != 16)
            return Result.Failure<byte[], SmartCardError>(
                new InvalidLengthError("key", 16, key.Length)
            );

        if (data.Length == 0)
            return Result.Failure<byte[], SmartCardError>(new EmptyDataError("data"));

        // Use existing MAC calculation from MacCalculations
        return CryptoService.Mac.CalculateScp02CommandMac(key, data);
    }

    /// <summary>
    /// Derives SCP02 session keys using 3DES-CBC encryption.
    /// Per GP Card Spec v2.3.1 Section E.4.1 and Figure E-2.
    /// </summary>
    /// <param name="keySet">The static key set.</param>
    /// <param name="hostChallenge">The host challenge (8 bytes).</param>
    /// <param name="cardChallenge">The card challenge (6 bytes).</param>
    /// <param name="sequenceCounter">The sequence counter (2 bytes).</param>
    /// <param name="implementationParameter">The implementation parameter.</param>
    /// <returns>The derived session keys.</returns>
    public static Result<SessionKeys, SmartCardError> DeriveSessionKeys(
        IKeySet keySet,
        byte[] hostChallenge,
        byte[] cardChallenge,
        byte[] sequenceCounter,
        byte implementationParameter
    )
    {
        if (hostChallenge.Length != 8)
            return Result.Failure<SessionKeys, SmartCardError>(
                new InvalidLengthError("hostChallenge", 8, hostChallenge.Length)
            );

        if (cardChallenge.Length != 6)
            return Result.Failure<SessionKeys, SmartCardError>(
                new InvalidLengthError("cardChallenge", 6, cardChallenge.Length)
            );

        if (sequenceCounter.Length != 2)
            return Result.Failure<SessionKeys, SmartCardError>(
                new InvalidLengthError("sequenceCounter", 2, sequenceCounter.Length)
            );

        if (!IsValidScp02Implementation(implementationParameter))
            return Result.Failure<SessionKeys, SmartCardError>(
                new UnsupportedImplementationError($"SCP02 i={implementationParameter:X2}")
            );

        ScpImplementation implementation = (ScpImplementation)implementationParameter;
        Result<KeyDerivationContext, SmartCardError> contextResult =
            KeyDerivationContext.CreateForScp02(
                keySet,
                hostChallenge,
                cardChallenge,
                sequenceCounter,
                implementation
            );

        return contextResult.Bind(CryptoService.KeyDerivation.DeriveSessionKeys);
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
        if (chainingValue.Length != ChainingValueSize)
            return Result.Failure<byte[], SmartCardError>(
                new InvalidLengthError("chainingValue", ChainingValueSize, chainingValue.Length)
            );

        // SCP02 C-MAC: 3DES-MAC over (chaining_value || command) using ISO 9797-1 Algorithm 3
        byte[] macInput = new byte[chainingValue.Length + command.Length];
        Array.Copy(chainingValue, 0, macInput, 0, chainingValue.Length);
        Array.Copy(command, 0, macInput, chainingValue.Length, command.Length);

        return CalculateScp02Mac(macKey, macInput);
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
        if (chainingValue.Length != ChainingValueSize)
            return Result.Failure<byte[], SmartCardError>(
                new InvalidLengthError("chainingValue", ChainingValueSize, chainingValue.Length)
            );

        // SCP02 R-MAC: 3DES-MAC over (chaining_value || response) using ISO 9797-1 Algorithm 3
        byte[] macInput = new byte[chainingValue.Length + response.Length];
        Array.Copy(chainingValue, 0, macInput, 0, chainingValue.Length);
        Array.Copy(response, 0, macInput, chainingValue.Length, response.Length);

        return CalculateScp02Mac(rMacKey, macInput);
    }

    /// <summary>
    /// Calculates initial MAC chaining value for EXTERNAL AUTHENTICATE command.
    /// Per GP Card Specification v2.3.1 Section E.3.2.
    /// </summary>
    /// <param name="command">The EXTERNAL AUTHENTICATE command.</param>
    /// <param name="macKey">The MAC key.</param>
    /// <returns>The calculated MAC which becomes the ICV for subsequent commands.</returns>
    public static Result<byte[], SmartCardError> CalculateInitialMacChainingValue(
        ExternalAuthenticateCommand command,
        byte[] macKey
    )
    {
        // Build the EXTERNAL AUTHENTICATE APDU for MAC calculation
        byte[] apdu = new byte[5 + command.HostCryptogram.Length];
        apdu[0] = (byte)(command.Cla | 0x04); // CLA with secure messaging bit (0x84)
        apdu[1] = command.Ins; // INS = 0x82
        apdu[2] = (byte)command.SecurityLevel; // P1 = security level
        apdu[3] = 0x00; // P2 = 0x00
        apdu[4] = (byte)(command.HostCryptogram.Length + MacSize); // Lc = 16 (8 host cryptogram + 8 MAC)
        Array.Copy(command.HostCryptogram, 0, apdu, 5, command.HostCryptogram.Length);

        // For SCP02 EXTERNAL AUTHENTICATE, MAC is calculated directly over the APDU structure
        return CalculateScp02Mac(macKey, apdu);
    }

    /// <summary>
    /// Applies command security for SCP02.
    /// </summary>
    /// <param name="command">The command APDU.</param>
    /// <param name="securityLevel">The security level.</param>
    /// <param name="sessionKeys">The session keys.</param>
    /// <param name="chainingValue">The MAC chaining value.</param>
    /// <returns>The secured command and new chaining value.</returns>
    public static Result<
        (byte[] securedCommand, byte[] newChainingValue),
        SmartCardError
    > ApplyCommandSecurity(
        byte[] command,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        byte[] chainingValue
    )
    {
        if (chainingValue.Length != ChainingValueSize)
            return Result.Failure<(byte[], byte[]), SmartCardError>(
                new InvalidLengthError("chainingValue", ChainingValueSize, chainingValue.Length)
            );

        byte[] processedCommand = command;
        byte[] newChainingValue = chainingValue;

        // Apply C-ENCRYPTION if required
        if (securityLevel.HasCEncryption())
        {
            Result<byte[], SmartCardError> encryptResult = ApplyCommandEncryption(
                processedCommand,
                sessionKeys.SEnc
            );
            if (encryptResult.IsFailure)
                return encryptResult.Error;

            processedCommand = encryptResult.Value;
        }

        // Apply C-MAC if required
        if (!securityLevel.HasCMac())
            return Result.Success<(byte[], byte[]), SmartCardError>(
                (processedCommand, newChainingValue)
            );

        Result<byte[], SmartCardError> macResult = CalculateCommandMac(
            processedCommand,
            sessionKeys.SMac,
            chainingValue
        );
        if (macResult.IsFailure)
            return macResult.Error;

        byte[] mac = macResult.Value;
        newChainingValue = mac;

        // Append MAC to command
        byte[] securedCommand = new byte[processedCommand.Length + MacSize];
        Array.Copy(processedCommand, 0, securedCommand, 0, processedCommand.Length);
        Array.Copy(mac, 0, securedCommand, processedCommand.Length, MacSize);
        processedCommand = securedCommand;

        // Set secure messaging bit in CLA
        processedCommand[0] |= 0x04;

        return Result.Success<(byte[], byte[]), SmartCardError>(
            (processedCommand, newChainingValue)
        );
    }

    /// <summary>
    /// Applies response security for SCP02.
    /// </summary>
    /// <param name="response">The response APDU.</param>
    /// <param name="securityLevel">The security level.</param>
    /// <param name="sessionKeys">The session keys.</param>
    /// <param name="chainingValue">The MAC chaining value.</param>
    /// <param name="encryptionCounter">The encryption counter (not used in SCP02).</param>
    /// <returns>The secured response and new chaining value.</returns>
    public static Result<
        (byte[] securedResponse, byte[] newChainingValue),
        SmartCardError
    > ApplyResponseSecurity(
        byte[] response,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        byte[] chainingValue,
        uint encryptionCounter = 0
    )
    {
        if (response.Length < 2)
            return Result.Failure<(byte[], byte[]), SmartCardError>(
                new InvalidLengthError("response", 2, response.Length)
            );

        if (chainingValue.Length != ChainingValueSize)
            return Result.Failure<(byte[], byte[]), SmartCardError>(
                new InvalidLengthError("chainingValue", ChainingValueSize, chainingValue.Length)
            );

        byte[] processedResponse = response;
        byte[] newChainingValue = chainingValue;

        // Check if response security should be applied based on status word
        ushort statusWord = (ushort)(response[^2] << 8 | response[^1]);
        if (!ShouldApplyResponseSecurity(statusWord))
            return Result.Success<(byte[], byte[]), SmartCardError>(
                (processedResponse, newChainingValue)
            );

        // Apply R-ENCRYPTION if required
        if (securityLevel.HasREncryption() && HasResponseData(response))
        {
            Result<byte[], SmartCardError> encryptResult = ApplyResponseEncryption(
                processedResponse,
                sessionKeys.SEnc
            );
            if (encryptResult.IsFailure)
                return encryptResult.Error;

            processedResponse = encryptResult.Value;
        }

        // Apply R-MAC if required
        if (securityLevel.HasRMac())
        {
            Result<byte[], SmartCardError> macResult = CalculateResponseMac(
                processedResponse,
                sessionKeys.SrMac,
                chainingValue
            );
            if (macResult.IsFailure)
                return macResult.Error;

            byte[] mac = macResult.Value;
            newChainingValue = mac;

            // Insert R-MAC before status word
            int statusOffset = processedResponse.Length - 2;
            byte[] securedResponse = new byte[processedResponse.Length + MacSize];
            Array.Copy(processedResponse, 0, securedResponse, 0, statusOffset); // Data
            Array.Copy(mac, 0, securedResponse, statusOffset, MacSize); // R-MAC
            Array.Copy(
                processedResponse,
                statusOffset,
                securedResponse,
                securedResponse.Length - 2,
                2
            ); // Status
            processedResponse = securedResponse;
        }

        return Result.Success<(byte[], byte[]), SmartCardError>(
            (processedResponse, newChainingValue)
        );
    }

    /// <summary>
    /// Converts implementation parameter byte to ScpImplementation enum value.
    /// Per GP Card Specification v2.3.1 Table E-1.
    /// </summary>
    /// <param name="implementationParameter">The i= parameter from INITIALIZE UPDATE response</param>
    /// <returns>The corresponding ScpImplementation enum value</returns>
    public static Result<ScpImplementation, SmartCardError> GetScp02Implementation(
        byte implementationParameter
    )
    {
        if (Enum.IsDefined(typeof(ScpImplementation), implementationParameter))
        {
            ScpImplementation impl = (ScpImplementation)implementationParameter;
            if (impl.IsScp02())
                return Result.Success<ScpImplementation, SmartCardError>(impl);
        }

        return Result.Failure<ScpImplementation, SmartCardError>(
            new UnsupportedImplementationError(
                $"SCP02 i={implementationParameter:X2} (valid: 00, 02, 04, 05, 15, 35, 55, 75)"
            )
        );
    }

    /// <summary>
    /// Checks if the given implementation parameter is a valid SCP02 implementation.
    /// </summary>
    /// <param name="implementationParameter">The implementation parameter to check.</param>
    /// <returns>True if valid, false otherwise.</returns>
    public static bool IsValidScp02Implementation(byte implementationParameter)
    {
        return implementationParameter switch
        {
            0x00
            or 0x02
            or 0x04
            or 0x05
            or 0x0A
            or 0x14
            or 0x15
            or 0x1A
            or 0x24
            or 0x25
            or 0x2A
            or 0x34
            or 0x35
            or 0x3A
            or 0x44
            or 0x45
            or 0x4A
            or 0x54
            or 0x55
            or 0x64
            or 0x65
            or 0x6A
            or 0x74
            or 0x75
            or 0x7A => true,
            _ => false,
        };
    }

    private static Result<byte[], SmartCardError> ApplyCommandEncryption(
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
        byte[] iv = new byte[8];
        return CryptoService.Cipher
            .Encrypt3DesCbcWithPadding(sEncKey, iv, dataToEncrypt)
            .Map(encryptedData =>
            {
                // Build new command with encrypted data
                byte[] newCommand = new byte[
                    5 + encryptedData.Length + (command.Length > 5 + lc ? 1 : 0)
                ];
                Array.Copy(command, 0, newCommand, 0, 4); // CLA INS P1 P2
                newCommand[0] |= 0x04; // Set secure messaging bit
                newCommand[4] = (byte)(encryptedData.Length + MacSize); // New Lc includes MAC
                Array.Copy(encryptedData, 0, newCommand, 5, encryptedData.Length);

                // Copy Le if present
                if (command.Length > 5 + lc)
                    newCommand[^1] = command[^1];

                return newCommand;
            });
    }

    private static Result<byte[], SmartCardError> ApplyResponseEncryption(
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
        byte[] iv = new byte[8];

        return CryptoService.Cipher
            .Encrypt3DesCbcWithPadding(sEncKey, iv, responseData)
            .Map(encryptedData =>
            {
                // Combine encrypted data with original status word
                byte[] result = new byte[encryptedData.Length + 2];
                Array.Copy(encryptedData, 0, result, 0, encryptedData.Length);
                Array.Copy(response, statusOffset, result, encryptedData.Length, 2);
                return result;
            });
    }

    private static bool ShouldApplyResponseSecurity(ushort statusWord)
    {
        // Only apply response security for success and warning status words per GP spec
        return statusWord == 0x9000
            || (statusWord & 0xFF00) == 0x6200
            || (statusWord & 0xFF00) == 0x6300;
    }

    private static bool HasResponseData(byte[] response)
    {
        return response.Length > 2;
    }

    // High-Level Protocol Operations for SecureChannelService Integration

    /// <summary>
    /// Creates an INITIALIZE UPDATE command for SCP02.
    /// </summary>
    /// <param name="hostChallenge">The host challenge (8 bytes).</param>
    /// <returns>The INITIALIZE UPDATE command or error.</returns>
    public static Result<InitializeUpdateCommand, SmartCardError> CreateInitializeUpdateCommand(
        byte[] hostChallenge
    )
    {
        return InitializeUpdateCommand.Create(0x00, 0x00, hostChallenge);
    }

    /// <summary>
    /// Processes an INITIALIZE UPDATE response for SCP02 and creates a secure channel context.
    /// </summary>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <param name="hostChallenge">The host challenge that was sent.</param>
    /// <param name="keySet">The key set to use for session key derivation.</param>
    /// <returns>A secure channel context for further protocol operations or error.</returns>
    public static Result<SecureChannelContext, SmartCardError> ProcessInitializeUpdateResponse(
        InitializeUpdateResponse response,
        byte[] hostChallenge,
        IKeySet keySet
    )
    {
        // Validate protocol version
        if (response.ScpId != ProtocolVersion)
        {
            return SmartCardError.InvalidResponse(
                $"Expected SCP02 but received {response.ScpId:X2}"
            );
        }

        // Validate key set type
        if (keySet is not Scp02KeySet scp02KeySet)
        {
            return SmartCardError.InvalidArgument("SCP02 requires Scp02KeySet");
        }

        // Derive session keys
        return DeriveSessionKeys(
                scp02KeySet,
                hostChallenge,
                response.CardChallenge,
                response.SequenceCounter,
                response.ImplementationParameter
            )
            .Bind(sessionKeys =>
            {
                // Verify card cryptogram
                // Build proper key information for the response
                byte[] keyInformation =
                [
                    scp02KeySet.KeyVersion,
                    0x02,
                    response.ImplementationParameter,
                ];

                // Create InitializeUpdateResponse using the Create factory method
                Result<InitializeUpdateResponse, SmartCardError> initResponseResult =
                    InitializeUpdateResponse.Create(
                        [], // empty key diversification data
                        scp02KeySet.KeyVersion,
                        0x02, // SCP02
                        response.SequenceCounter,
                        response.CardChallenge,
                        response.CardCryptogram
                    );

                if (initResponseResult.IsFailure)
                {
                    return initResponseResult.Error;
                }

                InitializeUpdateResponse initResponse = initResponseResult.Value;
                Result<byte[], SmartCardError> cardCryptogramData =
                    CryptoService.Cryptogram.BuildScp02CardCryptogramData(
                        initResponse,
                        hostChallenge
                    );
                return cardCryptogramData
                    .Bind(cryptogramData =>
                        CalculateScp02Cryptogram(sessionKeys.SEnc, cryptogramData)
                    )
                    .Bind(calculatedCryptogram =>
                    {
                        if (
                            !CryptoService.Utils.CompareBytes(
                                calculatedCryptogram,
                                response.CardCryptogram
                            )
                        )
                        {
                            return SmartCardError.AuthenticationFailed(
                                "Card cryptogram verification failed"
                            );
                        }

                        return SecureChannelContext.Create(
                            hostChallenge,
                            response,
                            sessionKeys,
                            ProtocolVersion,
                            keySet
                        );
                    });
            });
    }

    /// <summary>
    /// Creates an EXTERNAL AUTHENTICATE command for SCP02.
    /// </summary>
    /// <param name="context">The secure channel context from INITIALIZE UPDATE.</param>
    /// <param name="securityLevel">The requested security level.</param>
    /// <returns>The EXTERNAL AUTHENTICATE command with cryptogram and MAC or error.</returns>
    public static Result<
        ExternalAuthenticateCommand,
        SmartCardError
    > CreateExternalAuthenticateCommand(SecureChannelContext context, SecurityLevel securityLevel)
    {
        // Build host cryptogram data using UnifiedCryptoService
        return CryptoService.Cryptogram
            .BuildScp02HostCryptogramData(context.InitializeUpdateResponse, context.HostChallenge)
            .Bind(hostCryptogramData =>
                CryptoService.Cryptogram.CalculateScp02Cryptogram(context.SessionKeys.SEnc, hostCryptogramData)
            )
            .Bind(hostCryptogram =>
            {
                byte[] commandData = CryptoService.Utils.ConcatenateArrays(
                    hostCryptogram,
                    [(byte)securityLevel]
                );

                return ExternalAuthenticateCommand
                    .Create(commandData)
                    .Bind(command =>
                    {
                        // Calculate command MAC for EXTERNAL AUTHENTICATE
                        byte[] macData = CryptoService.Utils.ConcatenateArrays(
                            [command.Cla, command.Ins, command.P1, command.P2, command.Lc],
                            command.Data
                        );

                        // For EXTERNAL AUTHENTICATE (first secured command), use zero chaining value
                        byte[] initialChainingValue = new byte[8]; // 8 zeros
                        return CalculateCommandMac(
                                macData,
                                context.SessionKeys.SMac,
                                initialChainingValue
                            )
                            .Map(mac =>
                            {
                                byte[] securedData = CryptoService.Utils.ConcatenateArrays(
                                    commandData,
                                    mac
                                );
                                return ExternalAuthenticateCommand.Create(securedData).Value;
                            });
                    });
            });
    }

    /// <summary>
    /// Creates a secure channel session from the established SCP02 context.
    /// </summary>
    /// <param name="context">The secure channel context.</param>
    /// <param name="securityLevel">The established security level.</param>
    /// <returns>The secure channel session state or error.</returns>
    public static Result<SecureChannelState, SmartCardError> CreateSecureChannelSession(
        SecureChannelContext context,
        SecurityLevel securityLevel
    )
    {
        // Calculate initial MAC chaining value from EXTERNAL AUTHENTICATE command
        return CryptoService.Cryptogram
            .BuildScp02HostCryptogramData(context.InitializeUpdateResponse, context.HostChallenge)
            .Bind(hostCryptogramData =>
                CryptoService.Cryptogram.CalculateScp02Cryptogram(context.SessionKeys.SEnc, hostCryptogramData)
            )
            .Bind(hostCryptogram =>
            {
                byte[] commandData = CryptoService.Utils.ConcatenateArrays(
                    hostCryptogram,
                    [(byte)securityLevel]
                );

                return ExternalAuthenticateCommand
                    .Create(commandData)
                    .Bind(command =>
                        CalculateInitialMacChainingValue(command, context.SessionKeys.SMac)
                    )
                    .Bind(initialChaining =>
                        // Create the secure channel state
                        SecureChannelState.Create(
                            context.SessionKeys,
                            securityLevel,
                            ProtocolVersion,
                            initialChaining,
                            context.InitializeUpdateResponse.ImplementationParameter
                        )
                    );
            });
    }
}
