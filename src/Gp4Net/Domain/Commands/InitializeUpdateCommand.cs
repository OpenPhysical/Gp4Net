// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Core.Functional;
using Gp4Net.Transport;
using JetBrains.Annotations;
using WSCT.ISO7816;
using static Gp4Net.Constants.Constants;
using static Gp4Net.Cryptography.CryptoService;

namespace Gp4Net.Domain.Commands;

/// <summary>
/// Represents the INITIALIZE UPDATE command for secure channel initiation.
/// </summary>
[PublicAPI]
public class InitializeUpdateCommand : IApduCommand
{
    /// <summary>
    /// The command class byte.
    /// </summary>
    public const byte CLASS_BYTE = GlobalPlatform.Cla.GP_STANDARD;

    /// <summary>
    /// The command instruction byte.
    /// </summary>
    public const byte INSTRUCTION_BYTE = GlobalPlatform.Ins.INITIALIZE_UPDATE;

    /// <summary>
    /// Gets the key version number.
    /// </summary>
    public byte KeyVersion { get; }

    /// <summary>
    /// Gets the key identifier (always 0x00 for SCP03).
    /// </summary>
    public byte KeyIdentifier { get; }

    /// <summary>
    /// Gets the host challenge.
    /// </summary>
    public byte[] HostChallenge { get; }

    /// <summary>
    /// Gets whether to use maximum response length (256) for trace compatibility.
    /// </summary>
    private readonly bool _useMaxResponseLength;

    /// <inheritdoc />
    public byte Cla => CLASS_BYTE;

    /// <inheritdoc />
    public byte Ins => INSTRUCTION_BYTE;

    /// <summary>
    /// Converts this command to a CommandAPDU.
    /// </summary>
    /// <returns>A result containing the CommandAPDU or an error.</returns>
    public Result<CommandAPDU, SmartCardError> ToCommandApdu()
    {
        var expectedLength = _useMaxResponseLength ? 256 : 28;

        return Result.Success<CommandAPDU, SmartCardError>(
            new CommandAPDU(
                CLASS_BYTE,
                INSTRUCTION_BYTE,
                KeyVersion,
                KeyIdentifier,
                (uint)HostChallenge.Length,
                HostChallenge,
                (uint)expectedLength
            )
        );
    }

    /// <summary>
    /// Initializes a new instance of the InitializeUpdateCommand class.
    /// </summary>
    /// <param name="keyVersion">The key version number (0 = first available key).</param>
    /// <param name="keyIdentifier">The key identifier (must be 0x00 for SCP03).</param>
    /// <param name="hostChallenge">The host challenge (8 bytes).</param>
    /// <param name="useMaxResponseLength">Whether to use maximum response length for trace compatibility.</param>
    private InitializeUpdateCommand(
        byte keyVersion,
        byte keyIdentifier,
        byte[] hostChallenge,
        bool useMaxResponseLength = false
    )
    {
        KeyVersion = keyVersion;
        KeyIdentifier = keyIdentifier;
        HostChallenge = (byte[])hostChallenge.Clone();
        _useMaxResponseLength = useMaxResponseLength;
    }

    /// <summary>
    /// Creates a new InitializeUpdateCommand instance.
    /// </summary>
    /// <param name="keyVersion">The key version number (0 = first available key).</param>
    /// <param name="keyIdentifier">The key identifier (must be 0x00 for SCP03).</param>
    /// <param name="hostChallenge">The host challenge (8 bytes).</param>
    /// <returns>A result containing the command or an error.</returns>
    public static Result<InitializeUpdateCommand, SmartCardError> Create(
        byte keyVersion,
        byte keyIdentifier,
        byte[] hostChallenge
    )
    {
        return Maybe<byte[]>
            .From(hostChallenge)
            .Match(
                Some: challengeValue =>
                    challengeValue.Length == 8
                        ? Result.Success<InitializeUpdateCommand, SmartCardError>(
                            new InitializeUpdateCommand(keyVersion, keyIdentifier, challengeValue)
                        )
                        : Result.Failure<InitializeUpdateCommand, SmartCardError>(
                            SmartCardError.InvalidArgument(
                                $"Host challenge must be 8 bytes, got {challengeValue.Length}"
                            )
                        ),
                None: () =>
                    Result.Failure<InitializeUpdateCommand, SmartCardError>(
                        SmartCardError.InvalidArgument("Host challenge cannot be null")
                    )
            );
    }

    /// <summary>
    /// Creates a new InitializeUpdateCommand instance with trace compatibility.
    /// </summary>
    /// <param name="keyVersion">The key version number (0 = first available key).</param>
    /// <param name="keyIdentifier">The key identifier (must be 0x00 for SCP03).</param>
    /// <param name="hostChallenge">The host challenge (8 bytes).</param>
    /// <param name="useMaxResponseLength">Whether to use maximum response length for trace compatibility.</param>
    /// <returns>A result containing the command or an error.</returns>
    public static Result<InitializeUpdateCommand, SmartCardError> CreateWithOptions(
        byte keyVersion,
        byte keyIdentifier,
        byte[] hostChallenge,
        bool useMaxResponseLength
    )
    {
        return Maybe<byte[]>
            .From(hostChallenge)
            .Match(
                Some: challengeValue =>
                    challengeValue.Length == 8
                        ? Result.Success<InitializeUpdateCommand, SmartCardError>(
                            new InitializeUpdateCommand(
                                keyVersion,
                                keyIdentifier,
                                challengeValue,
                                useMaxResponseLength
                            )
                        )
                        : Result.Failure<InitializeUpdateCommand, SmartCardError>(
                            SmartCardError.InvalidArgument(
                                $"Host challenge must be 8 bytes, got {challengeValue.Length}"
                            )
                        ),
                None: () =>
                    Result.Failure<InitializeUpdateCommand, SmartCardError>(
                        SmartCardError.InvalidArgument("Host challenge cannot be null")
                    )
            );
    }

    /// <summary>
    /// Returns a string representation of this command.
    /// </summary>
    public override string ToString()
    {
        return "INITIALIZE UPDATE";
    }

    /// <inheritdoc />
    public CommandAPDU ToApdu()
    {
        return ToCommandApdu()
            .GetValueOrDefault(
                new CommandAPDU(
                    GlobalPlatform.Cla.GP_STANDARD,
                    GlobalPlatform.Ins.INITIALIZE_UPDATE,
                    0x00,
                    0x00
                )
            );
    }

    /// <inheritdoc />
    public byte[] ToBytes()
    {
        return ToCommandApdu().Map(cmd => cmd.ToBytes()).GetValueOrDefault([]);
    }
}

/// <summary>
/// Represents the response to an INITIALIZE UPDATE command.
/// </summary>
public class InitializeUpdateResponse
{
    /// <summary>
    /// Gets the key diversification data (10 bytes).
    /// </summary>
    public byte[] KeyDiversificationData { get; }

    /// <summary>
    /// Gets the key information (3 bytes).
    /// </summary>
    public byte[] KeyInformation { get; }

    /// <summary>
    /// Gets the card challenge (8 bytes).
    /// </summary>
    public byte[] CardChallenge { get; }

    /// <summary>
    /// Gets the card cryptogram (8 bytes).
    /// </summary>
    public byte[] CardCryptogram { get; }

    /// <summary>
    /// Gets the sequence counter (3 bytes, only for SCP02).
    /// </summary>
    public byte[] SequenceCounter { get; }

    /// <summary>
    /// Gets the key version from the key information.
    /// </summary>
    public byte KeyVersion
    {
        get { return KeyInformation[0]; }
    }

    /// <summary>
    /// Gets the secure channel protocol identifier as raw byte value.
    /// </summary>
    public byte ScpId => KeyInformation.Length > 1 ? KeyInformation[1] : (byte)0x00;

    /// <summary>
    /// Gets the secure channel protocol version as typed enum.
    /// </summary>
    public Maybe<ScpVersion> ScpVersion =>
        KeyInformation.Length > 1
            ? KeyInformation[1]
                .ToEnum<ScpVersion>() // Result<ScpVersion>
                .Match(Maybe<ScpVersion>.From, static _ => Maybe<ScpVersion>.None)
            : Maybe<ScpVersion>.None;

    /// <summary>
    /// Gets the secure channel protocol parameter.
    /// </summary>
    public byte ScpParameter
    {
        get { return KeyInformation[2]; }
    }

    /// <summary>
    /// Gets the implementation parameter (alias for ScpParameter).
    /// </summary>
    public byte ImplementationParameter => ScpParameter;

    /// <summary>
    /// Creates a new InitializeUpdateResponse instance with functional validation.
    /// GP Card Specification v2.3.1: Factory function for direct test instance creation.
    /// </summary>
    /// <param name="keyDiversificationData">The key diversification data (0-10 bytes, null for no diversification).</param>
    /// <param name="keyVersion">The key version byte.</param>
    /// <param name="scpId">The SCP identifier byte.</param>
    /// <param name="sequenceCounter">The sequence counter (2-3 bytes, null for SCP03).</param>
    /// <param name="cardChallenge">The card challenge (6 bytes for SCP02, 8 bytes for SCP03).</param>
    /// <param name="cardCryptogram">The card cryptogram (8 bytes).</param>
    /// <returns>A Result containing the created response or validation errors.</returns>
    public static Result<InitializeUpdateResponse, SmartCardError> Create(
        byte[] keyDiversificationData,
        byte keyVersion,
        byte scpId,
        byte[] sequenceCounter,
        byte[] cardChallenge,
        byte[] cardCryptogram
    )
    {
        // Validate all inputs functionally using UnitResult pattern
        var scpValidation = ValidateScpId(scpId);
        if (scpValidation.IsFailure)
            return Result.Failure<InitializeUpdateResponse, SmartCardError>(scpValidation.Error);

        var kddValidation = ValidateKeyDiversificationData(keyDiversificationData);
        if (kddValidation.IsFailure)
            return Result.Failure<InitializeUpdateResponse, SmartCardError>(kddValidation.Error);

        var sequenceValidation = ValidateSequenceCounter(sequenceCounter, scpId);
        if (sequenceValidation.IsFailure)
            return Result.Failure<InitializeUpdateResponse, SmartCardError>(
                sequenceValidation.Error
            );

        var challengeValidation = ValidateCardChallenge(cardChallenge, scpId);
        if (challengeValidation.IsFailure)
            return Result.Failure<InitializeUpdateResponse, SmartCardError>(
                challengeValidation.Error
            );

        var cryptogramValidation = ValidateCardCryptogram(cardCryptogram);
        if (cryptogramValidation.IsFailure)
            return Result.Failure<InitializeUpdateResponse, SmartCardError>(
                cryptogramValidation.Error
            );

        // All validations passed, create the instance
        return Result.Success<InitializeUpdateResponse, SmartCardError>(
            CreateInstance(
                keyDiversificationData,
                keyVersion,
                scpId,
                sequenceCounter,
                cardChallenge,
                cardCryptogram
            )
        );
    }

    /// <summary>
    /// Validates key diversification data per GP specification.
    /// </summary>
    private static UnitResult<SmartCardError> ValidateKeyDiversificationData(
        byte[] keyDiversificationData
    )
    {
        return keyDiversificationData switch
        {
            // Key diversification data validation according to GP specification
            null => UnitResult.Success<SmartCardError>(), // No diversification
            { Length: 0 } => UnitResult.Success<SmartCardError>(), // Empty is valid for no diversification
            { Length: 10 } => UnitResult.Success<SmartCardError>(), // Standard GP diversification length
            _
                => UnitResult.Failure(
                    SmartCardError.InvalidArgument(
                        $"Key diversification data must be null, empty, or 10 bytes, got {keyDiversificationData.Length}"
                    )
                ),
        };
    }

    /// <summary>
    /// Validates sequence counter per GP specification and SCP version.
    /// </summary>
    private static UnitResult<SmartCardError> ValidateSequenceCounter(
        byte[] sequenceCounter,
        byte scpId
    )
    {
        byte scpVersion = (byte)(scpId & 0x03);

        return scpVersion switch
        {
            0x02
                => sequenceCounter switch
                {
                    null
                        => UnitResult.Failure(
                            SmartCardError.InvalidArgument("SCP02 requires sequence counter")
                        ),
                    { Length: < 2 }
                        => UnitResult.Failure(
                            SmartCardError.InvalidArgument(
                                $"SCP02 sequence counter must be at least 2 bytes, got {sequenceCounter.Length}"
                            )
                        ),
                    { Length: > 3 }
                        => UnitResult.Failure(
                            SmartCardError.InvalidArgument(
                                $"SCP02 sequence counter must be at most 3 bytes, got {sequenceCounter.Length}"
                            )
                        ),
                    _ => UnitResult.Success<SmartCardError>(),
                },
            0x03 => UnitResult.Success<SmartCardError>(), // SCP03 doesn't use sequence counter in same way
            _
                => UnitResult.Failure(
                    SmartCardError.InvalidArgument($"Unsupported SCP version: {scpVersion:X2}")
                ),
        };
    }

    /// <summary>
    /// Validates SCP ID for supported versions.
    /// </summary>
    private static UnitResult<SmartCardError> ValidateScpId(byte scpId)
    {
        byte scpVersion = (byte)(scpId & 0x03);

        return scpVersion switch
        {
            0x02 or 0x03 => UnitResult.Success<SmartCardError>(),
            _
                => UnitResult.Failure(
                    SmartCardError.InvalidArgument($"Unsupported SCP version: {scpVersion:X2}")
                ),
        };
    }

    /// <summary>
    /// Validates card challenge per GP specification and SCP version.
    /// </summary>
    private static UnitResult<SmartCardError> ValidateCardChallenge(
        byte[] cardChallenge,
        byte scpId
    )
    {
        return Maybe<byte[]>
            .From(cardChallenge)
            .Match(
                Some: challengeValue => ValidateCardChallengeLength(challengeValue, scpId),
                None: () =>
                    UnitResult.Failure(
                        SmartCardError.InvalidArgument("Card challenge cannot be null")
                    )
            );
    }

    /// <summary>
    /// Validates card cryptogram per GP specification.
    /// </summary>
    private static UnitResult<SmartCardError> ValidateCardCryptogram(byte[] cardCryptogram)
    {
        return cardCryptogram switch
        {
            null
                => UnitResult.Failure(
                    SmartCardError.InvalidArgument("Card cryptogram cannot be null")
                ),
            { Length: 8 } => UnitResult.Success<SmartCardError>(),
            _
                => UnitResult.Failure(
                    SmartCardError.InvalidArgument(
                        $"Card cryptogram must be 8 bytes, got {cardCryptogram.Length}"
                    )
                ),
        };
    }

    /// <summary>
    /// Creates the actual instance after validation.
    /// </summary>
    private static InitializeUpdateResponse CreateInstance(
        byte[] keyDiversificationData,
        byte keyVersion,
        byte scpId,
        byte[] sequenceCounter,
        byte[] cardChallenge,
        byte[] cardCryptogram
    )
    {
        // Build key information array (3 bytes: version, scp_id, scp_parameter)
        byte[] keyInformation = [keyVersion, scpId, 0x00]; // Default SCP parameter

        return new InitializeUpdateResponse(
            keyDiversificationData ?? [],
            keyInformation,
            cardChallenge,
            cardCryptogram,
            sequenceCounter ?? []
        );
    }

    /// <summary>
    /// Parses an INITIALIZE UPDATE response.
    /// </summary>
    /// <param name="response">The response data (excluding status word).</param>
    /// <returns>A Result containing the parsed response, or an error if the response data is invalid.</returns>
    public static Result<InitializeUpdateResponse, SmartCardError> Parse(byte[] response)
    {
        return Maybe<byte[]>
            .From(response)
            .Match(
                Some: responseValue => ParseValidResponse(responseValue),
                None: () =>
                    Result.Failure<InitializeUpdateResponse, SmartCardError>(
                        SmartCardError.InvalidArgument("Response cannot be null")
                    )
            );
    }

    /// <summary>
    /// Validates host challenge length.
    /// </summary>
    /// <param name="hostChallenge">The host challenge to validate.</param>
    /// <returns>UnitResult indicating success or failure.</returns>
    private static UnitResult<SmartCardError> ValidateHostChallengeLength(byte[] hostChallenge)
    {
        return hostChallenge.Length == 8
            ? UnitResult.Success<SmartCardError>()
            : UnitResult.Failure(
                SmartCardError.InvalidData(
                    $"Host challenge must be 8 bytes, got {hostChallenge.Length}"
                )
            );
    }

    /// <summary>
    /// Validates card challenge length based on SCP version.
    /// </summary>
    /// <param name="cardChallenge">The card challenge to validate.</param>
    /// <param name="scpId">The SCP identifier.</param>
    /// <returns>UnitResult indicating success or failure.</returns>
    private static UnitResult<SmartCardError> ValidateCardChallengeLength(
        byte[] cardChallenge,
        byte scpId
    )
    {
        byte scpVersion = (byte)(scpId & 0x03);
        int expectedLength = scpVersion switch
        {
            0x02 => 6, // SCP02 uses 6-byte challenges
            0x03 => 8, // SCP03 uses 8-byte challenges
            _ => -1,
        };

        return expectedLength == -1
            ? UnitResult.Failure(
                SmartCardError.InvalidArgument($"Unsupported SCP version: {scpVersion:X2}")
            )
            : cardChallenge.Length == expectedLength
                ? UnitResult.Success<SmartCardError>()
                : UnitResult.Failure(
                    SmartCardError.InvalidArgument(
                        $"SCP{scpVersion:X2} card challenge must be {expectedLength} bytes, got {cardChallenge.Length}"
                    )
                );
    }

    /// <summary>
    /// Parses a validated response.
    /// </summary>
    /// <param name="response">The validated response data.</param>
    /// <returns>A Result containing the parsed response.</returns>
    private static Result<InitializeUpdateResponse, SmartCardError> ParseValidResponse(
        byte[] response
    )
    {
        // Per GP spec and trace analysis: SCP03 responses are 32 bytes, SCP02 are typically 28-30 bytes
        // Minimum 28 bytes per GP spec, but allow extra fields that some implementations include
        // Real-world traces show responses up to 35+ bytes with vendor-specific extensions
        if (response.Length < 28)
            return Result.Failure<InitializeUpdateResponse, SmartCardError>(
                SmartCardError.InvalidData(
                    $"INITIALIZE UPDATE response too short: {response.Length} bytes, expected at least 28"
                )
            );

        int offset = 0;

        // Key diversification data (10 bytes)
        byte[] keyDiversificationData = new byte[10];
        Array.Copy(response, offset, keyDiversificationData, 0, 10);
        offset += 10;

        // Key version (1 byte)
        byte keyVersion = response[offset++];

        // SCP identifier (1 byte)
        byte scpVersion = response[offset++];

        byte[] sequenceCounter = [];
        byte[] cardChallenge;
        byte[] cardCryptogram;

        // Strict SCP version parsing - fail secure, no fallbacks
        byte detectedScpVersion = (byte)(scpVersion & 0x03);

        switch (detectedScpVersion)
        {
            case 0x02: // SCP02
            {
                // SCP02 requires exactly 28 bytes minimum per GP spec Table E-8:
                // Key diversification data (10) + Key info (2) + Sequence Counter (2) + Card challenge (6) + Card cryptogram (8) = 28
                if (response.Length < 28)
                {
                    return Result.Failure<InitializeUpdateResponse, SmartCardError>(
                        SmartCardError.InvalidData(
                            $"SCP02 INITIALIZE UPDATE response too short: {response.Length} bytes, expected at least 28"
                        )
                    );
                }

                // Key information: KeyVersion + SCP ID + padding
                byte[] keyInformation = new byte[3];
                keyInformation[0] = keyVersion;
                keyInformation[1] = scpVersion;
                keyInformation[2] = 0x00; // Padding

                // Sequence counter (2 bytes - required for SCP02)
                sequenceCounter = new byte[2];
                Array.Copy(response, offset, sequenceCounter, 0, 2);
                offset += 2;

                // Card challenge (6 bytes - per SCP02 specification)
                cardChallenge = new byte[6];
                Array.Copy(response, offset, cardChallenge, 0, 6);
                offset += 6;

                // Card cryptogram (8 bytes)
                cardCryptogram = new byte[8];
                Array.Copy(response, offset, cardCryptogram, 0, 8);
                offset += 8;

                return Result.Success<InitializeUpdateResponse, SmartCardError>(
                    new InitializeUpdateResponse(
                        keyDiversificationData,
                        keyInformation,
                        cardChallenge,
                        cardCryptogram,
                        sequenceCounter
                    )
                );
            }

            case 0x03: // SCP03
            {
                // SCP03 requires exactly 32 bytes minimum per GP spec:
                // Key diversification data (10) + Key info (3) + Card challenge (8) + Card cryptogram (8) + Sequence counter (3) = 32
                if (response.Length < 32)
                {
                    return Result.Failure<InitializeUpdateResponse, SmartCardError>(
                        SmartCardError.InvalidData(
                            $"SCP03 INITIALIZE UPDATE response too short: {response.Length} bytes, expected at least 32"
                        )
                    );
                }

                // For SCP03, the key information is 3 bytes:
                // - Byte 0: Key Version (already read at offset 10)
                // - Byte 1: SCP Version (already read at offset 11, should be 0x03)
                // - Byte 2: Implementation parameter 'i' (at offset 12)
                byte implementation = response[offset++];

                // Build the key information structure
                byte[] keyInformation = new byte[3];
                keyInformation[0] = keyVersion;
                keyInformation[1] = scpVersion; // Should be 0x03 for SCP03
                keyInformation[2] = implementation; // Implementation parameter (e.g., 0x70)

                // Card challenge (8 bytes - per SCP03 specification)
                cardChallenge = new byte[8];
                Array.Copy(response, offset, cardChallenge, 0, 8);
                offset += 8;

                // Card cryptogram (8 bytes)
                cardCryptogram = new byte[8];
                Array.Copy(response, offset, cardCryptogram, 0, 8);
                offset += 8;

                // Sequence counter (remaining bytes - should be 3 for pseudo-random challenge)
                int remainingBytes = response.Length - offset;
                if (remainingBytes > 0)
                {
                    sequenceCounter = new byte[remainingBytes];
                    Array.Copy(response, offset, sequenceCounter, 0, remainingBytes);
                }
                else
                {
                    sequenceCounter = [];
                }

                return Result.Success<InitializeUpdateResponse, SmartCardError>(
                    new InitializeUpdateResponse(
                        keyDiversificationData,
                        keyInformation,
                        cardChallenge,
                        cardCryptogram,
                        sequenceCounter
                    )
                );
            }

            default:
                return Result.Failure<InitializeUpdateResponse, SmartCardError>(
                    SmartCardError.InvalidData(
                        $"Unsupported SCP version: {detectedScpVersion:X2}. Only SCP02 and SCP03 are supported."
                    )
                );
        }
    }

    private InitializeUpdateResponse(
        byte[] keyDiversificationData,
        byte[] keyInformation,
        byte[] cardChallenge,
        byte[] cardCryptogram,
        byte[] sequenceCounter
    )
    {
        KeyDiversificationData = keyDiversificationData;
        KeyInformation = keyInformation;
        CardChallenge = cardChallenge;
        CardCryptogram = cardCryptogram;
        SequenceCounter = sequenceCounter;
    }
}
