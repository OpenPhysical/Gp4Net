// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Commands;

/// <summary>
/// Represents the INITIALIZE UPDATE command for secure channel initiation.
/// </summary>
[PublicAPI]
public class InitializeUpdateCommand : BaseApduCommand
{
    /// <summary>
    /// The command class byte.
    /// </summary>
    public const byte ClassByte = 0x80;

    /// <summary>
    /// The command instruction byte.
    /// </summary>
    public const byte InstructionByte = 0x50;

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
    public override byte Cla
    {
        get
        {
            return ClassByte;
        }
    }

    /// <inheritdoc />
    public override byte Ins
    {
        get
        {
            return InstructionByte;
        }
    }

    /// <inheritdoc />
    public override byte P1
    {
        get
        {
            return KeyVersion;
        }
    }

    /// <inheritdoc />
    public override byte P2
    {
        get
        {
            return KeyIdentifier;
        }
    }

    /// <inheritdoc />
    public override byte[] Data
    {
        get
        {
            return HostChallenge;
        }
    }

    /// <inheritdoc />
    public override Maybe<int> ExpectedResponseLength
    {
        get
        {
            return Maybe<int>.From(_useMaxResponseLength ? 256 : 28);
        }
    }

    /// <summary>
    /// Initializes a new instance of the InitializeUpdateCommand class.
    /// </summary>
    /// <param name="keyVersion">The key version number (0 = first available key).</param>
    /// <param name="keyIdentifier">The key identifier (must be 0x00 for SCP03).</param>
    /// <param name="hostChallenge">The host challenge (8 bytes).</param>
    /// <param name="useMaxResponseLength">Whether to use maximum response length for trace compatibility.</param>
    private InitializeUpdateCommand(byte keyVersion, byte keyIdentifier, byte[] hostChallenge, bool useMaxResponseLength = false)
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
        byte[] hostChallenge)
    {
        if (hostChallenge.Length != 8)
        {
            return Result.Failure<InitializeUpdateCommand, SmartCardError>(
                SmartCardError.InvalidData($"Host challenge must be 8 bytes, got {hostChallenge.Length}"));
        }

        return Result.Success<InitializeUpdateCommand, SmartCardError>(
            new InitializeUpdateCommand(keyVersion, keyIdentifier, hostChallenge));
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
        bool useMaxResponseLength)
    {
        if (hostChallenge.Length != 8)
        {
            return Result.Failure<InitializeUpdateCommand, SmartCardError>(
                SmartCardError.InvalidData($"Host challenge must be 8 bytes, got {hostChallenge.Length}"));
        }

        return Result.Success<InitializeUpdateCommand, SmartCardError>(
            new InitializeUpdateCommand(keyVersion, keyIdentifier, hostChallenge, useMaxResponseLength));
    }


    /// <summary>
    /// Returns a string representation of this command.
    /// </summary>
    public override string ToString()
    {
        return "INITIALIZE UPDATE";
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
        get
        {
            return KeyInformation[0];
        }
    }

    /// <summary>
    /// Gets the secure channel protocol identifier.
    /// </summary>
    public byte ScpId
    {
        get
        {
            return KeyInformation[1];
        }
    }

    /// <summary>
    /// Gets the secure channel protocol parameter.
    /// </summary>
    public byte ScpParameter
    {
        get
        {
            return KeyInformation[2];
        }
    }

    /// <summary>
    /// Parses an INITIALIZE UPDATE response.
    /// </summary>
    /// <param name="response">The response data (excluding status word).</param>
    /// <returns>A Result containing the parsed response, or an error if the response data is invalid.</returns>
    public static Result<InitializeUpdateResponse, SmartCardError> Parse(byte[] response)
    {
        if (response is null)
            return Result.Failure<InitializeUpdateResponse, SmartCardError>(
                SmartCardError.InvalidArgument("Response cannot be null"));
        
        // Debug logging
        System.Diagnostics.Debug.WriteLine($"[InitializeUpdateResponse.Parse] Response length: {response.Length}");
        System.Diagnostics.Debug.WriteLine($"[InitializeUpdateResponse.Parse] Response data: {Convert.ToHexString(response)}");

        // SCP03 responses are 32 bytes, SCP02 are typically 28-30 bytes
        if (response.Length < 28)
            return Result.Failure<InitializeUpdateResponse, SmartCardError>(
                SmartCardError.InvalidData($"INITIALIZE UPDATE response too short: {response.Length} bytes, expected at least 28"));

        var offset = 0;

        // Key diversification data (10 bytes)
        var keyDiversificationData = new byte[10];
        Array.Copy(response, offset, keyDiversificationData, 0, 10);
        offset += 10;

        // Key version (1 byte)
        var keyVersion = response[offset++];
        System.Diagnostics.Debug.WriteLine($"[InitializeUpdateResponse.Parse] Key version: {keyVersion:X2}");
            
        // SCP identifier (1 byte)
        var scpVersion = response[offset++];
        System.Diagnostics.Debug.WriteLine($"[InitializeUpdateResponse.Parse] SCP ID byte: {scpVersion:X2}");
        System.Diagnostics.Debug.WriteLine($"[InitializeUpdateResponse.Parse] SCP version (masked): {(scpVersion & 0x03):X2}");
            
        byte[] sequenceCounter = [];
        byte[] cardChallenge;
        byte[] cardCryptogram;
            
        if ((scpVersion & 0x03) == 0x03) // SCP03
        {
            System.Diagnostics.Debug.WriteLine($"[InitializeUpdateResponse.Parse] Parsing as SCP03 (response length: {response.Length})");
            
            // For SCP03, the key information is 3 bytes:
            // - Byte 0: Key Version (already read at offset 10)
            // - Byte 1: SCP Version (already read at offset 11, should be 0x03)
            // - Byte 2: Implementation parameter 'i' (at offset 12)
            var implementation = response[offset++];
            System.Diagnostics.Debug.WriteLine($"[InitializeUpdateResponse.Parse] Implementation parameter: {implementation:X2}");
                
            // Build the key information structure
            var keyInformation = new byte[3];
            keyInformation[0] = keyVersion;
            keyInformation[1] = scpVersion; // Should be 0x03 for SCP03
            keyInformation[2] = implementation; // Implementation parameter (e.g., 0x70)
            System.Diagnostics.Debug.WriteLine($"[InitializeUpdateResponse.Parse] Key information: {Convert.ToHexString(keyInformation)}");
                
            // Card challenge (8 bytes)
            cardChallenge = new byte[8];
            Array.Copy(response, offset, cardChallenge, 0, 8);
            System.Diagnostics.Debug.WriteLine($"[InitializeUpdateResponse.Parse] Card challenge: {Convert.ToHexString(cardChallenge)}");
            offset += 8;

            // Card cryptogram (8 bytes)
            cardCryptogram = new byte[8];
            Array.Copy(response, offset, cardCryptogram, 0, 8);
            offset += 8;
                
            // Sequence counter (remaining bytes - should be 3 for pseudo-random challenge)
            var remainingBytes = response.Length - offset;
            System.Diagnostics.Debug.WriteLine($"[InitializeUpdateResponse.Parse] Remaining bytes for sequence counter: {remainingBytes}");
            if (remainingBytes > 0)
            {
                sequenceCounter = new byte[remainingBytes];
                Array.Copy(response, offset, sequenceCounter, 0, remainingBytes);
                System.Diagnostics.Debug.WriteLine($"[InitializeUpdateResponse.Parse] Sequence counter: {Convert.ToHexString(sequenceCounter)}");
            }
                
            return Result.Success<InitializeUpdateResponse, SmartCardError>(
                new InitializeUpdateResponse(
                    keyDiversificationData,
                    keyInformation,
                    cardChallenge,
                    cardCryptogram,
                    sequenceCounter
                ));
        }
        else // SCP02 or other format
        {
            System.Diagnostics.Debug.WriteLine($"[InitializeUpdateResponse.Parse] Parsing as SCP{(scpVersion & 0x03):X2} or other format");
            
            // Key information: KeyVersion + SCP ID + padding
            var keyInformation = new byte[3];
            keyInformation[0] = keyVersion;
            keyInformation[1] = scpVersion;
            keyInformation[2] = 0x00; // Padding

            if ((scpVersion & 0x03) == 0x02 && response.Length >= 28)
            {
                // SCP02 format per GP spec Table E-8:
                // Key diversification data (10) + Key info (2) + Sequence Counter (2) + Card challenge (6) + Card cryptogram (8)
                
                // Sequence counter (2 bytes - no padding for SCP02)
                sequenceCounter = new byte[2];
                Array.Copy(response, offset, sequenceCounter, 0, 2);
                offset += 2;
                
                // Card challenge (6 bytes)
                cardChallenge = new byte[6];
                Array.Copy(response, offset, cardChallenge, 0, 6);
                offset += 6;
                
                // Card cryptogram (8 bytes)
                cardCryptogram = new byte[8];
                Array.Copy(response, offset, cardCryptogram, 0, 8);
                offset += 8;
            }
            else
            {
                // SCP03 or other format - 8 byte card challenge
                cardChallenge = new byte[8];
                Array.Copy(response, offset, cardChallenge, 0, 8);
                offset += 8;

                // Card cryptogram (8 bytes)
                cardCryptogram = new byte[8];
                Array.Copy(response, offset, cardCryptogram, 0, 8);
                offset += 8;
            }
                
            return Result.Success<InitializeUpdateResponse, SmartCardError>(
                new InitializeUpdateResponse(
                    keyDiversificationData,
                    keyInformation,
                    cardChallenge,
                    cardCryptogram,
                    sequenceCounter
                ));
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