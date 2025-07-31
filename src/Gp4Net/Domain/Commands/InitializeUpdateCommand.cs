// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Commands
{
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
        public override byte Cla => ClassByte;

        /// <inheritdoc />
        public override byte Ins => InstructionByte;

        /// <inheritdoc />
        public override byte P1 => KeyVersion;

        /// <inheritdoc />
        public override byte P2 => KeyIdentifier;

        /// <inheritdoc />
        public override byte[]? Data => HostChallenge;

        /// <inheritdoc />
        public override int? ExpectedResponseLength => _useMaxResponseLength ? 256 : 28;

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
        /// Converts this command to an APDU byte array.
        /// This method is obsolete. Use IApduTransport.TransmitAsync instead.
        /// </summary>
        /// <returns>The APDU command bytes.</returns>
        [Obsolete("Use IApduTransport.TransmitAsync instead of manual APDU building")]
        public new byte[] ToApdu()
        {
            return base.ToApdu();
        }

        /// <summary>
        /// Gets the APDU byte array for this command (backward compatibility alias for ToApdu).
        /// </summary>
        /// <returns>The APDU command bytes.</returns>
        [Obsolete("Use IApduTransport.TransmitAsync instead of manual APDU building")]
        public byte[] GetApdu()
        {
            return ToApdu();
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
        public byte[]? SequenceCounter { get; }

        /// <summary>
        /// Gets the key version from the key information.
        /// </summary>
        public byte KeyVersion => KeyInformation[0];

        /// <summary>
        /// Gets the secure channel protocol identifier.
        /// </summary>
        public byte ScpId => KeyInformation[1];

        /// <summary>
        /// Gets the secure channel protocol parameter.
        /// </summary>
        public byte ScpParameter => KeyInformation[2];

        /// <summary>
        /// Parses an INITIALIZE UPDATE response.
        /// </summary>
        /// <param name="response">The response data (excluding status word).</param>
        /// <returns>The parsed response.</returns>
        public static InitializeUpdateResponse Parse(byte[] response)
        {
            ArgumentNullException.ThrowIfNull(response);

            // SCP03 responses are 32 bytes, SCP02 are typically 28-30 bytes
            if (response.Length < 28)
            {
                throw new ArgumentException("Response too short.", nameof(response));
            }

            var offset = 0;

            // Key diversification data (10 bytes)
            var keyDiversificationData = new byte[10];
            Array.Copy(response, offset, keyDiversificationData, 0, 10);
            offset += 10;

            // Key version (1 byte)
            var keyVersion = response[offset++];
            
            // SCP identifier (1 byte)
            var scpVersion = response[offset++];
            
            byte[]? sequenceCounter = null;
            byte[] cardChallenge;
            byte[] cardCryptogram;
            
            if (scpVersion == 0x03 && response.Length >= 32) // SCP03 with 32-byte response
            {
                // Implementation parameter (1 byte) 
                var implementation = response[offset++];
                
                // Key information: KeyVersion + combined SCP ID (version | implementation)
                var keyInformation = new byte[3];
                keyInformation[0] = keyVersion;
                keyInformation[1] = (byte)(scpVersion | implementation); // 0x03 | 0x70 = 0x73
                keyInformation[2] = 0x00; // Padding
                
                // Card challenge (8 bytes)
                cardChallenge = new byte[8];
                Array.Copy(response, offset, cardChallenge, 0, 8);
                offset += 8;

                // Card cryptogram (8 bytes)
                cardCryptogram = new byte[8];
                Array.Copy(response, offset, cardCryptogram, 0, 8);
                offset += 8;
                
                // Sequence counter (remaining bytes)
                var remainingBytes = response.Length - offset;
                if (remainingBytes > 0)
                {
                    sequenceCounter = new byte[remainingBytes];
                    Array.Copy(response, offset, sequenceCounter, 0, remainingBytes);
                }
                
                return new InitializeUpdateResponse(
                    keyDiversificationData,
                    keyInformation,
                    cardChallenge,
                    cardCryptogram,
                    sequenceCounter
                );
            }
            else // SCP02 or short SCP03 response
            {
                // Key information: KeyVersion + SCP ID + padding
                var keyInformation = new byte[3];
                keyInformation[0] = keyVersion;
                keyInformation[1] = scpVersion;
                keyInformation[2] = 0x00; // Padding

                // Card challenge (8 bytes)
                cardChallenge = new byte[8];
                Array.Copy(response, offset, cardChallenge, 0, 8);
                offset += 8;

                // Card cryptogram (8 bytes)
                cardCryptogram = new byte[8];
                Array.Copy(response, offset, cardCryptogram, 0, 8);
                offset += 8;
                
                // Extract sequence counter for SCP02
                if (scpVersion == 0x02)
                {
                    sequenceCounter = new byte[3];
                    sequenceCounter[0] = cardChallenge[0]; // First 2 bytes of challenge are sequence
                    sequenceCounter[1] = cardChallenge[1];
                    sequenceCounter[2] = 0x00; // Padding
                }
                
                return new InitializeUpdateResponse(
                    keyDiversificationData,
                    keyInformation,
                    cardChallenge,
                    cardCryptogram,
                    sequenceCounter
                );
            }
        }

        private InitializeUpdateResponse(
            byte[] keyDiversificationData,
            byte[] keyInformation,
            byte[] cardChallenge,
            byte[] cardCryptogram,
            byte[]? sequenceCounter
        )
        {
            KeyDiversificationData = keyDiversificationData;
            KeyInformation = keyInformation;
            CardChallenge = cardChallenge;
            CardCryptogram = cardCryptogram;
            SequenceCounter = sequenceCounter;
        }
    }
}