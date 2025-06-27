// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Commands
{
    /// <summary>
    /// Represents the INITIALIZE UPDATE command for secure channel initiation.
    /// </summary>
    [PublicAPI]
    public class InitializeUpdateCommand
    {
        /// <summary>
        /// The command class byte.
        /// </summary>
        public const byte Cla = 0x80;

        /// <summary>
        /// The command instruction byte.
        /// </summary>
        public const byte Ins = 0x50;

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
        /// Initializes a new instance of the InitializeUpdateCommand class.
        /// </summary>
        /// <param name="keyVersion">The key version number (0 = first available key).</param>
        /// <param name="keyIdentifier">The key identifier (must be 0x00 for SCP03).</param>
        /// <param name="hostChallenge">The host challenge (8 bytes).</param>
        public InitializeUpdateCommand(byte keyVersion, byte keyIdentifier, byte[] hostChallenge)
        {
            if (hostChallenge?.Length != 8)
                throw new ArgumentException("Host challenge must be 8 bytes.", nameof(hostChallenge));

            KeyVersion = keyVersion;
            KeyIdentifier = keyIdentifier;
            HostChallenge = (byte[])hostChallenge.Clone();
        }

        /// <summary>
        /// Converts this command to an APDU byte array.
        /// </summary>
        /// <returns>The APDU command bytes.</returns>
        public byte[] ToApdu()
        {
            var apdu = new byte[5 + HostChallenge.Length];
            apdu[0] = Cla;
            apdu[1] = Ins;
            apdu[2] = KeyVersion;
            apdu[3] = KeyIdentifier;
            apdu[4] = (byte)HostChallenge.Length;
            Array.Copy(HostChallenge, 0, apdu, 5, HostChallenge.Length);

            return apdu;
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
            if (response == null)
                throw new ArgumentNullException(nameof(response));

            // Minimum response length is 29 bytes (10 + 3 + 8 + 8)
            if (response.Length < 29)
                throw new ArgumentException("Response too short.", nameof(response));

            var offset = 0;

            // Key diversification data (10 bytes)
            var keyDiversificationData = new byte[10];
            Array.Copy(response, offset, keyDiversificationData, 0, 10);
            offset += 10;

            // Key information (3 bytes)
            var keyInformation = new byte[3];
            Array.Copy(response, offset, keyInformation, 0, 3);
            offset += 3;

            // Card challenge (8 bytes)
            var cardChallenge = new byte[8];
            Array.Copy(response, offset, cardChallenge, 0, 8);
            offset += 8;

            // Card cryptogram (8 bytes)
            var cardCryptogram = new byte[8];
            Array.Copy(response, offset, cardCryptogram, 0, 8);
            offset += 8;

            // Sequence counter (3 bytes, only for SCP02)
            byte[]? sequenceCounter = null;
            if (response.Length >= 32)
            {
                sequenceCounter = new byte[3];
                Array.Copy(response, offset, sequenceCounter, 0, 3);
            }

            return new InitializeUpdateResponse(
                keyDiversificationData,
                keyInformation,
                cardChallenge,
                cardCryptogram,
                sequenceCounter);
        }

        private InitializeUpdateResponse(
            byte[] keyDiversificationData,
            byte[] keyInformation,
            byte[] cardChallenge,
            byte[] cardCryptogram,
            byte[]? sequenceCounter)
        {
            KeyDiversificationData = keyDiversificationData;
            KeyInformation = keyInformation;
            CardChallenge = cardChallenge;
            CardCryptogram = cardCryptogram;
            SequenceCounter = sequenceCounter;
        }
    }
}
