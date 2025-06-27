// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using Gp4Net.Constants;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Interfaces;
using JetBrains.Annotations;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.Domain.Protocol
{
    /// <summary>
    /// Implements the SCP03 secure channel protocol.
    /// </summary>
    [PublicAPI]
    public class Scp03Protocol : ISecureChannelProtocol
    {
        private readonly Scp03KeySet _keySet;

        /// <summary>
        /// Gets the protocol version identifier.
        /// </summary>
        public byte ProtocolVersion => ProtocolIdentifiers.Scp03;

        /// <summary>
        /// Initializes a new instance of the Scp03Protocol class.
        /// </summary>
        /// <param name="keySet">The static key set.</param>
        public Scp03Protocol(Scp03KeySet keySet)
        {
            _keySet = keySet ?? throw new ArgumentNullException(nameof(keySet));
        }

        /// <summary>
        /// Creates an INITIALIZE UPDATE command.
        /// </summary>
        public InitializeUpdateCommand CreateInitializeUpdateCommand(byte[] hostChallenge)
        {
            if (hostChallenge?.Length != 8)
                throw new ArgumentException("Host challenge must be 8 bytes.", nameof(hostChallenge));

            // For SCP03, key identifier must be 0x00
            return new InitializeUpdateCommand(_keySet.KeyVersion, 0x00, hostChallenge);
        }

        /// <summary>
        /// Processes an INITIALIZE UPDATE response and establishes a session.
        /// </summary>
        public SecureChannelSession ProcessInitializeUpdateResponse(InitializeUpdateResponse response, byte[] hostChallenge)
        {
            if (response == null) throw new ArgumentNullException(nameof(response));
            if (hostChallenge?.Length != 8) throw new ArgumentException("Host challenge must be 8 bytes.", nameof(hostChallenge));

            // Verify the response is for SCP03
            if ((response.ScpId & ProtocolIdentifiers.ProtocolMask) != ProtocolIdentifiers.Scp03)
                throw new InvalidOperationException($"Expected SCP03 but received SCP{response.ScpId:X2}");

            // Determine key length from the static keys
            var keyLength = _keySet.EncKey.Length * 8;

            // Derive session keys
            var sessionKeys = KeyDerivation.DeriveScp03SessionKeys(
                _keySet,
                hostChallenge,
                response.CardChallenge,
                keyLength);

            // Verify card cryptogram
            if (!VerifyCardCryptogram(response, hostChallenge, sessionKeys))
                throw new InvalidOperationException("Card cryptogram verification failed.");

            // Calculate initial MAC chaining value
            var macChainingValue = new byte[16]; // Zero IV for SCP03

            return new SecureChannelSession(
                sessionKeys,
                SecurityLevel.None, // Will be set by EXTERNAL AUTHENTICATE
                ProtocolVersion,
                macChainingValue);
        }

        /// <summary>
        /// Creates an EXTERNAL AUTHENTICATE command.
        /// </summary>
        public ExternalAuthenticateCommand CreateExternalAuthenticateCommand(SecureChannelSession session, SecurityLevel securityLevel)
        {
            if (session == null) throw new ArgumentNullException(nameof(session));

            // For now, we'll need access to the original response data to calculate host cryptogram
            // This is a simplified version - in practice, you'd store necessary data in the session
            throw new NotImplementedException("Need to store INITIALIZE UPDATE response data in session.");
        }

        /// <summary>
        /// Verifies the card cryptogram.
        /// </summary>
        public bool VerifyCardCryptogram(InitializeUpdateResponse response, byte[] hostChallenge, SessionKeys sessionKeys)
        {
            // Build card cryptogram input data
            var cryptogramData = BuildCardCryptogramData(response, hostChallenge);

            // Calculate expected card cryptogram
            var expectedCryptogram = CalculateCryptogram(sessionKeys.SMac, cryptogramData);

            // Compare cryptograms
            return CompareBytes(expectedCryptogram, response.CardCryptogram);
        }

        /// <summary>
        /// Calculates the host cryptogram.
        /// </summary>
        public byte[] CalculateHostCryptogram(InitializeUpdateResponse response, byte[] hostChallenge, SessionKeys sessionKeys)
        {
            // Build host cryptogram input data
            var cryptogramData = BuildHostCryptogramData(response, hostChallenge);

            // Calculate host cryptogram
            return CalculateCryptogram(sessionKeys.SMac, cryptogramData);
        }

        /// <summary>
        /// Builds the input data for card cryptogram calculation.
        /// </summary>
        private byte[] BuildCardCryptogramData(InitializeUpdateResponse response, byte[] hostChallenge)
        {
            // Card cryptogram data: Label || 0x00 || 0x00 || L || Host Challenge || Card Challenge
            var data = new byte[11 + 1 + 1 + 2 + 8 + 8];
            var offset = 0;

            // Label (11 bytes of 0x00)
            offset += 11;

            // Derivation constant for card cryptogram
            data[offset++] = DerivationConstants.CardCryptogram;

            // Separator
            data[offset++] = 0x00;

            // Length (64 bits = 8 bytes)
            data[offset++] = 0x00;
            data[offset++] = 0x40;

            // Host challenge
            Array.Copy(hostChallenge, 0, data, offset, 8);
            offset += 8;

            // Card challenge
            Array.Copy(response.CardChallenge, 0, data, offset, 8);

            return data;
        }

        /// <summary>
        /// Builds the input data for host cryptogram calculation.
        /// </summary>
        private byte[] BuildHostCryptogramData(InitializeUpdateResponse response, byte[] hostChallenge)
        {
            // Host cryptogram data: Label || 0x01 || 0x00 || L || Host Challenge || Card Challenge
            var data = new byte[11 + 1 + 1 + 2 + 8 + 8];
            var offset = 0;

            // Label (11 bytes of 0x00)
            offset += 11;

            // Derivation constant for host cryptogram
            data[offset++] = DerivationConstants.HostCryptogram;

            // Separator
            data[offset++] = 0x00;

            // Length (64 bits = 8 bytes)
            data[offset++] = 0x00;
            data[offset++] = 0x40;

            // Host challenge
            Array.Copy(hostChallenge, 0, data, offset, 8);
            offset += 8;

            // Card challenge
            Array.Copy(response.CardChallenge, 0, data, offset, 8);

            return data;
        }

        /// <summary>
        /// Calculates a cryptogram using CMAC-AES.
        /// </summary>
        private byte[] CalculateCryptogram(byte[] key, byte[] data)
        {
            var cmac = new CMac(new AesEngine(), 64); // 64-bit MAC
            cmac.Init(new KeyParameter(key));
            cmac.BlockUpdate(data, 0, data.Length);

            var cryptogram = new byte[8];
            cmac.DoFinal(cryptogram, 0);

            return cryptogram;
        }

        /// <summary>
        /// Compares two byte arrays in constant time.
        /// </summary>
        private static bool CompareBytes(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;

            var result = 0;
            for (int i = 0; i < a.Length; i++)
            {
                result |= a[i] ^ b[i];
            }
            return result == 0;
        }
    }
}
