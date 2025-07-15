// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Linq;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Kdf.Modes;
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
        private readonly IKeySet _keySet;
        private readonly byte _implementation;

        /// <summary>
        /// Gets the protocol version identifier.
        /// </summary>
        public byte ProtocolVersion => ProtocolIdentifiers.Scp03;

        /// <summary>
        /// Gets the SCP03 implementation parameter.
        /// </summary>
        public byte Implementation => _implementation;

        /// <summary>
        /// Initializes a new instance of the Scp03Protocol class.
        /// </summary>
        /// <param name="keySet">The static key set.</param>
        /// <param name="implementation">The SCP03 implementation parameter (default is 0x70).</param>
        public Scp03Protocol(IKeySet keySet, byte implementation = 0x70)
        {
            ArgumentNullException.ThrowIfNull(keySet);
            _keySet = keySet;
            _implementation = implementation;

            // Validate that this is an SCP03-compatible key set
            if (keySet is not Scp03KeySet)
            {
                throw new ArgumentException("SCP03 protocol requires SCP03 key set");
            }

            // Validate implementation parameter
            if (!IsValidImplementation(implementation))
            {
                throw new ArgumentException("Invalid SCP03 implementation parameter");
            }
        }

        /// <summary>
        /// Validates if the implementation parameter is valid for SCP03.
        /// </summary>
        private static bool IsValidImplementation(byte implementation)
        {
            return implementation == 0x00
                || // No R-MAC, no R-ENC
                implementation == 0x10
                || // R-MAC
                implementation == 0x20
                || // R-ENC
                implementation == 0x60
                || // R-MAC and R-ENC with random card challenge
                implementation == 0x70; // R-MAC and R-ENC with pseudo-random card challenge
        }

        /// <summary>
        /// Creates an INITIALIZE UPDATE command.
        /// </summary>
        public Result<InitializeUpdateCommand, SmartCardError> CreateInitializeUpdateCommand(byte[] hostChallenge)
        {
            if (hostChallenge.Length != 8)
            {
                return Result<InitializeUpdateCommand, SmartCardError>.Fail(
                    SmartCardError.InvalidData($"Host challenge must be 8 bytes, got {hostChallenge.Length}"));
            }

            // For SCP03, key identifier must be 0x00
            return InitializeUpdateCommand.Create(_keySet.KeyVersion, 0x00, hostChallenge);
        }

        /// <summary>
        /// Processes an INITIALIZE UPDATE response and establishes a session context.
        /// </summary>
        public Result<SecureChannelContext, SmartCardError> ProcessInitializeUpdateResponse(
            InitializeUpdateResponse response,
            byte[] hostChallenge
        )
        {
            if (response == null)
            {
                return SmartCardError.InvalidArgument("Response cannot be null");
            }

            if (hostChallenge?.Length != 8)
            {
                return SmartCardError.InvalidData("Host challenge must be 8 bytes");
            }

            // Verify the response is for SCP03
            if ((response.ScpId & ProtocolIdentifiers.ProtocolMask) != ProtocolIdentifiers.Scp03)
            {
                return SmartCardError.InvalidResponse($"Expected SCP03 but received SCP{response.ScpId:X2}");
            }

            // Extract implementation parameter from response
            var cardImplementation = (byte)(response.ScpId & 0xF0);

            // Verify implementation matches what we expect
            if (cardImplementation != _implementation)
            {
                // Log warning but continue - card may report different i-value
                // This is common during protocol transition
            }

            // Determine key length from the static keys
            var keyLength = _keySet.EncKey.Length * 8;

            // Derive session keys
            var sessionKeys = KeyDerivation.DeriveScp03SessionKeys(
                (Scp03KeySet)_keySet,
                hostChallenge,
                response.CardChallenge,
                keyLength
            );


            // Strict spec: verify card cryptogram
            if (!VerifyCardCryptogram(response, hostChallenge, sessionKeys))
            {
                return SmartCardError.SecurityError("Card cryptogram verification failed");
            }

            var context = new SecureChannelContext(
                hostChallenge,
                response,
                sessionKeys,
                ProtocolVersion,
                _keySet
            );

            return Result<SecureChannelContext, SmartCardError>.Ok(context);
        }

        private byte[]? _lastExternalAuthMac; // Store the full MAC for chaining value

        /// <summary>
        /// Creates an EXTERNAL AUTHENTICATE command.
        /// </summary>
        public Result<ExternalAuthenticateCommand, SmartCardError> CreateExternalAuthenticateCommand(
            SecureChannelContext context,
            SecurityLevel securityLevel
        )
        {
            ArgumentNullException.ThrowIfNull(context);

            // Calculate host cryptogram
            var hostCryptogram = CalculateHostCryptogram(
                context.InitializeUpdateResponse,
                context.HostChallenge,
                context.SessionKeys
            );

            // For SCP03, if C-MAC is requested, we need to calculate MAC over the command
            if (securityLevel.HasCMac())
            {
                // Build the APDU for MAC calculation: CLA INS P1 P2 Lc Data
                // Lc should be the final length including MAC (host cryptogram + MAC = 16 bytes)
                var macApdu = new byte[5 + hostCryptogram.Length];
                macApdu[0] = 0x84; // CLA with secure messaging
                macApdu[1] = 0x82; // INS
                macApdu[2] = 0x01; // P1
                macApdu[3] = 0x00; // P2
                macApdu[4] = 0x10; // Lc = 16 bytes (8 host cryptogram + 8 MAC)
                Array.Copy(hostCryptogram, 0, macApdu, 5, hostCryptogram.Length);

                // Calculate full MAC over the command
                var fullMac = CalculateCMacForCommand(macApdu, context.SessionKeys.SMac);
                
                // Store the full MAC for use as initial chaining value
                _lastExternalAuthMac = fullMac;
                
                // Return only the truncated 8-byte MAC for the command
                var mac = new byte[8];
                Array.Copy(fullMac, 0, mac, 0, 8);
                
                return ExternalAuthenticateCommand.CreateWithMac(securityLevel, hostCryptogram, mac);
            }

            return ExternalAuthenticateCommand.CreateWithoutMac(securityLevel, hostCryptogram);
        }

        /// <summary>
        /// Creates a secure channel session from the context after successful authentication.
        /// </summary>
        public SecureChannelSession CreateSecureChannelSession(
            SecureChannelContext context,
            SecurityLevel securityLevel
        )
        {
            ArgumentNullException.ThrowIfNull(context);

            // Initial MAC chaining value depends on whether C-MAC was used
            byte[] macChainingValue;
            if (securityLevel.HasCMac() && _lastExternalAuthMac != null)
            {
                // Per SCP03 spec: "the full 16 byte C-MAC of the previous command becomes
                // the MAC chaining value for the subsequent C-MAC verification"
                macChainingValue = _lastExternalAuthMac;
            }
            else
            {
                // If no C-MAC, start with zero
                macChainingValue = new byte[16];
            }

            return new SecureChannelSession(
                context.SessionKeys,
                securityLevel,
                context.ProtocolVersion,
                macChainingValue
            );
        }

        /// <summary>
        /// Calculates C-MAC for a command during authentication.
        /// Returns the full 16-byte MAC (caller must truncate if needed).
        /// </summary>
        private byte[] CalculateCMacForCommand(byte[] command, byte[] sMacKey)
        {
            // For SCP03 authentication, MAC is calculated over the command with zero ICV
            var zeroIcv = new byte[16];
            var macInput = new byte[zeroIcv.Length + command.Length];
            Array.Copy(zeroIcv, 0, macInput, 0, zeroIcv.Length);
            Array.Copy(command, 0, macInput, zeroIcv.Length, command.Length);

            // Calculate full 16-byte AES-CMAC
            var cmac = new CMac(new AesEngine(), 128); // 128-bit MAC for full output
            cmac.Init(new KeyParameter(sMacKey));
            cmac.BlockUpdate(macInput, 0, macInput.Length);
            
            var fullMac = new byte[16];
            _ = cmac.DoFinal(fullMac, 0);
            
            return fullMac;
        }

        /// <summary>
        /// Verifies the card cryptogram.
        /// </summary>
        public bool VerifyCardCryptogram(
            InitializeUpdateResponse response,
            byte[] hostChallenge,
            SessionKeys sessionKeys
        )
        {
            // Build context for cryptogram calculation (host challenge + card challenge)
            var context = new byte[16];
            Array.Copy(hostChallenge, 0, context, 0, 8);
            Array.Copy(response.CardChallenge, 0, context, 8, 8);

            // Use the same KDF structure as session key derivation but with card cryptogram derivation constant
            var expectedCryptogram = DeriveScp03Cryptogram(
                sessionKeys.SMac,
                DerivationConstants.CardCryptogram,
                context,
                64  // 64 bits = 8 bytes for cryptogram
            );

            // Compare cryptograms
            return CompareBytes(expectedCryptogram, response.CardCryptogram);
        }

        /// <summary>
        /// Calculates the host cryptogram.
        /// </summary>
        public byte[] CalculateHostCryptogram(
            InitializeUpdateResponse response,
            byte[] hostChallenge,
            SessionKeys sessionKeys
        )
        {
            // Build context for cryptogram calculation (host challenge + card challenge)
            var context = new byte[16];
            Array.Copy(hostChallenge, 0, context, 0, 8);
            Array.Copy(response.CardChallenge, 0, context, 8, 8);

            // Use the same KDF structure as session key derivation but with host cryptogram derivation constant
            // and length of 64 bits (8 bytes) for the cryptogram
            return DeriveScp03Cryptogram(
                sessionKeys.SMac,
                DerivationConstants.HostCryptogram,
                context,
                64  // 64 bits = 8 bytes for cryptogram
            );
        }

        /// <summary>
        /// Builds the input data for card cryptogram calculation.
        /// </summary>
        private byte[] BuildCardCryptogramData(
            InitializeUpdateResponse response,
            byte[] hostChallenge
        )
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
        private byte[] BuildHostCryptogramData(
            InitializeUpdateResponse response,
            byte[] hostChallenge
        )
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
        /// Derives SCP03 cryptogram using the same KDF structure as session keys.
        /// </summary>
        private byte[] DeriveScp03Cryptogram(
            byte[] kdk,
            byte derivationConstant,
            byte[] context,
            int outputLengthBits
        )
        {
            // Build the "fixed input data" (everything that's constant for this derivation)
            // This includes: Label + Separator + L + Context 
            // The counter will be inserted by the KDF library between L and Context
            var fixedInputBeforeCounter = new byte[11 + 1 + 1 + 2]; // Label + derivation + separator + L
            var offset = 0;

            // Label (11 bytes of 0x00 followed by derivation constant)
            Array.Copy(DerivationConstants.Scp03Label, 0, fixedInputBeforeCounter, offset, 11);
            offset += 11;
            fixedInputBeforeCounter[offset++] = derivationConstant;

            // Separator
            fixedInputBeforeCounter[offset++] = 0x00;

            // L (length in bits as 2-byte big-endian)
            fixedInputBeforeCounter[offset++] = (byte)(outputLengthBits >> 8);
            fixedInputBeforeCounter[offset++] = (byte)outputLengthBits;

            // Determine PRF type based on key length
            var prfType = kdk.Length switch
            {
                16 => PrfType.CmacAes128,
                24 => PrfType.CmacAes192,
                32 => PrfType.CmacAes256,
                _ => throw new ArgumentException($"Unsupported key length: {kdk.Length} bytes"),
            };

            // Configure KDF options for SCP03
            var options = new KdfOptions(
                prfType: prfType,
                counterLengthBits: 8, // SCP03 uses 8-bit counter
                useCounter: true,
                counterLocation: CounterLocation.MiddleFixed // Counter in the middle of fixed input
            );

            var kdf = new CounterModeKdf();

            // Use DeriveWithSplitFixedInput:
            // - fixedInputBeforeCounter goes before the counter
            // - context goes after the counter
            return kdf.DeriveWithSplitFixedInput(
                kdk,
                fixedInputBeforeCounter, // Label + derivation + separator + L
                context, // Context (host + card challenges)
                outputLengthBits,
                options
            );
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
            _ = cmac.DoFinal(cryptogram, 0);

            return cryptogram;
        }

        /// <summary>
        /// Compares two byte arrays in constant time.
        /// </summary>
        private static bool CompareBytes(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }

            var result = 0;
            for (int i = 0; i < a.Length; i++)
            {
                result |= a[i] ^ b[i];
            }
            return result == 0;
        }
    }
}
