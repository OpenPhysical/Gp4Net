using System;
using Gp4Net.Constants;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Keys;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.Domain
{
    /// <summary>
    /// Represents an active secure channel session.
    /// </summary>
    public class SecureChannelSession
    {
        private readonly SessionKeys _sessionKeys;
        private readonly SecurityLevel _securityLevel;
        private readonly byte _protocolVersion;
        private byte[] _macChainingValue;
        private uint _encryptionCounter;
        private readonly object _lock = new object();

        /// <summary>
        /// Gets the session identifier.
        /// </summary>
        public byte[] SessionId { get; }

        /// <summary>
        /// Gets the security level for this session.
        /// </summary>
        public SecurityLevel SecurityLevel => _securityLevel;

        /// <summary>
        /// Gets the protocol version (SCP02 or SCP03).
        /// </summary>
        public byte ProtocolVersion => _protocolVersion;

        /// <summary>
        /// Gets whether this is an SCP03 session.
        /// </summary>
        public bool IsScp03 => _protocolVersion == ProtocolIdentifiers.Scp03;

        /// <summary>
        /// Initializes a new instance of the SecureChannelSession class.
        /// </summary>
        /// <param name="sessionKeys">The session keys.</param>
        /// <param name="securityLevel">The security level.</param>
        /// <param name="protocolVersion">The protocol version.</param>
        /// <param name="macChainingValue">The initial MAC chaining value.</param>
        public SecureChannelSession(
            SessionKeys sessionKeys,
            SecurityLevel securityLevel,
            byte protocolVersion,
            byte[] macChainingValue)
        {
            _sessionKeys = sessionKeys ?? throw new ArgumentNullException(nameof(sessionKeys));
            _securityLevel = securityLevel;
            _protocolVersion = protocolVersion;
            _macChainingValue = macChainingValue ?? throw new ArgumentNullException(nameof(macChainingValue));
            _encryptionCounter = 1;

            // Generate a random session ID
            SessionId = new byte[8];
            new Random().NextBytes(SessionId);
        }

        /// <summary>
        /// Wraps an APDU command with secure messaging.
        /// </summary>
        /// <param name="command">The command APDU to wrap.</param>
        /// <returns>The wrapped command APDU.</returns>
        public byte[] WrapCommand(byte[] command)
        {
            if (command == null || command.Length < 4)
                throw new ArgumentException("Invalid command APDU.", nameof(command));

            lock (_lock)
            {
                var wrappedCommand = new byte[command.Length];
                Array.Copy(command, wrappedCommand, command.Length);

                // Apply encryption if required
                if (_securityLevel.HasCDecryption())
                {
                    wrappedCommand = ApplyEncryption(wrappedCommand);
                }

                // Apply MAC if required
                if (_securityLevel.HasCMac())
                {
                    wrappedCommand = ApplyMac(wrappedCommand);
                }

                return wrappedCommand;
            }
        }

        /// <summary>
        /// Unwraps an APDU response with secure messaging.
        /// </summary>
        /// <param name="response">The response APDU to unwrap.</param>
        /// <returns>The unwrapped response APDU.</returns>
        public byte[] UnwrapResponse(byte[] response)
        {
            if (response == null || response.Length < 2)
                throw new ArgumentException("Invalid response APDU.", nameof(response));

            lock (_lock)
            {
                var unwrappedResponse = new byte[response.Length];
                Array.Copy(response, unwrappedResponse, response.Length);

                // Verify and remove R-MAC if required
                if (_securityLevel.HasRMac())
                {
                    unwrappedResponse = VerifyAndRemoveRMac(unwrappedResponse);
                }

                // Decrypt if required
                if (_securityLevel.HasREncryption())
                {
                    unwrappedResponse = DecryptResponse(unwrappedResponse);
                }

                return unwrappedResponse;
            }
        }

        /// <summary>
        /// Applies encryption to the command data.
        /// </summary>
        private byte[] ApplyEncryption(byte[] command)
        {
            if (command.Length <= 5) // No data to encrypt
                return command;

            var lc = command[4];
            if (lc == 0 || command.Length < 5 + lc)
                return command;

            // Extract data to encrypt
            var dataToEncrypt = new byte[lc];
            Array.Copy(command, 5, dataToEncrypt, 0, lc);

            // Pad data
            var paddedData = Iso7816Padding.AddPadding(dataToEncrypt, 16);

            // Encrypt
            byte[] encryptedData;
            if (IsScp03)
            {
                encryptedData = EncryptAesCbc(paddedData);
            }
            else
            {
                encryptedData = Encrypt3DesCbc(paddedData);
            }

            // Build new command
            var newCommand = new byte[5 + encryptedData.Length + (command.Length > 5 + lc ? 1 : 0)];
            Array.Copy(command, 0, newCommand, 0, 4);
            newCommand[4] = (byte)(encryptedData.Length + 8); // New Lc includes C-MAC
            Array.Copy(encryptedData, 0, newCommand, 5, encryptedData.Length);

            // Copy Le if present
            if (command.Length > 5 + lc)
            {
                newCommand[newCommand.Length - 1] = command[command.Length - 1];
            }

            return newCommand;
        }

        /// <summary>
        /// Applies MAC to the command.
        /// </summary>
        private byte[] ApplyMac(byte[] command)
        {
            // Calculate C-MAC
            var mac = CalculateCMac(command);

            // Append MAC to command
            var macCommand = new byte[command.Length + 8];
            Array.Copy(command, 0, macCommand, 0, command.Length);
            Array.Copy(mac, 0, macCommand, command.Length, 8);

            // Update Lc
            if (macCommand[4] != 0)
            {
                macCommand[4] = (byte)(macCommand[4] + 8);
            }

            return macCommand;
        }

        /// <summary>
        /// Calculates C-MAC for a command.
        /// </summary>
        private byte[] CalculateCMac(byte[] command)
        {
            // Build MAC input
            var macInput = new byte[_macChainingValue.Length + command.Length];
            Array.Copy(_macChainingValue, 0, macInput, 0, _macChainingValue.Length);
            Array.Copy(command, 0, macInput, _macChainingValue.Length, command.Length);

            byte[] mac;
            if (IsScp03)
            {
                var cmac = new CMac(new AesEngine(), 64); // 64-bit MAC
                cmac.Init(new KeyParameter(_sessionKeys.SMac));
                cmac.BlockUpdate(macInput, 0, macInput.Length);
                mac = new byte[8];
                cmac.DoFinal(mac, 0);
            }
            else
            {
                // Use ISO 9797-1 MAC Algorithm 3 for SCP02
                var engine = new DesEdeEngine();
                var desMac = new ISO9797Alg3Mac(engine);
                desMac.Init(new KeyParameter(_sessionKeys.SMac));
                desMac.BlockUpdate(macInput, 0, macInput.Length);
                mac = new byte[8];
                desMac.DoFinal(mac, 0);
            }

            // Update chaining value
            Array.Copy(mac, 0, _macChainingValue, 0, mac.Length);

            return mac;
        }

        private byte[] EncryptAesCbc(byte[] data)
        {
            var cipher = new CbcBlockCipher(new AesEngine());

            // Generate IV for SCP03
            var iv = GenerateEncryptionIv();

            cipher.Init(true, new ParametersWithIV(new KeyParameter(_sessionKeys.SEnc), iv));

            var encrypted = new byte[data.Length];
            for (int i = 0; i < data.Length; i += 16)
            {
                cipher.ProcessBlock(data, i, encrypted, i);
            }

            return encrypted;
        }

        private byte[] Encrypt3DesCbc(byte[] data)
        {
            var cipher = new CbcBlockCipher(new DesEdeEngine());
            var iv = new byte[8]; // Zero IV for SCP02

            cipher.Init(true, new ParametersWithIV(new KeyParameter(_sessionKeys.SEnc), iv));

            var encrypted = new byte[data.Length];
            for (int i = 0; i < data.Length; i += 8)
            {
                cipher.ProcessBlock(data, i, encrypted, i);
            }

            return encrypted;
        }

        private byte[] GenerateEncryptionIv()
        {
            // For SCP03, IV is based on encryption counter
            var iv = new byte[16];

            // Set counter in the last 4 bytes (big-endian)
            iv[12] = (byte)(_encryptionCounter >> 24);
            iv[13] = (byte)(_encryptionCounter >> 16);
            iv[14] = (byte)(_encryptionCounter >> 8);
            iv[15] = (byte)_encryptionCounter;

            _encryptionCounter++;

            return iv;
        }

        private byte[] VerifyAndRemoveRMac(byte[] response)
        {
            if (response.Length < 10) // Minimum: 2 status bytes + 8 MAC bytes
                throw new InvalidOperationException("Response too short for R-MAC.");

            // Extract R-MAC (last 8 bytes before status)
            var rmacOffset = response.Length - 10;
            var receivedRMac = new byte[8];
            Array.Copy(response, rmacOffset, receivedRMac, 0, 8);

            // Calculate expected R-MAC
            var dataToMac = new byte[rmacOffset + 2];
            Array.Copy(response, 0, dataToMac, 0, rmacOffset);
            Array.Copy(response, response.Length - 2, dataToMac, rmacOffset, 2); // Status bytes

            var expectedRMac = CalculateRMac(dataToMac);

            // Verify R-MAC
            if (!CompareBytes(receivedRMac, expectedRMac))
                throw new InvalidOperationException("R-MAC verification failed.");

            // Remove R-MAC from response
            var result = new byte[response.Length - 8];
            Array.Copy(response, 0, result, 0, rmacOffset);
            Array.Copy(response, response.Length - 2, result, result.Length - 2, 2);

            return result;
        }

        private byte[] CalculateRMac(byte[] data)
        {
            // R-MAC calculation is similar to C-MAC but uses S-RMAC key
            var macInput = new byte[_macChainingValue.Length + data.Length];
            Array.Copy(_macChainingValue, 0, macInput, 0, _macChainingValue.Length);
            Array.Copy(data, 0, macInput, _macChainingValue.Length, data.Length);

            byte[] mac;
            if (IsScp03)
            {
                var cmac = new CMac(new AesEngine(), 64);
                cmac.Init(new KeyParameter(_sessionKeys.SRMac));
                cmac.BlockUpdate(macInput, 0, macInput.Length);
                mac = new byte[8];
                cmac.DoFinal(mac, 0);
            }
            else
            {
                // Use ISO 9797-1 MAC Algorithm 3 for SCP02
                var engine = new DesEdeEngine();
                var desMac = new ISO9797Alg3Mac(engine);
                desMac.Init(new KeyParameter(_sessionKeys.SRMac));
                desMac.BlockUpdate(macInput, 0, macInput.Length);
                mac = new byte[8];
                desMac.DoFinal(mac, 0);
            }

            return mac;
        }

        private byte[] DecryptResponse(byte[] response)
        {
            // TODO: Implement response decryption
            return response;
        }

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
