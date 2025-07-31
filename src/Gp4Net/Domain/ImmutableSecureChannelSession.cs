using System;
using System.Security.Cryptography;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Keys;
using Gp4Net.Transport;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.Domain
{
    /// <summary>
    /// Immutable secure channel session that maintains thread safety through immutability.
    /// Each operation returns a new session state rather than mutating existing state.
    /// This ensures thread safety without locks and follows functional programming principles.
    /// </summary>
    public sealed class ImmutableSecureChannelSession
    {
        private readonly SessionKeys _sessionKeys;
        private readonly SecurityLevel _securityLevel;
        private readonly byte _protocolVersion;
        private readonly byte[] _macChainingValue;
        private readonly uint _encryptionCounter;

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
        /// Gets the current MAC chaining value (immutable copy).
        /// </summary>
        public byte[] MacChainingValue => (byte[])_macChainingValue.Clone();

        /// <summary>
        /// Gets the current encryption counter.
        /// </summary>
        public uint EncryptionCounter => _encryptionCounter;

        /// <summary>
        /// Initializes a new instance of the ImmutableSecureChannelSession class.
        /// </summary>
        public ImmutableSecureChannelSession(
            SessionKeys sessionKeys,
            SecurityLevel securityLevel,
            byte protocolVersion,
            byte[] macChainingValue,
            byte[]? sessionId = null,
            uint encryptionCounter = 1)
        {
            ArgumentNullException.ThrowIfNull(sessionKeys);
            ArgumentNullException.ThrowIfNull(macChainingValue);
            
            _sessionKeys = sessionKeys;
            _securityLevel = securityLevel;
            _protocolVersion = protocolVersion;
            _macChainingValue = (byte[])macChainingValue.Clone(); // Defensive copy
            _encryptionCounter = encryptionCounter;

            if (sessionId != null)
            {
                SessionId = (byte[])sessionId.Clone();
            }
            else
            {
                // Generate a cryptographically secure random session ID
                SessionId = new byte[8];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(SessionId);
                }
            }
        }

        /// <summary>
        /// Creates a new session with updated state.
        /// Private helper for immutable updates.
        /// </summary>
        private ImmutableSecureChannelSession With(
            byte[]? macChainingValue = null,
            uint? encryptionCounter = null)
        {
            return new ImmutableSecureChannelSession(
                _sessionKeys,
                _securityLevel,
                _protocolVersion,
                macChainingValue ?? _macChainingValue,
                SessionId,
                encryptionCounter ?? _encryptionCounter);
        }

        /// <summary>
        /// Wraps an APDU command with secure messaging.
        /// Returns both the wrapped command and the new session state.
        /// </summary>
        public Result<(byte[] wrappedData, int? expectedResponseLength, ImmutableSecureChannelSession newSession), SmartCardError> 
            WrapCommand(IApduCommand command)
        {
            if (command == null)
            {
                return Result.Failure<(byte[], int?, ImmutableSecureChannelSession), SmartCardError>(
                    SmartCardError.InvalidArgument("Command cannot be null"));
            }

            try
            {
                // Build command data without Le
                var hasData = command.Data != null && command.Data.Length > 0;
                var commandData = hasData 
                    ? new byte[5 + command.Data!.Length]  // Header + Lc + Data
                    : new byte[4];                        // Header only
                
                commandData[0] = command.Cla;
                commandData[1] = command.Ins;
                commandData[2] = command.P1;
                commandData[3] = command.P2;
                
                if (hasData)
                {
                    commandData[4] = (byte)command.Data!.Length;
                    Array.Copy(command.Data, 0, commandData, 5, command.Data.Length);
                }

                var wrappedCommand = commandData;
                var currentSession = this;

                // Apply encryption if required
                if (_securityLevel.HasCDecryption())
                {
                    var (encryptedCommand, newCounter) = currentSession.ApplyEncryption(wrappedCommand);
                    wrappedCommand = encryptedCommand;
                    currentSession = currentSession.With(encryptionCounter: newCounter);
                }

                // Apply MAC if required
                if (_securityLevel.HasCMac())
                {
                    var (macCommand, newChaining) = currentSession.ApplyMac(wrappedCommand);
                    wrappedCommand = macCommand;
                    currentSession = currentSession.With(macChainingValue: newChaining);
                }

                // Return wrapped data, original Le, and new session state
                return Result.Success<(byte[], int?, ImmutableSecureChannelSession), SmartCardError>(
                    (wrappedCommand, command.ExpectedResponseLength, currentSession));
            }
            catch (InvalidOperationException ex)
            {
                return Result.Failure<(byte[], int?, ImmutableSecureChannelSession), SmartCardError>(
                    SmartCardError.SecurityError($"Failed to wrap command: {ex.Message}"));
            }
            catch (Exception ex)
            {
                return Result.Failure<(byte[], int?, ImmutableSecureChannelSession), SmartCardError>(
                    SmartCardError.UnexpectedError($"Unexpected error wrapping command: {ex.Message}", ex));
            }
        }

        /// <summary>
        /// Unwraps an APDU response with secure messaging.
        /// Returns both the unwrapped response and the new session state.
        /// </summary>
        public Result<(byte[] unwrappedResponse, ImmutableSecureChannelSession newSession), SmartCardError> 
            UnwrapResponse(byte[] response)
        {
            if (response == null || response.Length < 2)
            {
                return Result.Failure<(byte[], ImmutableSecureChannelSession), SmartCardError>(
                    SmartCardError.InvalidArgument("Invalid response APDU"));
            }

            try
            {
                var unwrappedResponse = (byte[])response.Clone();
                var currentSession = this;

                // Verify and remove R-MAC if required
                if (_securityLevel.HasRMac())
                {
                    unwrappedResponse = currentSession.VerifyAndRemoveRMac(unwrappedResponse);
                    // R-MAC doesn't update chaining value
                }

                // Decrypt if required
                if (_securityLevel.HasREncryption())
                {
                    unwrappedResponse = currentSession.DecryptResponse(unwrappedResponse);
                    // Response decryption doesn't update counter in this implementation
                }

                return Result.Success<(byte[], ImmutableSecureChannelSession), SmartCardError>(
                    (unwrappedResponse, currentSession));
            }
            catch (InvalidOperationException ex)
            {
                return Result.Failure<(byte[], ImmutableSecureChannelSession), SmartCardError>(
                    SmartCardError.SecurityError($"Failed to unwrap response: {ex.Message}"));
            }
            catch (Exception ex)
            {
                return Result.Failure<(byte[], ImmutableSecureChannelSession), SmartCardError>(
                    SmartCardError.UnexpectedError($"Unexpected error unwrapping response: {ex.Message}", ex));
            }
        }

        /// <summary>
        /// Applies encryption to the command data.
        /// Returns encrypted command and new encryption counter.
        /// </summary>
        private (byte[] encryptedCommand, uint newCounter) ApplyEncryption(byte[] command)
        {
            if (command.Length <= 5) // No data to encrypt
            {
                return (command, _encryptionCounter);
            }

            var lc = command[4];
            if (lc == 0 || command.Length < 5 + lc)
            {
                return (command, _encryptionCounter);
            }

            // Extract data to encrypt
            var dataToEncrypt = new byte[lc];
            Array.Copy(command, 5, dataToEncrypt, 0, lc);

            // Pad data
            var paddedData = Iso7816Padding.AddPadding(dataToEncrypt, 16);

            // Encrypt with current counter
            byte[] encryptedData;
            uint newCounter = _encryptionCounter;
            
            if (IsScp03)
            {
                encryptedData = EncryptAesCbc(paddedData, ref newCounter);
            }
            else
            {
                encryptedData = Encrypt3DesCbc(paddedData);
            }

            // Build new command
            var newCommand = new byte[5 + encryptedData.Length + (command.Length > 5 + lc ? 1 : 0)];
            Array.Copy(command, 0, newCommand, 0, 4);
            
            // Set secure messaging indicator in CLA byte (bit 2)
            newCommand[0] |= 0x04;
            
            newCommand[4] = (byte)(encryptedData.Length + 8); // New Lc includes C-MAC
            Array.Copy(encryptedData, 0, newCommand, 5, encryptedData.Length);

            // Copy Le if present
            if (command.Length > 5 + lc)
            {
                newCommand[newCommand.Length - 1] = command[command.Length - 1];
            }

            return (newCommand, newCounter);
        }

        /// <summary>
        /// Applies MAC to the command.
        /// Returns MAC'd command and new chaining value.
        /// </summary>
        private (byte[] macCommand, byte[] newChaining) ApplyMac(byte[] command)
        {
            byte[] mac;
            byte[] newChainingValue;

            if (IsScp03)
            {
                // For SCP03, we need to calculate MAC over modified command per GP spec
                var modifiedCommand = CreateScp03MacInput(command);
                (mac, newChainingValue) = CalculateCMac(modifiedCommand);
            }
            else
            {
                // For SCP02, we need to calculate MAC over modified APDU
                var modifiedCommand = CreateScp02MacInput(command);
                (mac, newChainingValue) = CalculateCMac(modifiedCommand);
            }

            // Create new command with MAC appended
            var macCommand = new byte[command.Length + 8];
            Array.Copy(command, 0, macCommand, 0, command.Length);
            Array.Copy(mac, 0, macCommand, command.Length, 8);

            // Set secure messaging indicator in CLA byte (bit 2)
            macCommand[0] |= 0x04;

            // Update Lc - set to original Lc + 8
            if (command.Length > 4)
            {
                var originalLc = command[4];
                macCommand[4] = (byte)(originalLc + 8);
            }

            return (macCommand, newChainingValue);
        }

        /// <summary>
        /// Creates the modified APDU input for SCP03 MAC calculation.
        /// </summary>
        private byte[] CreateScp03MacInput(byte[] command)
        {
            if (command.Length < 5)
            {
                throw new InvalidOperationException("Command too short for SCP03 MAC");
            }

            // Extract header and data
            var ins = command[1];
            var p1 = command[2];
            var p2 = command[3];
            var lc = command[4];

            // Build modified APDU for MAC calculation per GP spec
            var macInput = new byte[5 + (lc > 0 ? lc : 0)];
            macInput[0] = 0x84; // Fixed CLA for MAC calculation
            macInput[1] = ins;
            macInput[2] = p1;
            macInput[3] = p2;
            macInput[4] = (byte)(lc + 8); // Modified Lc for MAC calculation

            // Copy data if present
            if (lc > 0 && command.Length >= 5 + lc)
            {
                Array.Copy(command, 5, macInput, 5, lc);
            }

            return macInput;
        }

        /// <summary>
        /// Creates the modified APDU input for SCP02 MAC calculation.
        /// </summary>
        private byte[] CreateScp02MacInput(byte[] command)
        {
            if (command.Length < 5)
            {
                throw new InvalidOperationException("Command too short for SCP02 MAC");
            }

            // Extract header and Lc
            var cla = command[0];
            var ins = command[1];
            var p1 = command[2];
            var p2 = command[3];
            var lc = command[4];

            // Build modified APDU for MAC calculation
            var macInput = new byte[5 + (lc > 0 ? lc : 0)];
            macInput[0] = cla;
            macInput[1] = ins;
            macInput[2] = p1;
            macInput[3] = p2;
            macInput[4] = (byte)(lc + 8); // Modified Lc for MAC calculation

            // Copy data if present
            if (lc > 0 && command.Length >= 5 + lc)
            {
                Array.Copy(command, 5, macInput, 5, lc);
            }

            return macInput;
        }

        /// <summary>
        /// Calculates C-MAC for a command.
        /// Returns MAC and new chaining value.
        /// </summary>
        private (byte[] mac, byte[] newChaining) CalculateCMac(byte[] command)
        {
            byte[] mac;
            byte[] newChainingValue;

            if (IsScp03)
            {
                // For SCP03, use full MAC chaining value (16 bytes)
                var macInput = new byte[_macChainingValue.Length + command.Length];
                Array.Copy(_macChainingValue, 0, macInput, 0, _macChainingValue.Length);
                Array.Copy(command, 0, macInput, _macChainingValue.Length, command.Length);

                // Calculate full 128-bit AES-CMAC
                var cmac = new CMac(new AesEngine(), 128);
                cmac.Init(new KeyParameter(_sessionKeys.SMac));
                cmac.BlockUpdate(macInput, 0, macInput.Length);
                
                // Get the full 16-byte MAC
                var fullMac = new byte[16];
                _ = cmac.DoFinal(fullMac, 0);

                // Create new chaining value
                newChainingValue = (byte[])fullMac.Clone();
                
                // Return truncated 8-byte MAC for the command
                mac = new byte[8];
                Array.Copy(fullMac, 0, mac, 0, 8);
            }
            else
            {
                // For SCP02, use 8-byte ICV
                var icvLength = Math.Min(_macChainingValue.Length, 8);
                var macInput = new byte[icvLength + command.Length];
                Array.Copy(_macChainingValue, 0, macInput, 0, icvLength);
                Array.Copy(command, 0, macInput, icvLength, command.Length);

                // Use ISO 9797-1 MAC Algorithm 3 for SCP02
                var engine = new DesEdeEngine();
                var desMac = new ISO9797Alg3Mac(engine);
                desMac.Init(new KeyParameter(_sessionKeys.SMac));
                desMac.BlockUpdate(macInput, 0, macInput.Length);
                mac = new byte[8];
                _ = desMac.DoFinal(mac, 0);

                // Create new chaining value
                newChainingValue = (byte[])_macChainingValue.Clone();
                if (newChainingValue.Length >= 8)
                {
                    Array.Copy(mac, 0, newChainingValue, 0, 8);
                }
            }

            return (mac, newChainingValue);
        }

        private byte[] EncryptAesCbc(byte[] data, ref uint counter)
        {
            var cipher = new CbcBlockCipher(new AesEngine());

            // Generate IV for SCP03
            var iv = GenerateEncryptionIv(counter);
            counter++; // Increment for next use

            cipher.Init(true, new ParametersWithIV(new KeyParameter(_sessionKeys.SEnc), iv));

            var encrypted = new byte[data.Length];
            for (int i = 0; i < data.Length; i += 16)
            {
                _ = cipher.ProcessBlock(data, i, encrypted, i);
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
                _ = cipher.ProcessBlock(data, i, encrypted, i);
            }

            return encrypted;
        }

        private byte[] DecryptAesCbc(byte[] data)
        {
            var cipher = new CbcBlockCipher(new AesEngine());

            // Generate IV for SCP03 (same as encryption)
            var iv = GenerateEncryptionIv(_encryptionCounter);

            cipher.Init(false, new ParametersWithIV(new KeyParameter(_sessionKeys.SEnc), iv));

            var decrypted = new byte[data.Length];
            for (int i = 0; i < data.Length; i += 16)
            {
                _ = cipher.ProcessBlock(data, i, decrypted, i);
            }

            return decrypted;
        }

        private byte[] Decrypt3DesCbc(byte[] data)
        {
            var cipher = new CbcBlockCipher(new DesEdeEngine());
            var iv = new byte[8]; // Zero IV for SCP02

            cipher.Init(false, new ParametersWithIV(new KeyParameter(_sessionKeys.SEnc), iv));

            var decrypted = new byte[data.Length];
            for (int i = 0; i < data.Length; i += 8)
            {
                _ = cipher.ProcessBlock(data, i, decrypted, i);
            }

            return decrypted;
        }

        private static byte[] GenerateEncryptionIv(uint counter)
        {
            // For SCP03, IV is based on encryption counter
            var iv = new byte[16];

            // Set counter in the last 4 bytes (big-endian)
            iv[12] = (byte)(counter >> 24);
            iv[13] = (byte)(counter >> 16);
            iv[14] = (byte)(counter >> 8);
            iv[15] = (byte)counter;

            return iv;
        }

        private byte[] VerifyAndRemoveRMac(byte[] response)
        {
            if (response.Length < 10) // Minimum: 2 status bytes + 8 MAC bytes
            {
                throw new InvalidOperationException("Response too short for R-MAC.");
            }

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
            {
                throw new InvalidOperationException("R-MAC verification failed.");
            }

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
                // Calculate full 128-bit AES-CMAC for R-MAC
                var cmac = new CMac(new AesEngine(), 128);
                cmac.Init(new KeyParameter(_sessionKeys.SRMac));
                cmac.BlockUpdate(macInput, 0, macInput.Length);
                
                // Get the full 16-byte MAC
                var fullMac = new byte[16];
                _ = cmac.DoFinal(fullMac, 0);
                
                // Note: R-MAC doesn't update the chaining value
                
                // Return truncated 8-byte MAC
                mac = new byte[8];
                Array.Copy(fullMac, 0, mac, 0, 8);
            }
            else
            {
                // Use ISO 9797-1 MAC Algorithm 3 for SCP02
                var engine = new DesEdeEngine();
                var desMac = new ISO9797Alg3Mac(engine);
                desMac.Init(new KeyParameter(_sessionKeys.SRMac));
                desMac.BlockUpdate(macInput, 0, macInput.Length);
                mac = new byte[8];
                _ = desMac.DoFinal(mac, 0);
            }

            return mac;
        }

        private byte[] DecryptResponse(byte[] response)
        {
            if (response.Length <= 2) // Only status word, no data to decrypt
            {
                return response;
            }

            // Extract data (everything except the last 2 bytes which are status word)
            var statusOffset = response.Length - 2;
            var encryptedData = new byte[statusOffset];
            Array.Copy(response, 0, encryptedData, 0, statusOffset);

            // Decrypt data
            byte[] decryptedData;
            if (IsScp03)
            {
                decryptedData = DecryptAesCbc(encryptedData);
            }
            else
            {
                decryptedData = Decrypt3DesCbc(encryptedData);
            }

            // Remove padding
            var unpaddedData = Iso7816Padding.RemovePadding(decryptedData);

            // Reconstruct response with decrypted data
            var result = new byte[unpaddedData.Length + 2];
            Array.Copy(unpaddedData, 0, result, 0, unpaddedData.Length);
            Array.Copy(response, statusOffset, result, unpaddedData.Length, 2); // Copy status word

            return result;
        }

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