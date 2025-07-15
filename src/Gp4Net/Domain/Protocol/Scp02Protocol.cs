using System;
using System.Linq;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Cryptography.Implementation;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Domain.Protocol
{
    /// <summary>
    /// Implements the SCP02 secure channel protocol.
    /// Supports various implementation options (i=04, i=05, i=15, etc.).
    /// </summary>
    [PublicAPI]
    public class Scp02Protocol : ISecureChannelProtocol
    {
        private readonly IKeySet _keySet;
        private readonly IKeyDerivationService _keyDerivationService;
        private readonly ILogger<Scp02Protocol> _logger;

        /// <inheritdoc />
        public byte ProtocolVersion => ProtocolIdentifiers.Scp02;

        /// <summary>
        /// Initializes a new instance of the Scp02Protocol class.
        /// </summary>
        /// <param name="keySet">The static key set.</param>
        /// <param name="keyDerivationService">The key derivation service.</param>
        /// <param name="logger">The logger.</param>
        public Scp02Protocol(
            IKeySet keySet,
            IKeyDerivationService keyDerivationService,
            ILogger<Scp02Protocol> logger
        )
        {
            ArgumentNullException.ThrowIfNull(keySet);
            ArgumentNullException.ThrowIfNull(keyDerivationService);
            ArgumentNullException.ThrowIfNull(logger);
            _keySet = keySet;
            _keyDerivationService = keyDerivationService;
            _logger = logger;

            // Validate that this is an SCP02-compatible key set
            if (keySet is not Scp02KeySet)
            {
                throw new ArgumentException(
                    "SCP02 protocol requires SCP02 key set",
                    nameof(keySet)
                );
            }
        }

        /// <inheritdoc />
        public Result<InitializeUpdateCommand, SmartCardError> CreateInitializeUpdateCommand(byte[] hostChallenge)
        {
            if (hostChallenge.Length != 8)
            {
                return Result<InitializeUpdateCommand, SmartCardError>.Fail(
                    SmartCardError.InvalidData($"Host challenge must be 8 bytes, got {hostChallenge.Length}"));
            }

            _logger.LogDebug("Creating SCP02 INITIALIZE UPDATE command");

            // For SCP02, key identifier can vary (0x00 is common)
            return InitializeUpdateCommand.Create(_keySet.KeyVersion, 0x00, hostChallenge);
        }

        /// <inheritdoc />
        public SecureChannelContext ProcessInitializeUpdateResponse(
            InitializeUpdateResponse response,
            byte[] hostChallenge
        )
        {
            ArgumentNullException.ThrowIfNull(response);

            if (hostChallenge?.Length != 8)
            {
                throw new ArgumentException(
                    "Host challenge must be 8 bytes.",
                    nameof(hostChallenge)
                );
            }

            // Verify the response is for SCP02
            if ((response.ScpId & ProtocolIdentifiers.ProtocolMask) != ProtocolIdentifiers.Scp02)
            {
                throw new InvalidOperationException(
                    $"Expected SCP02 but received SCP{response.ScpId:X2}"
                );
            }

            _logger.LogDebug(
                "Processing SCP02 INITIALIZE UPDATE response with implementation option i={Option:X2}",
                response.ScpParameter
            );

            // For SCP02, we need the sequence counter from the response
            if (response.SequenceCounter == null)
            {
                throw new InvalidOperationException(
                    "SCP02 requires sequence counter in INITIALIZE UPDATE response"
                );
            }

            // Create key derivation context
            var derivationContext = new KeyDerivationContext(
                protocolVersion: ProtocolVersion,
                keySet: _keySet,
                hostChallenge: hostChallenge,
                cardChallenge: response.CardChallenge,
                sequenceCounter: response.SequenceCounter
            );

            // Derive session keys
            var sessionKeys = _keyDerivationService.DeriveSessionKeys(derivationContext);

            // Verify card cryptogram
            if (!VerifyCardCryptogram(response, hostChallenge, sessionKeys))
            {
                throw new InvalidOperationException("Card cryptogram verification failed.");
            }

            _logger.LogDebug("Successfully processed SCP02 INITIALIZE UPDATE response");

            return new SecureChannelContext(
                hostChallenge,
                response,
                sessionKeys,
                ProtocolVersion,
                _keySet
            );
        }

        /// <inheritdoc />
        public Result<ExternalAuthenticateCommand, SmartCardError> CreateExternalAuthenticateCommand(
            SecureChannelContext context,
            SecurityLevel securityLevel
        )
        {
            ArgumentNullException.ThrowIfNull(context);

            _logger.LogDebug(
                "Creating SCP02 EXTERNAL AUTHENTICATE command with security level {SecurityLevel}",
                securityLevel
            );

            // Calculate host cryptogram
            var hostCryptogram = CalculateHostCryptogram(context);

            // For SCP02, if C-MAC is requested, we need to calculate MAC over the command
            if (securityLevel.HasCMac())
            {
                // Create the command without MAC first to get the APDU structure
                var tempCommandResult = ExternalAuthenticateCommand.CreateWithoutMac(securityLevel, hostCryptogram);
                if (tempCommandResult.IsFailure)
                {
                    return tempCommandResult;
                }
                
                var tempCommand = tempCommandResult.Value;
                var commandApdu = new byte[] { tempCommand.Cla, tempCommand.Ins, tempCommand.P1, tempCommand.P2, (byte)tempCommand.Data!.Length }.Concat(tempCommand.Data!).ToArray();

                // Calculate MAC over the command
                var mac = CalculateCMacForCommand(commandApdu, context.SessionKeys.SMac);
                
                return ExternalAuthenticateCommand.CreateWithMac(securityLevel, hostCryptogram, mac);
            }

            return ExternalAuthenticateCommand.CreateWithoutMac(securityLevel, hostCryptogram);
        }

        /// <inheritdoc />
        public SecureChannelSession CreateSecureChannelSession(
            SecureChannelContext context,
            SecurityLevel securityLevel
        )
        {
            ArgumentNullException.ThrowIfNull(context);

            // For SCP02, MAC chaining value starts with zero ICV
            var macChainingValue = new byte[8]; // 8 bytes for SCP02 (3DES block size)

            _logger.LogDebug(
                "Creating SCP02 secure channel session with security level {SecurityLevel}",
                securityLevel
            );

            return new SecureChannelSession(
                context.SessionKeys,
                securityLevel,
                context.ProtocolVersion,
                macChainingValue
            );
        }

        /// <summary>
        /// Verifies the card cryptogram from the INITIALIZE UPDATE response.
        /// </summary>
        private bool VerifyCardCryptogram(
            InitializeUpdateResponse response,
            byte[] hostChallenge,
            SessionKeys sessionKeys
        )
        {
            // Build card cryptogram data for SCP02
            var cryptogramData = BuildCardCryptogramData(response, hostChallenge);

            // Calculate expected card cryptogram using the appropriate strategy
            var cryptogramContext = new CryptogramContext(
                protocolVersion: ProtocolVersion,
                key: sessionKeys.SMac,
                data: cryptogramData,
                type: CryptogramType.CardCryptogram
            );

            var expectedCryptogram = _keyDerivationService.CalculateCryptogram(cryptogramContext);

            // Compare cryptograms
            return CompareBytes(expectedCryptogram, response.CardCryptogram);
        }

        /// <summary>
        /// Calculates the host cryptogram for EXTERNAL AUTHENTICATE.
        /// </summary>
        private byte[] CalculateHostCryptogram(SecureChannelContext context)
        {
            // Build host cryptogram data for SCP02
            var cryptogramData = BuildHostCryptogramData(
                context.InitializeUpdateResponse,
                context.HostChallenge
            );

            // Calculate host cryptogram using the appropriate strategy
            var cryptogramContext = new CryptogramContext(
                protocolVersion: ProtocolVersion,
                key: context.SessionKeys.SMac,
                data: cryptogramData,
                type: CryptogramType.HostCryptogram
            );

            return _keyDerivationService.CalculateCryptogram(cryptogramContext);
        }

        /// <summary>
        /// Calculates C-MAC for a command during authentication.
        /// </summary>
        private byte[] CalculateCMacForCommand(byte[] command, byte[] sMacKey)
        {
            // For SCP02 authentication, MAC is calculated over the command with zero ICV
            var zeroIcv = new byte[8]; // 8 bytes for SCP02
            var macInput = new byte[zeroIcv.Length + command.Length];
            Array.Copy(zeroIcv, 0, macInput, 0, zeroIcv.Length);
            Array.Copy(command, 0, macInput, zeroIcv.Length, command.Length);

            var cryptogramContext = new CryptogramContext(
                protocolVersion: ProtocolVersion,
                key: sMacKey,
                data: macInput,
                type: CryptogramType.CommandMac
            );

            return _keyDerivationService.CalculateCryptogram(cryptogramContext);
        }

        /// <summary>
        /// Builds the input data for card cryptogram calculation.
        /// For SCP02: Host Challenge || Card Challenge (with appropriate padding).
        /// </summary>
        private byte[] BuildCardCryptogramData(
            InitializeUpdateResponse response,
            byte[] hostChallenge
        )
        {
            var data = new byte[16]; // Host challenge + Card challenge
            Array.Copy(hostChallenge, 0, data, 0, 8);
            Array.Copy(response.CardChallenge, 0, data, 8, 8);

            return data;
        }

        /// <summary>
        /// Builds the input data for host cryptogram calculation.
        /// For SCP02: Card Challenge || Host Challenge (with appropriate padding).
        /// </summary>
        private byte[] BuildHostCryptogramData(
            InitializeUpdateResponse response,
            byte[] hostChallenge
        )
        {
            var data = new byte[16]; // Card challenge + Host challenge
            Array.Copy(response.CardChallenge, 0, data, 0, 8);
            Array.Copy(hostChallenge, 0, data, 8, 8);

            return data;
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
