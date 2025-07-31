using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Constants;
using Gp4Net.CardEmulator.Core;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Functional
{
    /// <summary>
    /// Pure functional command processors that transform card state.
    /// Each processor is a pure function: (command, state, config, services) -> Result&lt;(response, newState)&gt;
    /// </summary>
    [PublicAPI]
    public static class CommandProcessors
    {
        /// <summary>
        /// Processes a SELECT command to select the ISD or an application.
        /// </summary>
        public static Result<(ApduResponse, CardState), SmartCardError> ProcessSelect(
            byte[] command,
            CardState state,
            CardConfiguration config)
        {
            return ParseSelectCommand(command)
                .Bind(aid => ValidateSelectAid(aid, config))
                .Map(aid => CreateSelectResponse(aid, config))
                .Map(response => (response, state.WithSelected(true)));
        }

        /// <summary>
        /// Processes an INITIALIZE UPDATE command to start secure channel establishment.
        /// </summary>
        public static Result<(ApduResponse, CardState), SmartCardError> ProcessInitializeUpdate(
            byte[] command,
            CardState state,
            CardConfiguration config,
            ICryptographicService crypto)
        {
            return ParseInitializeUpdateCommand(command)
                .Bind(request => ValidateInitializeUpdatePreconditions(request, state))
                .Bind(request => GenerateCardChallengeForRequest(request, state, config, crypto))
                .Bind(data => CalculateInitializeUpdateCryptogram(data, state, config, crypto))
                .Map(result => CreateInitializeUpdateResult(result, state, config));
        }

        /// <summary>
        /// Processes an EXTERNAL AUTHENTICATE command to complete secure channel establishment.
        /// </summary>
        public static Result<(ApduResponse, CardState), SmartCardError> ProcessExternalAuthenticate(
            byte[] command,
            CardState state,
            CardConfiguration config,
            ICryptographicService crypto)
        {
            return ParseExternalAuthenticateCommand(command)
                .Bind(request => ValidateExternalAuthenticatePreconditions(request, state))
                .Bind(request => VerifyHostCryptogram(request, state, config, crypto))
                .Bind(request => DeriveSessionKeys(request, state, config, crypto))
                .Map(sessionKeys => CreateExternalAuthenticateResult(sessionKeys, state));
        }

        /// <summary>
        /// Processes a GET DATA command to retrieve card data objects.
        /// </summary>
        public static Result<(ApduResponse, CardState), SmartCardError> ProcessGetData(
            byte[] command,
            CardState state,
            CardConfiguration config)
        {
            return ParseGetDataCommand(command)
                .Bind(tag => ValidateGetDataAccess(tag, state))
                .Bind(tag => RetrieveDataObject(tag, state, config))
                .Map(data => (new ApduResponse(data, StatusWords.Success), state));
        }

        /// <summary>
        /// Processes a GET STATUS command to retrieve application/load file status.
        /// </summary>
        public static Result<(ApduResponse, CardState), SmartCardError> ProcessGetStatus(
            byte[] command,
            CardState state,
            CardConfiguration config)
        {
            return ParseGetStatusCommand(command)
                .Bind(request => ValidateGetStatusAccess(request, state))
                .Bind(request => RetrieveStatusData(request, state, config))
                .Map(data => (new ApduResponse(data, StatusWords.Success), state));
        }

        // Helper methods for command parsing and validation

        private static Result<byte[], SmartCardError> ParseSelectCommand(byte[] command)
        {
            if (command.Length < 4)
                return Result.Failure<byte[], SmartCardError>(SmartCardError.WrongLength());

            if (command[0] != 0x00 || command[1] != 0xA4)
                return Result.Failure<byte[], SmartCardError>(SmartCardError.InstructionNotSupported());

            // Handle SELECT with no data (select by default)
            if (command.Length == 4)
                return Result.Success<byte[], SmartCardError>(Array.Empty<byte>());

            if (command.Length < 5)
                return Result.Failure<byte[], SmartCardError>(SmartCardError.WrongLength());

            var lc = command[4];
            if (command.Length != 5 + lc)
                return Result.Failure<byte[], SmartCardError>(SmartCardError.WrongLength());

            var aid = command.Skip(5).Take(lc).ToArray();
            return Result.Success<byte[], SmartCardError>(aid);
        }

        private static Result<byte[], SmartCardError> ValidateSelectAid(byte[] aid, CardConfiguration config)
        {
            // Empty AID means select default (ISD)
            if (aid.Length == 0)
                return Result.Success<byte[], SmartCardError>(config.IsdAid);

            // Check if it's the ISD AID
            if (aid.SequenceEqual(config.IsdAid))
                return Result.Success<byte[], SmartCardError>(aid);

            // For now, only support ISD selection
            return Result.Failure<byte[], SmartCardError>(SmartCardError.FileNotFound());
        }

        private static ApduResponse CreateSelectResponse(byte[] aid, CardConfiguration config)
        {
            // Return FCI template for ISD
            var fciData = new byte[]
            {
                0x6F, 0x10, // FCI Template
                0x84, 0x08, // DF Name
                0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00, // ISD AID
                0xA5, 0x04, // FCI Proprietary Template
                0x9F, 0x65, 0x01, 0x00 // Maximum length of data field in command message
            };
            return new ApduResponse(fciData, StatusWords.Success);
        }

        private static Result<InitializeUpdateRequest, SmartCardError> ParseInitializeUpdateCommand(byte[] command)
        {
            if (command.Length < 13) // CLA INS P1 P2 LC + 8 bytes challenge
                return Result.Failure<InitializeUpdateRequest, SmartCardError>(SmartCardError.WrongLength());

            if (command[0] != 0x80 || command[1] != 0x50)
                return Result.Failure<InitializeUpdateRequest, SmartCardError>(SmartCardError.InstructionNotSupported());

            var keyVersion = command[2];
            var keyIdentifier = command[3];
            var lc = command[4];

            if (lc != 8 || command.Length != 13)
                return Result.Failure<InitializeUpdateRequest, SmartCardError>(SmartCardError.WrongLength());

            var hostChallenge = command.Skip(5).Take(8).ToArray();

            return Result.Success<InitializeUpdateRequest, SmartCardError>(
                new InitializeUpdateRequest(keyVersion, keyIdentifier, hostChallenge));
        }

        private static Result<InitializeUpdateRequest, SmartCardError> ValidateInitializeUpdatePreconditions(
            InitializeUpdateRequest request, 
            CardState state)
        {
            if (!state.IsSelected)
                return Result.Failure<InitializeUpdateRequest, SmartCardError>(
                    SmartCardError.ConditionsNotSatisfied());

            return Result.Success<InitializeUpdateRequest, SmartCardError>(request);
        }

        private static Result<(InitializeUpdateRequest, byte[]), SmartCardError> GenerateCardChallengeForRequest(
            InitializeUpdateRequest request,
            CardState state,
            CardConfiguration config,
            ICryptographicService crypto)
        {
            // Check if pseudo-random challenge generation is required (SCP03 i=70)
            if (state.ScpVersion == 0x03 && (state.ScpImplementation & 0xF0) == 0x70)
            {
                // SCP03 i=70: Use pseudo-random challenge generation
                return GeneratePseudoRandomChallenge(request, state, config, crypto);
            }
            else
            {
                // Standard random challenge generation
                return crypto.GenerateChallenge(8)
                    .Map(challenge => (request, challenge));
            }
        }

        private static Result<(InitializeUpdateRequest, byte[]), SmartCardError> GeneratePseudoRandomChallenge(
            InitializeUpdateRequest request,
            CardState state,
            CardConfiguration config,
            ICryptographicService crypto)
        {
            // Get the keyset for the requested key version
            var keySet = state.InstalledKeys.TryGetValue(request.KeyVersion, out var keys) 
                ? keys 
                : config.StaticKeys.TryGetValue(request.KeyVersion, out var staticKeys)
                    ? staticKeys 
                    : config.StaticKeys.Values.FirstOrDefault();

            if (keySet is not Gp4Net.Domain.Keys.Scp03KeySet scp03Keys)
            {
                return SmartCardError.InvalidArgument("SCP03 pseudo-random challenge requires SCP03 keys");
            }

            // Get sequence counter for this key version
            var sequenceCounter = state.GetSequenceCounter(request.KeyVersion);

            // Use the ISD AID for challenge generation
            var aid = config.IsdAid;

            return crypto.GeneratePseudoRandomChallenge(scp03Keys.EncKey, sequenceCounter, aid, 8)
                .Map(challenge => (request, challenge));
        }

        private static Result<InitializeUpdateData, SmartCardError> CalculateInitializeUpdateCryptogram(
            (InitializeUpdateRequest request, byte[] cardChallenge) data,
            CardState state,
            CardConfiguration config,
            ICryptographicService crypto)
        {
            var (request, cardChallenge) = data;

            // Determine the effective key version to use
            var effectiveKeyVersion = request.KeyVersion;
            if (effectiveKeyVersion == 0x00)
            {
                // Use default key version when 0x00 is specified
                effectiveKeyVersion = state.DefaultKeyVersion;
                if (effectiveKeyVersion == 0xFF) // No default set, use first available
                {
                    effectiveKeyVersion = config.StaticKeys.Keys.FirstOrDefault();
                }
            }

            // Get the appropriate keys - check installed keys first, then static keys
            Gp4Net.Domain.Keys.IKeySet? keys = null;
            if (state.InstalledKeys.TryGetValue(effectiveKeyVersion, out var installedKeys))
            {
                keys = installedKeys;
            }
            else if (!config.StaticKeys.TryGetValue(effectiveKeyVersion, out var staticKeys))
            {
                // Not found in either, try to get any available key
                keys = config.StaticKeys.Values.FirstOrDefault();
                if (keys is null)
                    return Result.Failure<InitializeUpdateData, SmartCardError>(
                        SmartCardError.ReferencedDataNotFound());
                effectiveKeyVersion = keys.KeyVersion;
            }
            else
            {
                keys = staticKeys;
            }

            if (keys is null)
                return Result.Failure<InitializeUpdateData, SmartCardError>(
                    SmartCardError.ReferencedDataNotFound());

            return crypto.CalculateCardCryptogram(
                    request.HostChallenge, 
                    cardChallenge, 
                    keys, 
                    state.ScpVersion)
                .Map(cryptogram => new InitializeUpdateData(
                    effectiveKeyVersion, // Use the effective key version, not the requested one
                    state.ScpVersion,
                    state.ScpImplementation,
                    cardChallenge,
                    cryptogram,
                    request.HostChallenge,
                    keys));
        }

        private static (ApduResponse, CardState) CreateInitializeUpdateResult(
            InitializeUpdateData data,
            CardState state,
            CardConfiguration config)
        {
            // Build INITIALIZE UPDATE response
            var response = new byte[32]; // Typical SCP response length
            var offset = 0;

            // Key diversification data (10 bytes)
            Array.Fill<byte>(response, 0x00, offset, 10);
            offset += 10;

            // Key information (3 bytes)
            response[offset++] = data.KeyVersion;
            
            // For SCP03, combine version and implementation into single byte
            if (data.ScpVersion == 0x03)
            {
                response[offset++] = (byte)(data.ScpVersion | data.ScpImplementation); // e.g., 0x03 | 0x70 = 0x73
                response[offset++] = 0x00; // Padding for SCP03
            }
            else
            {
                // For SCP02, use separate bytes
                response[offset++] = data.ScpVersion;
                response[offset++] = data.ScpImplementation;
            }

            // Card challenge (8 bytes)
            Array.Copy(data.CardChallenge, 0, response, offset, 8);
            offset += 8;

            // Card cryptogram (8 bytes)
            Array.Copy(data.CardCryptogram, 0, response, offset, 8);
            offset += 8;

            // Sequence counter for SCP03 (3 bytes)
            var newState = state;
            if (data.ScpVersion == 0x03)
            {
                var sequenceCounter = state.GetSequenceCounter(data.KeyVersion);
                Array.Copy(sequenceCounter, 0, response, offset, 3);
                offset += 3;
                
                // Increment sequence counter if pseudo-random challenges are used (i=70)
                if ((data.ScpImplementation & 0xF0) == 0x70)
                {
                    newState = newState.WithIncrementedSequenceCounter(data.KeyVersion);
                }
            }

            var actualResponse = new byte[offset];
            Array.Copy(response, actualResponse, offset);

            newState = newState
                .WithChallenges(data.HostChallenge, data.CardChallenge)
                .WithKeys(data.Keys);

            return (new ApduResponse(actualResponse, StatusWords.Success), newState);
        }

        // Additional helper records for command data
        private record InitializeUpdateRequest(byte KeyVersion, byte KeyIdentifier, byte[] HostChallenge);
        private record InitializeUpdateData(
            byte KeyVersion, 
            byte ScpVersion, 
            byte ScpImplementation,
            byte[] CardChallenge, 
            byte[] CardCryptogram,
            byte[] HostChallenge,
            Gp4Net.Domain.Keys.IKeySet Keys);

        // External Authenticate command implementation
        private static Result<ExternalAuthenticateRequest, SmartCardError> ParseExternalAuthenticateCommand(byte[] command)
        {
            if (command.Length < 5)
                return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(SmartCardError.WrongLength());

            if (command[0] != 0x84 || command[1] != 0x82)
                return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(SmartCardError.InstructionNotSupported());

            var securityLevel = command[2];
            var p2 = command[3];
            var lc = command[4];

            // For SCP02, expect 16 bytes (8 byte cryptogram + 8 byte MAC)
            // For SCP03, expect 16 bytes (8 byte cryptogram + 8 byte MAC)
            if (lc != 16 || command.Length != 21)
                return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(SmartCardError.WrongLength());

            var hostCryptogram = command.Skip(5).Take(8).ToArray();
            var hostMac = command.Skip(13).Take(8).ToArray();

            return Result.Success<ExternalAuthenticateRequest, SmartCardError>(
                new ExternalAuthenticateRequest(securityLevel, hostCryptogram, hostMac));
        }

        private static Result<ExternalAuthenticateRequest, SmartCardError> ValidateExternalAuthenticatePreconditions(
            ExternalAuthenticateRequest request, CardState state)
        {
            if (!state.IsSelected)
                return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                    SmartCardError.ConditionsNotSatisfied());

            if (state.HostChallenge == null || state.CardChallenge == null)
                return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                    SmartCardError.ConditionsNotSatisfied());

            if (state.CurrentKeys == null)
                return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                    SmartCardError.ConditionsNotSatisfied());

            return Result.Success<ExternalAuthenticateRequest, SmartCardError>(request);
        }

        private static Result<ExternalAuthenticateRequest, SmartCardError> VerifyHostCryptogram(
            ExternalAuthenticateRequest request, CardState state, CardConfiguration config, ICryptographicService crypto)
        {
            if (state.HostChallenge == null || state.CardChallenge == null || state.CurrentKeys == null)
                return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                    SmartCardError.ConditionsNotSatisfied());

            return crypto.CalculateHostCryptogram(
                    state.HostChallenge, 
                    state.CardChallenge, 
                    state.CurrentKeys, 
                    state.ScpVersion)
                .Bind(expectedCryptogram => crypto.VerifyCryptogram(request.HostCryptogram, expectedCryptogram))
                .Bind(verified => verified
                    ? Result.Success<ExternalAuthenticateRequest, SmartCardError>(request)
                    : Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                        SmartCardError.SecurityStatusNotSatisfied()));
        }

        private static Result<SessionKeys, SmartCardError> DeriveSessionKeys(
            ExternalAuthenticateRequest request, CardState state, CardConfiguration config, ICryptographicService crypto)
        {
            if (state.HostChallenge == null || state.CardChallenge == null || state.CurrentKeys == null)
                return Result.Failure<SessionKeys, SmartCardError>(
                    SmartCardError.ConditionsNotSatisfied());

            return crypto.DeriveSessionKeys(
                state.CurrentKeys,
                state.HostChallenge,
                state.CardChallenge,
                state.ScpVersion);
        }

        private static (ApduResponse, CardState) CreateExternalAuthenticateResult(
            SessionKeys sessionKeys, CardState state)
        {
            // Update state with established secure channel
            var newState = state.WithSecureChannel(
                established: true,
                sessionKeys: sessionKeys,
                securityLevel: 0x01 // Basic security level
            );

            // EXTERNAL AUTHENTICATE response is typically empty on success
            return (new ApduResponse(Array.Empty<byte>(), StatusWords.Success), newState);
        }

        // Placeholder implementations for other commands
        private static Result<ushort, SmartCardError> ParseGetDataCommand(byte[] command)
        {
            // GET DATA command format: CLA INS P1 P2 [Le]
            // P1P2 contains the tag (2 bytes)
            if (command.Length < 4)
                return Result.Failure<ushort, SmartCardError>(SmartCardError.WrongLength());
            
            var tag = (ushort)((command[2] << 8) | command[3]);
            return Result.Success<ushort, SmartCardError>(tag);
        }

        private static Result<ushort, SmartCardError> ValidateGetDataAccess(ushort tag, CardState state)
        {
            // For now, allow access to all data objects regardless of authentication state
            // In a real implementation, some objects might require secure channel
            return Result.Success<ushort, SmartCardError>(tag);
        }

        private static Result<byte[], SmartCardError> RetrieveDataObject(
            ushort tag, CardState state, CardConfiguration config)
        {
            // Check if this tag exists in the card configuration
            if (config.DefaultDataObjects.TryGetValue(tag, out var data))
            {
                return Result.Success<byte[], SmartCardError>(data);
            }
            
            // Check if this tag exists in the card state
            if (state.DataObjects.TryGetValue(tag, out var stateData))
            {
                return Result.Success<byte[], SmartCardError>(stateData);
            }
            
            return Result.Failure<byte[], SmartCardError>(SmartCardError.ReferencedDataNotFound());
        }

        private static Result<GetStatusRequest, SmartCardError> ParseGetStatusCommand(byte[] command) =>
            Result.Failure<GetStatusRequest, SmartCardError>(SmartCardError.InstructionNotSupported());

        private static Result<GetStatusRequest, SmartCardError> ValidateGetStatusAccess(
            GetStatusRequest request, CardState state) =>
            Result.Failure<GetStatusRequest, SmartCardError>(SmartCardError.InstructionNotSupported());

        private static Result<byte[], SmartCardError> RetrieveStatusData(
            GetStatusRequest request, CardState state, CardConfiguration config) =>
            Result.Failure<byte[], SmartCardError>(SmartCardError.InstructionNotSupported());

        private record ExternalAuthenticateRequest(byte SecurityLevel, byte[] HostCryptogram, byte[] HostMac);
        private record GetStatusRequest();
    }
}