using System;
using System.Linq;
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
                .Bind(request => GenerateCardChallengeForRequest(request, crypto))
                .Bind(data => CalculateInitializeUpdateCryptogram(data, state, config, crypto))
                .Map(result => CreateInitializeUpdateResult(result, state));
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
                .Map(data => (new ApduResponse(data, StatusWords.SUCCESS), state));
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
                .Map(data => (new ApduResponse(data, StatusWords.SUCCESS), state));
        }

        // Helper methods for command parsing and validation

        private static Result<byte[], SmartCardError> ParseSelectCommand(byte[] command)
        {
            if (command.Length < 4)
                return new Result<byte[], SmartCardError>.Failure(SmartCardError.WrongLength());

            if (command[0] != 0x00 || command[1] != 0xA4)
                return new Result<byte[], SmartCardError>.Failure(SmartCardError.InstructionNotSupported());

            // Handle SELECT with no data (select by default)
            if (command.Length == 4)
                return new Result<byte[], SmartCardError>.Success(Array.Empty<byte>());

            if (command.Length < 5)
                return new Result<byte[], SmartCardError>.Failure(SmartCardError.WrongLength());

            var lc = command[4];
            if (command.Length != 5 + lc)
                return new Result<byte[], SmartCardError>.Failure(SmartCardError.WrongLength());

            var aid = command.Skip(5).Take(lc).ToArray();
            return new Result<byte[], SmartCardError>.Success(aid);
        }

        private static Result<byte[], SmartCardError> ValidateSelectAid(byte[] aid, CardConfiguration config)
        {
            // Empty AID means select default (ISD)
            if (aid.Length == 0)
                return new Result<byte[], SmartCardError>.Success(config.IsdAid);

            // Check if it's the ISD AID
            if (aid.SequenceEqual(config.IsdAid))
                return new Result<byte[], SmartCardError>.Success(aid);

            // For now, only support ISD selection
            return new Result<byte[], SmartCardError>.Failure(SmartCardError.FileNotFound());
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
            return new ApduResponse(fciData, StatusWords.SUCCESS);
        }

        private static Result<InitializeUpdateRequest, SmartCardError> ParseInitializeUpdateCommand(byte[] command)
        {
            if (command.Length < 13) // CLA INS P1 P2 LC + 8 bytes challenge
                return new Result<InitializeUpdateRequest, SmartCardError>.Failure(SmartCardError.WrongLength());

            if (command[0] != 0x80 || command[1] != 0x50)
                return new Result<InitializeUpdateRequest, SmartCardError>.Failure(SmartCardError.InstructionNotSupported());

            var keyVersion = command[2];
            var keyIdentifier = command[3];
            var lc = command[4];

            if (lc != 8 || command.Length != 13)
                return new Result<InitializeUpdateRequest, SmartCardError>.Failure(SmartCardError.WrongLength());

            var hostChallenge = command.Skip(5).Take(8).ToArray();

            return new Result<InitializeUpdateRequest, SmartCardError>.Success(
                new InitializeUpdateRequest(keyVersion, keyIdentifier, hostChallenge));
        }

        private static Result<InitializeUpdateRequest, SmartCardError> ValidateInitializeUpdatePreconditions(
            InitializeUpdateRequest request, 
            CardState state)
        {
            if (!state.IsSelected)
                return new Result<InitializeUpdateRequest, SmartCardError>.Failure(
                    SmartCardError.ConditionsNotSatisfied());

            return new Result<InitializeUpdateRequest, SmartCardError>.Success(request);
        }

        private static Result<(InitializeUpdateRequest, byte[]), SmartCardError> GenerateCardChallengeForRequest(
            InitializeUpdateRequest request,
            ICryptographicService crypto)
        {
            return crypto.GenerateChallenge(8)
                .Map(challenge => (request, challenge));
        }

        private static Result<InitializeUpdateData, SmartCardError> CalculateInitializeUpdateCryptogram(
            (InitializeUpdateRequest request, byte[] cardChallenge) data,
            CardState state,
            CardConfiguration config,
            ICryptographicService crypto)
        {
            var (request, cardChallenge) = data;

            // Get the appropriate keys
            if (!config.StaticKeys.TryGetValue(request.KeyVersion, out var keys))
            {
                keys = config.StaticKeys.Values.FirstOrDefault();
                if (keys == null)
                    return new Result<InitializeUpdateData, SmartCardError>.Failure(
                        SmartCardError.ReferencedDataNotFound());
            }

            return crypto.CalculateCardCryptogram(
                    request.HostChallenge, 
                    cardChallenge, 
                    keys, 
                    state.ScpVersion)
                .Map(cryptogram => new InitializeUpdateData(
                    request.KeyVersion,
                    state.ScpVersion,
                    state.ScpImplementation,
                    cardChallenge,
                    cryptogram,
                    request.HostChallenge,
                    keys));
        }

        private static (ApduResponse, CardState) CreateInitializeUpdateResult(
            InitializeUpdateData data,
            CardState state)
        {
            // Build INITIALIZE UPDATE response
            var response = new byte[32]; // Typical SCP response length
            var offset = 0;

            // Key diversification data (10 bytes)
            Array.Fill<byte>(response, 0x00, offset, 10);
            offset += 10;

            // Key information (3 bytes)
            response[offset++] = data.KeyVersion;
            response[offset++] = data.ScpVersion;
            response[offset++] = data.ScpImplementation;

            // Card challenge (8 bytes)
            Array.Copy(data.CardChallenge, 0, response, offset, 8);
            offset += 8;

            // Card cryptogram (8 bytes)
            Array.Copy(data.CardCryptogram, 0, response, offset, 8);
            offset += 8;

            // Sequence counter for SCP03 (3 bytes)
            if (data.ScpVersion == 0x03)
            {
                response[offset++] = 0x00;
                response[offset++] = 0x00;
                response[offset++] = 0x00;
            }

            var actualResponse = new byte[offset];
            Array.Copy(response, actualResponse, offset);

            var newState = state
                .WithChallenges(data.HostChallenge, data.CardChallenge)
                .WithKeys(data.Keys);

            return (new ApduResponse(actualResponse, StatusWords.SUCCESS), newState);
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

        // Placeholder implementations for other commands
        private static Result<ExternalAuthenticateRequest, SmartCardError> ParseExternalAuthenticateCommand(byte[] command) =>
            new Result<ExternalAuthenticateRequest, SmartCardError>.Failure(SmartCardError.InstructionNotSupported());

        private static Result<ExternalAuthenticateRequest, SmartCardError> ValidateExternalAuthenticatePreconditions(
            ExternalAuthenticateRequest request, CardState state) =>
            new Result<ExternalAuthenticateRequest, SmartCardError>.Failure(SmartCardError.InstructionNotSupported());

        private static Result<ExternalAuthenticateRequest, SmartCardError> VerifyHostCryptogram(
            ExternalAuthenticateRequest request, CardState state, CardConfiguration config, ICryptographicService crypto) =>
            new Result<ExternalAuthenticateRequest, SmartCardError>.Failure(SmartCardError.InstructionNotSupported());

        private static Result<SessionKeys, SmartCardError> DeriveSessionKeys(
            ExternalAuthenticateRequest request, CardState state, CardConfiguration config, ICryptographicService crypto) =>
            new Result<SessionKeys, SmartCardError>.Failure(SmartCardError.InstructionNotSupported());

        private static (ApduResponse, CardState) CreateExternalAuthenticateResult(
            SessionKeys sessionKeys, CardState state) =>
            (new ApduResponse(Array.Empty<byte>(), StatusWords.SUCCESS), state);

        private static Result<ushort, SmartCardError> ParseGetDataCommand(byte[] command) =>
            new Result<ushort, SmartCardError>.Failure(SmartCardError.InstructionNotSupported());

        private static Result<ushort, SmartCardError> ValidateGetDataAccess(ushort tag, CardState state) =>
            new Result<ushort, SmartCardError>.Failure(SmartCardError.InstructionNotSupported());

        private static Result<byte[], SmartCardError> RetrieveDataObject(
            ushort tag, CardState state, CardConfiguration config) =>
            new Result<byte[], SmartCardError>.Failure(SmartCardError.InstructionNotSupported());

        private static Result<GetStatusRequest, SmartCardError> ParseGetStatusCommand(byte[] command) =>
            new Result<GetStatusRequest, SmartCardError>.Failure(SmartCardError.InstructionNotSupported());

        private static Result<GetStatusRequest, SmartCardError> ValidateGetStatusAccess(
            GetStatusRequest request, CardState state) =>
            new Result<GetStatusRequest, SmartCardError>.Failure(SmartCardError.InstructionNotSupported());

        private static Result<byte[], SmartCardError> RetrieveStatusData(
            GetStatusRequest request, CardState state, CardConfiguration config) =>
            new Result<byte[], SmartCardError>.Failure(SmartCardError.InstructionNotSupported());

        private record ExternalAuthenticateRequest();
        private record GetStatusRequest();
    }
}