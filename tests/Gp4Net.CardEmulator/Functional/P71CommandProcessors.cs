using System;
using System.Collections.Generic;
using System.Linq;
using Gp4Net.Core;
using Gp4Net.Constants;
using Gp4Net.CardEmulator.Core;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Functional
{
    /// <summary>
    /// P71-specific command processors based on NXP JCOP4 P71 public specifications.
    /// Implements proprietary commands like IDENTIFY that are specific to P71 cards.
    /// </summary>
    [PublicAPI]
    public static class P71CommandProcessors
    {
        /// <summary>
        /// Processes the P71 IDENTIFY command (80 CA 00 FE) based on FIPS 140-2 documentation.
        /// Returns platform identification data including ROM ID, Platform ID, and FIPS mode status.
        /// </summary>
        public static Result<(ApduResponse, CardState), SmartCardError> ProcessIdentify(
            byte[] command,
            CardState state,
            CardConfiguration config)
        {
            return ParseIdentifyCommand(command)
                .Bind(_ => ValidateIdentifyAccess(state))
                .Map(_ => CreateP71IdentifyResponse(config))
                .Map(response => (response, state)); // State unchanged for IDENTIFY
        }

        /// <summary>
        /// Processes enhanced GET DATA commands with P71-specific data objects.
        /// Extends standard GP GET DATA with P71 proprietary data.
        /// </summary>
        public static Result<(ApduResponse, CardState), SmartCardError> ProcessP71GetData(
            byte[] command,
            CardState state,
            CardConfiguration config)
        {
            return ParseGetDataCommand(command)
                .Bind(tag => ValidateP71DataAccess(tag, state))
                .Bind(tag => RetrieveP71DataObject(tag, config))
                .Map(data => (new ApduResponse(data, StatusWords.SUCCESS), state));
        }

        /// <summary>
        /// Processes P71-specific CPLC data retrieval with enhanced formatting.
        /// </summary>
        public static Result<(ApduResponse, CardState), SmartCardError> ProcessP71Cplc(
            CardState state,
            CardConfiguration config)
        {
            return ValidateCplcAccess(state)
                .Map(_ => CreateP71CplcResponse(config))
                .Map(response => (response, state));
        }

        // Private helper methods

        private static Result<IdentifyRequest, SmartCardError> ParseIdentifyCommand(byte[] command)
        {
            // IDENTIFY command: 80 CA 00 FE 02 DF28 00
            if (command.Length < 7)
                return new Result<IdentifyRequest, SmartCardError>.Failure(SmartCardError.WrongLength());

            if (command[0] != 0x80 || command[1] != 0xCA || 
                command[2] != 0x00 || command[3] != 0xFE)
                return new Result<IdentifyRequest, SmartCardError>.Failure(SmartCardError.InstructionNotSupported());

            if (command[4] != 0x02)
                return new Result<IdentifyRequest, SmartCardError>.Failure(SmartCardError.WrongLength());

            if (command[5] != 0xDF || command[6] != 0x28)
                return new Result<IdentifyRequest, SmartCardError>.Failure(SmartCardError.IncorrectData());

            return new Result<IdentifyRequest, SmartCardError>.Success(new IdentifyRequest());
        }

        private static Result<IdentifyRequest, SmartCardError> ValidateIdentifyAccess(CardState state)
        {
            // IDENTIFY can be called without secure channel or selection
            return new Result<IdentifyRequest, SmartCardError>.Success(new IdentifyRequest());
        }

        private static ApduResponse CreateP71IdentifyResponse(CardConfiguration config)
        {
            var data = new List<byte>();

            // DF28 tag + length (based on FIPS 140-2 spec)
            data.AddRange([0xDF, 0x28, 0x2A]);

            // Platform ID (Tag 03) - from FIPS 140-2 document
            data.AddRange([0x03, 0x20]);
            data.AddRange(Convert.FromHexString("4A335233353130323336333130343030DCE5C19CFE6D0DCF"));

            // ROM ID (Tag 08) - from FIPS 140-2 document  
            data.AddRange([0x08, 0x08]);
            data.AddRange(Convert.FromHexString("2E5AD88409C9BADB"));

            // Patch ID (Tag 02) - from FIPS 140-2 document
            data.AddRange([0x02, 0x08]);
            data.AddRange(Convert.FromHexString("0000000000000001"));

            // FIPS Mode (Tag 05) - from FIPS 140-2 document
            data.AddRange([0x05, 0x01, 0x01]); // 01 = FIPS mode active

            return new ApduResponse(data.ToArray(), StatusWords.SUCCESS);
        }

        private static Result<ushort, SmartCardError> ParseGetDataCommand(byte[] command)
        {
            if (command.Length < 4)
                return new Result<ushort, SmartCardError>.Failure(SmartCardError.WrongLength());

            if (command[0] != 0x80 || command[1] != 0xCA)
                return new Result<ushort, SmartCardError>.Failure(SmartCardError.InstructionNotSupported());

            var tag = (ushort)((command[2] << 8) | command[3]);
            return new Result<ushort, SmartCardError>.Success(tag);
        }

        private static Result<ushort, SmartCardError> ValidateP71DataAccess(ushort tag, CardState state)
        {
            // Most P71 data can be accessed without authentication
            // Some sensitive data might require secure channel
            return tag switch
            {
                0x00E0 when !state.IsSecureChannelEstablished => // Key info requires auth
                    new Result<ushort, SmartCardError>.Failure(SmartCardError.SecurityStatusNotSatisfied()),
                _ => new Result<ushort, SmartCardError>.Success(tag)
            };
        }

        private static Result<byte[], SmartCardError> RetrieveP71DataObject(
            ushort tag,
            CardConfiguration config)
        {
            // Try to get from configuration first
            if (config.DefaultDataObjects.TryGetValue(tag, out var data))
                return new Result<byte[], SmartCardError>.Success(data);

            // Handle P71-specific dynamic data objects
            return tag switch
            {
                0x9F7F => CreateP71CplcData(), // Enhanced CPLC
                0x0067 => CreateP71Capabilities(), // Enhanced capabilities
                0x0066 => CreateP71CardData(), // Enhanced card data
                _ => new Result<byte[], SmartCardError>.Failure(SmartCardError.ReferencedDataNotFound())
            };
        }

        private static Result<byte[], SmartCardError> ValidateCplcAccess(CardState state)
        {
            // CPLC data is usually publicly readable
            return new Result<byte[], SmartCardError>.Success(Array.Empty<byte>());
        }

        private static ApduResponse CreateP71CplcResponse(CardConfiguration config)
        {
            // P71 CPLC data from public traces
            var cplcData = Convert.FromHexString(
                "4790D3214700000000002345558919204839000000000000000018649535383931390000000000000000");
            
            return new ApduResponse(cplcData, StatusWords.SUCCESS);
        }

        private static Result<byte[], SmartCardError> CreateP71CplcData()
        {
            // Enhanced P71 CPLC with proper structure
            var cplcData = new List<byte>();
            
            // IC Fabricator: 4790 (NXP)
            cplcData.AddRange([0x47, 0x90]);
            // IC Type: D321 (P71D321)
            cplcData.AddRange([0xD3, 0x21]);
            // Operating System ID: 4700
            cplcData.AddRange([0x47, 0x00]);
            // Operating System Release Date: 0000 (invalid)
            cplcData.AddRange([0x00, 0x00]);
            // Operating System Release Level: 0000
            cplcData.AddRange([0x00, 0x00]);
            // IC Fabrication Date: 2345 (2022-12-11)
            cplcData.AddRange([0x23, 0x45]);
            // IC Serial Number: 55891920
            cplcData.AddRange([0x55, 0x89, 0x19, 0x20]);
            // IC Batch Identifier: 4839
            cplcData.AddRange([0x48, 0x39]);
            // IC Module Fabricator: 0000
            cplcData.AddRange([0x00, 0x00]);
            // IC Module Packaging Date: 0000
            cplcData.AddRange([0x00, 0x00]);
            // ICC Manufacturer: 0000
            cplcData.AddRange([0x00, 0x00]);
            // IC Embedding Date: 0000
            cplcData.AddRange([0x00, 0x00]);
            // IC Pre-Personalizer: 1864
            cplcData.AddRange([0x18, 0x64]);
            // IC Pre-Personalization Date: 9535
            cplcData.AddRange([0x95, 0x35]);
            // IC Pre-Personalization Equipment ID: 38393139
            cplcData.AddRange([0x38, 0x39, 0x31, 0x39]);
            // IC Personalizer: 0000
            cplcData.AddRange([0x00, 0x00]);
            // IC Personalization Date: 0000
            cplcData.AddRange([0x00, 0x00]);
            // IC Personalization Equipment ID: 00000000
            cplcData.AddRange([0x00, 0x00, 0x00, 0x00]);

            return new Result<byte[], SmartCardError>.Success(cplcData.ToArray());
        }

        private static Result<byte[], SmartCardError> CreateP71Capabilities()
        {
            // P71 capabilities from trace data
            var capabilities = Convert.FromHexString(
                "6728A00D800103810500102060708201078103E5BEC082031E030083010284010285017B86010C87017B");
            return new Result<byte[], SmartCardError>.Success(capabilities);
        }

        private static Result<byte[], SmartCardError> CreateP71CardData()
        {
            // P71 card data from trace data showing GP and JavaCard support
            var cardData = Convert.FromHexString(
                "664D734B06072A864886FC6B01600B06092A864886FC6B020203630906072A864886FC6B03640B06092A864886FC6B040370650D060B2A864886FC6B0507020000660C060A2B060104012A026E0103");
            return new Result<byte[], SmartCardError>.Success(cardData);
        }

        private record IdentifyRequest();
    }
}