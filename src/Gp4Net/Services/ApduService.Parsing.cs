using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Security;
using static Gp4Net.Constants.Constants;

namespace Gp4Net.Services;

public static partial class ApduService
{
    /// <summary>
    /// APDU parsing operations consolidating ApduParser + Command parsing logic.
    /// All methods are functionally pure and return Result&lt;T, SmartCardError&gt;.
    /// </summary>
    public static class Parsing
    {
        /// <summary>
        /// Parsed APDU command with all components extracted.
        /// Immutable record replacing multiple parsing result types.
        /// </summary>
        public sealed record ParsedCommand(
            byte Cla,
            byte Ins,
            byte P1,
            byte P2,
            byte[] Data,
            Maybe<int> ExpectedLength,
            byte[] FullCommand
        )
        {
            /// <summary>
            /// Gets whether this is a SELECT command (INS=A4).
            /// </summary>
            public bool IsSelect => Ins == Apdu.Instructions.Select;

            /// <summary>
            /// Gets whether this is an INITIALIZE UPDATE command.
            /// </summary>
            public bool IsInitializeUpdate => Ins == GlobalPlatform.Ins.InitializeUpdate;

            /// <summary>
            /// Gets whether this is an EXTERNAL AUTHENTICATE command.
            /// </summary>
            public bool IsExternalAuthenticate => Ins == Apdu.Instructions.ExternalAuthenticate;

            /// <summary>
            /// Gets whether this is a GET STATUS command.
            /// </summary>
            public bool IsGetStatus => Ins == GlobalPlatform.Ins.GetStatus;

            /// <summary>
            /// Gets whether this is a GET DATA command.
            /// </summary>
            public bool IsGetData => Ins == GlobalPlatform.Ins.GetData;

            /// <summary>
            /// Gets whether this is an INSTALL command.
            /// </summary>
            public bool IsInstall => Ins == GlobalPlatform.Ins.Install;

            /// <summary>
            /// Gets whether this is a DELETE command.
            /// </summary>
            public bool IsDelete => Ins == GlobalPlatform.Ins.Delete;

            /// <summary>
            /// Gets whether this is a LOAD command.
            /// </summary>
            public bool IsLoad => Ins == GlobalPlatform.Ins.Load;

            /// <summary>
            /// Gets whether this uses extended length encoding.
            /// </summary>
            public bool IsExtendedLength => Data.Length > 255 || 
                ExpectedLength.Match(len => len > 255, () => false);
        }

        /// <summary>
        /// Parses raw APDU command bytes into structured components.
        /// Validates ISO 7816-4 format and extracts all fields.
        /// </summary>
        /// <param name="commandBytes">Raw command bytes (minimum 4 bytes).</param>
        /// <returns>Parsed command with all components, or error.</returns>
        public static Result<ParsedCommand, SmartCardError> ParseCommand(byte[] commandBytes)
        {
            if (commandBytes.Length < 4)
            {
                return Result.Failure<ParsedCommand, SmartCardError>(
                    SmartCardError.InvalidData("APDU command must be at least 4 bytes"));
            }

            byte cla = commandBytes[0];
            byte ins = commandBytes[1];
            byte p1 = commandBytes[2];
            byte p2 = commandBytes[3];

            if (commandBytes.Length == 4)
            {
                // Case 1: No data, no expected response length
                return Result.Success<ParsedCommand, SmartCardError>(new ParsedCommand(
                    cla, ins, p1, p2, 
                    Data: [],
                    ExpectedLength: Maybe<int>.None,
                    FullCommand: commandBytes
                ));
            }

            if (commandBytes.Length == 5)
            {
                // Case 2: No data, expected response length specified
                byte le = commandBytes[4];
                int expectedLength = le == 0 ? 256 : le;
                
                return Result.Success<ParsedCommand, SmartCardError>(new ParsedCommand(
                    cla, ins, p1, p2,
                    Data: [],
                    ExpectedLength: Maybe<int>.From(expectedLength),
                    FullCommand: commandBytes
                ));
            }

            // Case 3 & 4: Command contains data
            return ParseCommandWithData(cla, ins, p1, p2, commandBytes);
        }

        private static Result<ParsedCommand, SmartCardError> ParseCommandWithData(
            byte cla, byte ins, byte p1, byte p2, byte[] commandBytes)
        {
            byte lc = commandBytes[4];
            
            if (lc == 0)
            {
                // Extended length format
                return ParseExtendedLengthCommand(cla, ins, p1, p2, commandBytes);
            }

            // Short length format
            if (commandBytes.Length < 5 + lc)
            {
                return Result.Failure<ParsedCommand, SmartCardError>(
                    SmartCardError.InvalidData("Command length inconsistent with Lc field"));
            }

            byte[] data = new byte[lc];
            Array.Copy(commandBytes, 5, data, 0, lc);

            Maybe<int> expectedLength = Maybe<int>.None;
            if (commandBytes.Length == 5 + lc + 1)
            {
                // Case 4: Data + expected response length
                byte le = commandBytes[5 + lc];
                expectedLength = Maybe<int>.From(le == 0 ? 256 : le);
            }

            return Result.Success<ParsedCommand, SmartCardError>(new ParsedCommand(
                cla, ins, p1, p2,
                Data: data,
                ExpectedLength: expectedLength,
                FullCommand: commandBytes
            ));
        }

        private static Result<ParsedCommand, SmartCardError> ParseExtendedLengthCommand(
            byte cla, byte ins, byte p1, byte p2, byte[] commandBytes)
        {
            if (commandBytes.Length < 7)
            {
                return Result.Failure<ParsedCommand, SmartCardError>(
                    SmartCardError.InvalidData("Extended length command too short"));
            }

            int dataLength = (commandBytes[5] << 8) | commandBytes[6];
            
            if (commandBytes.Length < 7 + dataLength)
            {
                return Result.Failure<ParsedCommand, SmartCardError>(
                    SmartCardError.InvalidData("Extended length command data incomplete"));
            }

            byte[] data = new byte[dataLength];
            if (dataLength > 0)
            {
                Array.Copy(commandBytes, 7, data, 0, dataLength);
            }

            Maybe<int> expectedLength = Maybe<int>.None;
            if (commandBytes.Length == 7 + dataLength + 2)
            {
                // Extended expected length
                int le = (commandBytes[7 + dataLength] << 8) | commandBytes[7 + dataLength + 1];
                expectedLength = Maybe<int>.From(le == 0 ? 65536 : le);
            }

            return Result.Success<ParsedCommand, SmartCardError>(new ParsedCommand(
                cla, ins, p1, p2,
                Data: data,
                ExpectedLength: expectedLength,
                FullCommand: commandBytes
            ));
        }

        /// <summary>
        /// Parses secured command APDU to extract components for SCP processing.
        /// Consolidates logic from ApduParser.ParseSecuredCommand.
        /// </summary>
        /// <param name="securedCommand">Secured command bytes.</param>
        /// <returns>Parsed secured command or error.</returns>
        public static Result<ParsedSecuredCommand, SmartCardError> ParseSecuredCommand(byte[] securedCommand)
        {
            return ApduParser.ParseSecuredCommand(securedCommand);
        }

        /// <summary>
        /// Builds original command from parsed secured command components.
        /// Used in SCP processing to reconstruct unprotected commands.
        /// </summary>
        /// <param name="parsedSecured">Parsed secured command.</param>
        /// <returns>Original command bytes or error.</returns>
        public static Result<byte[], SmartCardError> BuildOriginalCommand(ParsedSecuredCommand parsedSecured)
        {
            return Result.Try(() => ApduParser.BuildOriginalCommand(
                parsedSecured.Cla,
                parsedSecured.Ins,
                parsedSecured.P1,
                parsedSecured.P2,
                parsedSecured.Data,
                parsedSecured.Le
            ), ex => SmartCardError.UnexpectedError($"Failed to build original command: {ex.Message}"));
        }
    }
}