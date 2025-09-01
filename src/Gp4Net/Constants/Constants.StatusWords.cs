// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.Constants;

public static partial class Constants
{
    /// <summary>
    /// ISO 7816-4 and GlobalPlatform status word constants organized by functional category.
    /// Status words are two-byte values returned in APDU responses indicating command execution results.
    /// 
    /// Organization follows ISO 7816-4 specification sections 5.1.3 and Annex A, plus
    /// GlobalPlatform Card Specification sections covering response processing.
    /// 
    /// Reference: ISO/IEC 7816-4:2020 - Identification cards - Integrated circuit cards - Part 4: Organization, security and commands for interchange
    /// Reference: GlobalPlatform Card Specification v2.3.1 - Section 11.1.1 Response Processing
    /// </summary>
    [PublicAPI]
    public static class StatusWords
    {
        /// <summary>
        /// Success status words indicating normal command completion.
        /// ISO 7816-4 Section 5.1.3 - Process completed
        /// </summary>
        [PublicAPI]
        public static class Success
        {
            /// <summary>
            /// Command completed successfully without errors.
            /// ISO 7816-4: 0x9000 - Normal processing - No error
            /// </summary>
            public static readonly StatusWord Normal = new(0x9000);
        }

        /// <summary>
        /// Information status words providing additional details about successful operations.
        /// ISO 7816-4 Section 5.1.3 - Process completed with information
        /// </summary>
        [PublicAPI]
        public static class Information
        {
            /// <summary>
            /// Command completed successfully but response data may be corrupted.
            /// ISO 7816-4: 0x6200 - Warning - No information given (NV-memory not changed)
            /// </summary>
            public static readonly StatusWord WarningNoInformation = new(0x6200);

            /// <summary>
            /// Command completed successfully but response data part may be corrupted.
            /// ISO 7816-4: 0x6281 - Warning - Part of returned data may be corrupted
            /// </summary>
            public static readonly StatusWord WarningDataCorrupted = new(0x6281);

            /// <summary>
            /// Command completed successfully but end of file reached before reading Le bytes.
            /// ISO 7816-4: 0x6282 - Warning - End of file reached before reading Le bytes
            /// </summary>
            public static readonly StatusWord WarningEndOfFile = new(0x6282);

            /// <summary>
            /// Command completed successfully but selected file deactivated.
            /// ISO 7816-4: 0x6283 - Warning - Selected file deactivated
            /// </summary>
            public static readonly StatusWord WarningFileDeactivated = new(0x6283);

            /// <summary>
            /// Command completed successfully but file control information not formatted according to 5.3.3.
            /// ISO 7816-4: 0x6284 - Warning - FCI not formatted according to 5.3.3
            /// </summary>
            public static readonly StatusWord WarningFciNotFormatted = new(0x6284);

            /// <summary>
            /// Command completed successfully but selected file in termination state.
            /// ISO 7816-4: 0x6285 - Warning - Selected file in termination state
            /// </summary>
            public static readonly StatusWord WarningFileTerminating = new(0x6285);

            /// <summary>
            /// Command completed successfully but no input data available from sensor.
            /// ISO 7816-4: 0x6286 - Warning - No input data available from a sensor on the card
            /// </summary>
            public static readonly StatusWord WarningNoInputData = new(0x6286);
        }

        /// <summary>
        /// Execution error status words indicating problems with command processing.
        /// ISO 7816-4 Section 5.1.3 - Process aborted
        /// </summary>
        [PublicAPI]
        public static class ExecutionErrors
        {
            /// <summary>
            /// Command aborted due to wrong length field.
            /// ISO 7816-4: 0x6700 - Wrong length - No precise diagnosis
            /// </summary>
            public static readonly StatusWord WrongLength = new(0x6700);

            /// <summary>
            /// Logical channel not supported.
            /// ISO 7816-4: 0x6881 - Logical channel not supported
            /// </summary>
            public static readonly StatusWord LogicalChannelNotSupported = new(0x6881);

            /// <summary>
            /// Secure messaging not supported.
            /// ISO 7816-4: 0x6882 - Secure messaging not supported
            /// </summary>
            public static readonly StatusWord SecureMessagingNotSupported = new(0x6882);

            /// <summary>
            /// Last command of the chain expected.
            /// ISO 7816-4: 0x6883 - Last command of the chain expected
            /// </summary>
            public static readonly StatusWord LastCommandExpected = new(0x6883);

            /// <summary>
            /// Command chaining not supported.
            /// ISO 7816-4: 0x6884 - Command chaining not supported
            /// </summary>
            public static readonly StatusWord CommandChainingNotSupported = new(0x6884);
        }

        /// <summary>
        /// Checking error status words indicating problems with command structure.
        /// ISO 7816-4 Section 5.1.3 - Process aborted
        /// </summary>
        [PublicAPI]
        public static class CheckingErrors
        {
            /// <summary>
            /// Command not allowed in current security state.
            /// ISO 7816-4: 0x6982 - Security status not satisfied
            /// </summary>
            public static readonly StatusWord SecurityStatusNotSatisfied = new(0x6982);

            /// <summary>
            /// Authentication method blocked after too many attempts.
            /// ISO 7816-4: 0x6983 - Authentication method blocked
            /// </summary>
            public static readonly StatusWord AuthenticationMethodBlocked = new(0x6983);

            /// <summary>
            /// Reference data not usable (e.g., key blocked).
            /// ISO 7816-4: 0x6984 - Referenced data not usable
            /// </summary>
            public static readonly StatusWord ReferenceDataNotUsable = new(0x6984);

            /// <summary>
            /// Conditions of use not satisfied.
            /// ISO 7816-4: 0x6985 - Conditions of use not satisfied
            /// </summary>
            public static readonly StatusWord ConditionsNotSatisfied = new(0x6985);

            /// <summary>
            /// Command not allowed (no current EF selected).
            /// ISO 7816-4: 0x6986 - Command not allowed (no current EF)
            /// </summary>
            public static readonly StatusWord CommandNotAllowed = new(0x6986);

            /// <summary>
            /// Expected secure messaging data objects missing.
            /// ISO 7816-4: 0x6987 - Expected secure messaging data objects missing
            /// </summary>
            public static readonly StatusWord SecureMessagingMissing = new(0x6987);

            /// <summary>
            /// Incorrect secure messaging data objects.
            /// ISO 7816-4: 0x6988 - Incorrect secure messaging data objects
            /// </summary>
            public static readonly StatusWord SecureMessagingIncorrect = new(0x6988);
        }

        /// <summary>
        /// Functions in CLA not supported error status words.
        /// ISO 7816-4 Section 5.1.3 - Process aborted
        /// </summary>
        [PublicAPI]
        public static class FunctionErrors
        {
            /// <summary>
            /// Function not supported in class byte.
            /// ISO 7816-4: 0x6A81 - Function not supported - Logical channel not supported or is not available
            /// </summary>
            public static readonly StatusWord FunctionNotSupported = new(0x6A81);

            /// <summary>
            /// File or application not found.
            /// ISO 7816-4: 0x6A82 - File or application not found
            /// </summary>
            public static readonly StatusWord FileNotFound = new(0x6A82);

            /// <summary>
            /// Record not found.
            /// ISO 7816-4: 0x6A83 - Record not found
            /// </summary>
            public static readonly StatusWord RecordNotFound = new(0x6A83);

            /// <summary>
            /// Not enough memory space in the file.
            /// ISO 7816-4: 0x6A84 - Not enough memory space in the file
            /// </summary>
            public static readonly StatusWord InsufficientMemory = new(0x6A84);

            /// <summary>
            /// Nc inconsistent with TLV structure.
            /// ISO 7816-4: 0x6A85 - Nc inconsistent with TLV structure
            /// </summary>
            public static readonly StatusWord NcInconsistentTlv = new(0x6A85);

            /// <summary>
            /// Incorrect parameters P1-P2.
            /// ISO 7816-4: 0x6A86 - Incorrect parameters P1-P2
            /// </summary>
            public static readonly StatusWord IncorrectP1P2 = new(0x6A86);

            /// <summary>
            /// Nc inconsistent with parameters P1-P2.
            /// ISO 7816-4: 0x6A87 - Nc inconsistent with parameters P1-P2
            /// </summary>
            public static readonly StatusWord NcInconsistentP1P2 = new(0x6A87);

            /// <summary>
            /// Referenced data or reference data not found.
            /// ISO 7816-4: 0x6A88 - Referenced data or reference data not found
            /// </summary>
            public static readonly StatusWord ReferencedDataNotFound = new(0x6A88);

            /// <summary>
            /// File already exists.
            /// ISO 7816-4: 0x6A89 - File already exists
            /// </summary>
            public static readonly StatusWord FileExists = new(0x6A89);

            /// <summary>
            /// DF name already exists.
            /// ISO 7816-4: 0x6A8A - DF name already exists
            /// </summary>
            public static readonly StatusWord DfNameExists = new(0x6A8A);
        }

        /// <summary>
        /// Wrong parameters error status words indicating invalid data in command.
        /// ISO 7816-4 Section 5.1.3 - Process aborted
        /// </summary>
        [PublicAPI]
        public static class ParameterErrors
        {
            /// <summary>
            /// Wrong parameter(s) P1-P2.
            /// ISO 7816-4: 0x6B00 - Wrong parameter(s) P1-P2
            /// </summary>
            public static readonly StatusWord WrongP1P2 = new(0x6B00);

            /// <summary>
            /// Incorrect data field or parameters in data field.
            /// ISO 7816-4: 0x6A80 - Incorrect parameters in the data field
            /// </summary>
            public static readonly StatusWord IncorrectDataField = new(0x6A80);
        }

        /// <summary>
        /// Instruction error status words indicating unsupported commands.
        /// ISO 7816-4 Section 5.1.3 - Process aborted
        /// </summary>
        [PublicAPI]
        public static class InstructionErrors
        {
            /// <summary>
            /// Instruction code not supported or invalid.
            /// ISO 7816-4: 0x6D00 - Instruction code not supported or invalid
            /// </summary>
            public static readonly StatusWord InstructionNotSupported = new(0x6D00);

            /// <summary>
            /// Class not supported.
            /// ISO 7816-4: 0x6E00 - Class not supported
            /// </summary>
            public static readonly StatusWord ClassNotSupported = new(0x6E00);

            /// <summary>
            /// No precise diagnosis available.
            /// ISO 7816-4: 0x6F00 - No precise diagnosis
            /// </summary>
            public static readonly StatusWord NoPreciseDiagnosis = new(0x6F00);
        }

        /// <summary>
        /// Legacy aliases for backward compatibility.
        /// These delegate to the properly categorized constants above.
        /// </summary>
        [PublicAPI]
        public static class Legacy
        {
            /// <summary>Success - Command completed successfully.</summary>
            public static readonly StatusWord Success = StatusWords.Success.Normal;

            /// <summary>Incorrect data field or parameters in data field.</summary>
            public static readonly StatusWord IncorrectData = ParameterErrors.IncorrectDataField;

            /// <summary>Memory problem or insufficient memory.</summary>
            public static readonly StatusWord MemoryError = FunctionErrors.InsufficientMemory;

            /// <summary>Conditions of use not satisfied.</summary>
            public static readonly StatusWord ConditionsNotSatisfied = CheckingErrors.ConditionsNotSatisfied;

            /// <summary>Generic failure or internal error.</summary>
            public static readonly StatusWord GenericFailure = InstructionErrors.NoPreciseDiagnosis;

            /// <summary>Wrong length - Le field incorrect.</summary>
            public static readonly StatusWord WrongLength = ExecutionErrors.WrongLength;

            /// <summary>Class not supported.</summary>
            public static readonly StatusWord ClassNotSupported = InstructionErrors.ClassNotSupported;

            /// <summary>Instruction not supported.</summary>
            public static readonly StatusWord InstructionNotSupported = InstructionErrors.InstructionNotSupported;

            /// <summary>Function not supported.</summary>
            public static readonly StatusWord FunctionNotSupported = FunctionErrors.FunctionNotSupported;

            /// <summary>File not found.</summary>
            public static readonly StatusWord FileNotFound = FunctionErrors.FileNotFound;

            /// <summary>Record not found.</summary>
            public static readonly StatusWord RecordNotFound = FunctionErrors.RecordNotFound;

            /// <summary>Wrong parameters P1-P2.</summary>
            public static readonly StatusWord WrongParameters = FunctionErrors.IncorrectP1P2;

            /// <summary>Lc inconsistent with P1-P2.</summary>
            public static readonly StatusWord LcInconsistent = FunctionErrors.NcInconsistentP1P2;

            /// <summary>Referenced data not found.</summary>
            public static readonly StatusWord ReferencedDataNotFound = FunctionErrors.ReferencedDataNotFound;

            /// <summary>Security status not satisfied.</summary>
            public static readonly StatusWord SecurityStatusNotSatisfied = CheckingErrors.SecurityStatusNotSatisfied;

            /// <summary>Authentication method blocked.</summary>
            public static readonly StatusWord AuthenticationMethodBlocked = CheckingErrors.AuthenticationMethodBlocked;

            /// <summary>Reference data not usable.</summary>
            public static readonly StatusWord ReferenceDataNotUsable = CheckingErrors.ReferenceDataNotUsable;

            /// <summary>Command not allowed (no current EF).</summary>
            public static readonly StatusWord CommandNotAllowed = CheckingErrors.CommandNotAllowed;

            /// <summary>Expected secure messaging data objects missing.</summary>
            public static readonly StatusWord SecureMessagingMissing = CheckingErrors.SecureMessagingMissing;

            /// <summary>Incorrect secure messaging data objects.</summary>
            public static readonly StatusWord SecureMessagingIncorrect = CheckingErrors.SecureMessagingIncorrect;
        }
    }
}