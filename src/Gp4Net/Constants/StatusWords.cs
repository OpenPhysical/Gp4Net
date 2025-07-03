// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using JetBrains.Annotations;

namespace Gp4Net.Constants
{
    /// <summary>
    /// ISO 7816-4 and GlobalPlatform status word constants for APDU responses.
    /// </summary>
    [PublicAPI]
    public static class StatusWords
    {
        /// <summary>
        /// Success - Command completed successfully.
        /// </summary>
        public const ushort SUCCESS = 0x9000;

        /// <summary>
        /// Incorrect data field or parameters in data field.
        /// </summary>
        public const ushort INCORRECT_DATA = 0x6A80;

        /// <summary>
        /// Memory problem or insufficient memory.
        /// </summary>
        public const ushort MEMORY_ERROR = 0x6A84;

        /// <summary>
        /// Conditions of use not satisfied.
        /// </summary>
        public const ushort CONDITIONS_NOT_SATISFIED = 0x6985;

        /// <summary>
        /// Generic failure or internal error.
        /// </summary>
        public const ushort GENERIC_FAILURE = 0x6F00;

        /// <summary>
        /// Wrong length - Le field incorrect.
        /// </summary>
        public const ushort WRONG_LENGTH = 0x6700;

        /// <summary>
        /// Class not supported.
        /// </summary>
        public const ushort CLASS_NOT_SUPPORTED = 0x6E00;

        /// <summary>
        /// Instruction not supported.
        /// </summary>
        public const ushort INSTRUCTION_NOT_SUPPORTED = 0x6D00;

        /// <summary>
        /// Function not supported.
        /// </summary>
        public const ushort FUNCTION_NOT_SUPPORTED = 0x6A81;

        /// <summary>
        /// File not found.
        /// </summary>
        public const ushort FILE_NOT_FOUND = 0x6A82;

        /// <summary>
        /// Record not found.
        /// </summary>
        public const ushort RECORD_NOT_FOUND = 0x6A83;

        /// <summary>
        /// Wrong parameters P1-P2.
        /// </summary>
        public const ushort WRONG_PARAMETERS = 0x6A86;

        /// <summary>
        /// Lc inconsistent with P1-P2.
        /// </summary>
        public const ushort LC_INCONSISTENT = 0x6A87;

        /// <summary>
        /// Referenced data not found.
        /// </summary>
        public const ushort REFERENCED_DATA_NOT_FOUND = 0x6A88;

        /// <summary>
        /// Security status not satisfied.
        /// </summary>
        public const ushort SECURITY_STATUS_NOT_SATISFIED = 0x6982;

        /// <summary>
        /// Authentication method blocked.
        /// </summary>
        public const ushort AUTHENTICATION_METHOD_BLOCKED = 0x6983;

        /// <summary>
        /// Reference data not usable.
        /// </summary>
        public const ushort REFERENCE_DATA_NOT_USABLE = 0x6984;

        /// <summary>
        /// Command not allowed (no current EF).
        /// </summary>
        public const ushort COMMAND_NOT_ALLOWED = 0x6986;

        /// <summary>
        /// Expected secure messaging data objects missing.
        /// </summary>
        public const ushort SECURE_MESSAGING_MISSING = 0x6987;

        /// <summary>
        /// Incorrect secure messaging data objects.
        /// </summary>
        public const ushort SECURE_MESSAGING_INCORRECT = 0x6988;
    }
}
