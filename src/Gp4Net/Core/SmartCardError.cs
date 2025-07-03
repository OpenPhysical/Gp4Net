using System;
using System.Collections.Generic;

namespace Gp4Net.Core
{
    /// <summary>
    /// Represents an error that occurred during smart card operations.
    /// </summary>
    public record SmartCardError(
        string Code,
        string Message,
        ushort? StatusWord = null,
        Exception? InnerException = null,
        IReadOnlyDictionary<string, object>? Context = null)
    {
        /// <summary>
        /// Creates an error from a status word.
        /// </summary>
        public static SmartCardError FromStatusWord(ushort sw) =>
            new(
                Code: $"SW_{sw:X4}",
                Message: GetStatusWordDescription(sw),
                StatusWord: sw
            );

        /// <summary>
        /// Creates an error for a communication failure.
        /// </summary>
        public static SmartCardError CommunicationError(string message, Exception? ex = null) =>
            new(
                Code: "COMM_ERROR",
                Message: message,
                InnerException: ex
            );

        /// <summary>
        /// Creates an error for a security failure.
        /// </summary>
        public static SmartCardError SecurityError(string message, ushort? sw = null) =>
            new(
                Code: "SECURITY_ERROR",
                Message: message,
                StatusWord: sw
            );

        /// <summary>
        /// Creates an error for invalid data.
        /// </summary>
        public static SmartCardError InvalidData(string message) =>
            new(
                Code: "INVALID_DATA",
                Message: message
            );

        /// <summary>
        /// Creates an error for unsupported operations.
        /// </summary>
        public static SmartCardError Unsupported(string message) =>
            new(
                Code: "UNSUPPORTED",
                Message: message
            );

        /// <summary>
        /// Creates an error for invalid response data.
        /// </summary>
        public static SmartCardError InvalidResponse(string message) =>
            new(
                Code: "INVALID_RESPONSE",
                Message: message
            );

        /// <summary>
        /// Creates an error for card-specific errors.
        /// </summary>
        public static SmartCardError CardError(string message) =>
            new(
                Code: "CARD_ERROR",
                Message: message
            );

        /// <summary>
        /// Creates an error for unsupported instructions (6D00).
        /// </summary>
        public static SmartCardError InstructionNotSupported() =>
            new(
                Code: "INSTRUCTION_NOT_SUPPORTED",
                Message: "Invalid instruction",
                StatusWord: 0x6D00
            );

        /// <summary>
        /// Creates an error for wrong length (6700).
        /// </summary>
        public static SmartCardError WrongLength() =>
            new(
                Code: "WRONG_LENGTH",
                Message: "Wrong length",
                StatusWord: 0x6700
            );

        /// <summary>
        /// Creates an error for incorrect data (6A80).
        /// </summary>
        public static SmartCardError IncorrectData() =>
            new(
                Code: "INCORRECT_DATA",
                Message: "Wrong data",
                StatusWord: 0x6A80
            );

        /// <summary>
        /// Creates an error for security status not satisfied (6982).
        /// </summary>
        public static SmartCardError SecurityStatusNotSatisfied() =>
            new(
                Code: "SECURITY_STATUS_NOT_SATISFIED",
                Message: "Security status not satisfied",
                StatusWord: 0x6982
            );

        /// <summary>
        /// Creates an error for referenced data not found (6A88).
        /// </summary>
        public static SmartCardError ReferencedDataNotFound() =>
            new(
                Code: "REFERENCED_DATA_NOT_FOUND",
                Message: "Referenced data not found",
                StatusWord: 0x6A88
            );

        /// <summary>
        /// Creates an error for cryptographic operations.
        /// </summary>
        public static SmartCardError CryptographicError(string message) =>
            new(
                Code: "CRYPTOGRAPHIC_ERROR",
                Message: message
            );

        /// <summary>
        /// Creates an error for file not found (6A82).
        /// </summary>
        public static SmartCardError FileNotFound() =>
            new(
                Code: "FILE_NOT_FOUND",
                Message: "File not found",
                StatusWord: 0x6A82
            );

        /// <summary>
        /// Creates an error for conditions not satisfied (6985).
        /// </summary>
        public static SmartCardError ConditionsNotSatisfied() =>
            new(
                Code: "CONDITIONS_NOT_SATISFIED",
                Message: "Conditions of use not satisfied",
                StatusWord: 0x6985
            );

        /// <summary>
        /// Adds context information to the error.
        /// </summary>
        public SmartCardError WithContext(string key, object value)
        {
            var newContext = new Dictionary<string, object>(Context ?? new Dictionary<string, object>())
            {
                [key] = value
            };
            return this with { Context = newContext };
        }

        /// <summary>
        /// Adds multiple context values to the error.
        /// </summary>
        public SmartCardError WithContext(IReadOnlyDictionary<string, object> additionalContext)
        {
            var newContext = new Dictionary<string, object>(Context ?? new Dictionary<string, object>());
            foreach (var kvp in additionalContext)
            {
                newContext[kvp.Key] = kvp.Value;
            }
            return this with { Context = newContext };
        }

        private static string GetStatusWordDescription(ushort sw) =>
            sw switch
            {
                0x9000 => "Success",
                0x6283 => "Selected file invalidated",
                0x6300 => "Authentication failed",
                0x6581 => "Memory failure",
                0x6700 => "Wrong length",
                0x6881 => "Logical channel not supported",
                0x6982 => "Security status not satisfied",
                0x6983 => "Authentication method blocked",
                0x6984 => "Referenced data invalidated",
                0x6985 => "Conditions of use not satisfied",
                0x6986 => "Command not allowed",
                0x6987 => "Expected SM data objects missing",
                0x6988 => "SM data objects incorrect",
                0x6A80 => "Wrong data",
                0x6A81 => "Function not supported",
                0x6A82 => "File not found",
                0x6A83 => "Record not found",
                0x6A84 => "Not enough memory space",
                0x6A85 => "Lc inconsistent with TLV structure",
                0x6A86 => "Incorrect P1 P2",
                0x6A87 => "Lc inconsistent with P1-P2",
                0x6A88 => "Referenced data not found",
                0x6B00 => "Wrong parameters P1-P2",
                0x6C00 => "Wrong Le",
                0x6D00 => "Invalid instruction",
                0x6E00 => "Invalid class",
                0x6F00 => "No precise diagnostics",
                _ when (sw & 0xFF00) == 0x6100 => $"More data available ({sw & 0xFF} bytes)",
                _ when (sw & 0xFF00) == 0x6C00 => $"Wrong length ({sw & 0xFF} bytes expected)",
                _ => $"Unknown status word: {sw:X4}"
            };

        public override string ToString() =>
            StatusWord.HasValue
                ? $"{Code}: {Message} (SW={StatusWord:X4})"
                : $"{Code}: {Message}";
    }

    /// <summary>
    /// Common error codes for smart card operations.
    /// </summary>
    public static class ErrorCodes
    {
        public const string Success = "SUCCESS";
        public const string CommunicationError = "COMM_ERROR";
        public const string SecurityError = "SECURITY_ERROR";
        public const string InvalidData = "INVALID_DATA";
        public const string Unsupported = "UNSUPPORTED";
        public const string Timeout = "TIMEOUT";
        public const string CardNotPresent = "CARD_NOT_PRESENT";
        public const string ReaderNotFound = "READER_NOT_FOUND";
        public const string SecureChannelNotEstablished = "SECURE_CHANNEL_NOT_ESTABLISHED";
        public const string InvalidCapFile = "INVALID_CAP_FILE";
        public const string InstallationFailed = "INSTALLATION_FAILED";
        public const string DeletionFailed = "DELETION_FAILED";
    }
}