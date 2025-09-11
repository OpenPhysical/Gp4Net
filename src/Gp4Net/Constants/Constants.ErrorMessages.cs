// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

namespace Gp4Net.Constants;

/// <summary>
/// Centralized error message constants and formatting methods to eliminate 576+ duplicate
/// error constructions found across the codebase. Replaces all hardcoded error strings
/// with reusable, consistent patterns following functional programming principles.
///
/// REPLACES patterns like:
/// - SmartCardError.InvalidArgument($"Invalid {field}: {value}")
/// - SmartCardError.CryptographicError($"Failed to {operation}: {message}")
/// - SmartCardError.InvalidData($"Expected {expected} but got {actual}")
/// - SmartCardError.InvalidArgument($"Invalid length: expected {expected}, got {actual}")
///
/// Design Principles:
/// - Single source of truth for all error message patterns
/// - Consistent formatting across all error types
/// - Type-safe parameter interpolation
/// - Zero duplicate string literals
/// - Easy discoverability through IntelliSense
/// - Perfect functional programming compatibility
/// </summary>
public static partial class Constants
{
    /// <summary>
    /// Error message constants and formatting methods organized by functional domain.
    /// Each category provides both template constants and formatting methods for
    /// consistent error message construction throughout the codebase.
    /// </summary>
    public static class ErrorMessages
    {
        /// <summary>
        /// Common error message templates for basic validation failures.
        /// Used across all domains for consistent argument and data validation.
        /// </summary>
        public static class Templates
        {
            // Argument validation templates
            public const string NULL_ARGUMENT = "{0} cannot be null";
            public const string EMPTY_ARGUMENT = "{0} cannot be empty";
            public const string INVALID_FIELD = "Invalid {0}: {1}";
            public const string UNSUPPORTED_VALUE = "Unsupported {0}: {1}";

            // Length validation templates
            public const string INVALID_LENGTH = "Invalid length: expected {0}, got {1}";
            public const string INVALID_LENGTH_FIELD = "{0} must be {1} bytes, got {2}";
            public const string INVALID_RANGE = "{0} must be between {1} and {2}, got {3}";
            public const string DATA_TOO_LARGE = "{0} too large: {1} > {2}";

            // Operation failure templates
            public const string OPERATION_FAILED = "Failed to {0}: {1}";
            public const string OPERATION_TIMEOUT = "Operation timed out after {0}ms";
            public const string INITIALIZATION_FAILED = "{0} initialization failed: {1}";

            // Comparison and expectation templates
            public const string EXPECTED_BUT_GOT = "Expected {0} but got {1}";
            public const string UNEXPECTED_VALUE = "Unexpected {0}: {1}";
            public const string MISMATCH = "{0} mismatch: expected {1}, got {2}";

            // Data format templates
            public const string INVALID_FORMAT = "Invalid {0} format";
            public const string INVALID_FORMAT_DETAILS = "Invalid {0} format: {1}";
            public const string MALFORMED_DATA = "Malformed {0}: {1}";
            public const string INSUFFICIENT_DATA = "Insufficient data for {0}";
            public const string MISSING_REQUIRED = "Missing required {0}";
            public const string NOT_FOUND = "{0} not found";
            public const string NOT_FOUND_DETAILS = "{0} not found: {1}";
        }

        /// <summary>
        /// Smart card communication error messages for transport layer failures.
        /// </summary>
        public static class Communication
        {
            public const string NO_CARD_PRESENT = "No card present in reader";
            public const string READER_NOT_FOUND = "Reader not found: {0}";
            public const string TRANSMISSION_FAILED = "APDU transmission failed: {0}";
            public const string SERVICE_DISPOSED = "Service has been disposed";
            public const string NO_READERS_FOUND = "No card readers found";
            public const string CONNECTION_FAILED = "Failed to connect to reader: {0}";
            public const string SEND_COMMAND_FAILED = "Send command failed";
            public const string GET_READERS_FAILED = "Failed to get readers";
            public const string COMMAND_EXECUTION_FAILED = "Command execution failed";
        }

        /// <summary>
        /// Cryptographic operation error messages for security layer failures.
        /// </summary>
        public static class Cryptography
        {
            public const string MAC_VERIFICATION_FAILED = "MAC verification failed";
            public const string CRYPTOGRAM_VERIFICATION_FAILED = "Cryptogram verification failed";
            public const string ENCRYPTION_FAILED = "Encryption failed: {0}";
            public const string DECRYPTION_FAILED = "Decryption failed: {0}";
            public const string KEY_DERIVATION_FAILED = "Key derivation failed: {0}";
            public const string INVALID_KEY = "Invalid {0} key: {1}";
            public const string KEY_GENERATION_FAILED = "Failed to generate {0} key: {1}";
            public const string INVALID_KEY_LENGTH = "Invalid key length: expected {0}, got {1}";
            public const string UNSUPPORTED_ALGORITHM = "Unsupported algorithm: {0}";
            public const string CRYPTO_OPERATION_FAILED = "{0} operation failed: {1}";
        }

        /// <summary>
        /// Protocol-specific error messages for SCP and GlobalPlatform operations.
        /// </summary>
        public static class Protocol
        {
            public const string UNSUPPORTED_PROTOCOL = "Unsupported SCP protocol: {0}";
            public const string PROTOCOL_MISMATCH = "Protocol mismatch: expected {0}, got {1}";
            public const string INVALID_PROTOCOL_STATE = "Invalid protocol state for {0}";
            public const string INVALID_IMPLEMENTATION = "Invalid {0} implementation: {1:X2}";
            public const string INVALID_SECURITY_LEVEL = "Invalid security level for {0}: {1:X2}";
            public const string PROTOCOL_VERSION_INVALID = "Invalid protocol version: 0x{0:X2}";
            public const string AUTHENTICATION_FAILED = "Authentication failed";
            public const string SECURE_CHANNEL_FAILED = "Secure channel establishment failed: {0}";
            public const string UNSUPPORTED_SCP_VERSION = "Unsupported SCP version: {0}";
        }

        /// <summary>
        /// APDU and response processing error messages.
        /// </summary>
        public static class Apdu
        {
            public const string INVALID_APDU_FORMAT = "Invalid APDU format: {0}";
            public const string APDU_TOO_LARGE = "APDU too large: {0} bytes";
            public const string RESPONSE_TOO_SHORT = "Response too short: expected {0}, got {1}";
            public const string MALFORMED_RESPONSE = "Malformed response: {0}";
            public const string UNEXPECTED_STATUS_WORD = "Unexpected status word: {0:X4}";
            public const string NO_RESPONSE_CONFIGURED = "No response configured";
        }

        /// <summary>
        /// TLV parsing and data structure error messages.
        /// </summary>
        public static class Tlv
        {
            public const string PARSING_FAILED = "TLV parsing failed: {0}";
            public const string TAG_NOT_FOUND = "{0} TLV (tag 0x{1:X2}) not found";
            public const string INVALID_LENGTH = "{0} TLV invalid length: expected {1}, got {2}";
            public const string STRUCTURE_INVALID = "Invalid TLV structure: {0}";
            public const string EXCESSIVE_LENGTH_BYTES = "Excessive length bytes in TLV";
            public const string INVALID_TAG = "Invalid TLV tag: {0}";
            public const string UNEXPECTED_END_OF_DATA = "Unexpected end of TLV data";
        }

        /// <summary>
        /// Card application management error messages.
        /// </summary>
        public static class Applications
        {
            public const string NOT_FOUND = "Application not found: {0}";
            public const string INSTALLATION_FAILED = "Application installation failed: {0}";
            public const string DELETION_FAILED = "Application deletion failed: {0}";
            public const string LOAD_FILE_TOO_LARGE = "Load file too large: {0} bytes";
            public const string INVALID_AID = "Invalid AID: {0}";
            public const string AID_CONFLICT = "AID conflict: {0}";
            public const string INSUFFICIENT_MEMORY = "Insufficient memory for application";
            public const string LOAD_FAILED = "Load failed: {0}";
            public const string INSTALL_FAILED = "Install failed: {0}";
        }

        /// <summary>
        /// CAP file processing error messages.
        /// </summary>
        public static class CapFile
        {
            public const string INVALID_CAP_FILE = "Invalid CAP file: {0}";
            public const string FAILED_TO_READ_PROFILE = "Failed to read profile file: {0}";
            public const string FAILED_TO_LOAD_PROFILE = "Failed to load profile: {0}";
            public const string INVALID_JSON_FORMAT = "Invalid JSON format: {0}";
            public const string FAILED_TO_DESERIALIZE = "Failed to deserialize JSON profile";
            public const string FAILED_TO_PARSE = "Failed to parse {0}: {1}";
            public const string COMPONENT_MISSING = "Missing CAP file component: {0}";
            public const string COMPONENT_INVALID = "Invalid CAP file component: {0}";
        }

        /// <summary>
        /// Key management and validation error messages.
        /// </summary>
        public static class Keys
        {
            public const string INVALID_KEY_SET = "Invalid key set: {0}";
            public const string KEY_NOT_FOUND = "Key not found: {0}";
            public const string KEY_VERSION_INVALID = "Invalid key version: {0}";
            public const string UNSUPPORTED_KEY_TYPE = "Unsupported key type: {0}";
            public const string KEY_DERIVATION_ERROR = "Key derivation error: {0}";
            public const string INVALID_KEY_DATA = "Invalid key data: {0}";
            public const string KEYSTORE_ERROR = "Keystore error: {0}";
        }

        /// <summary>
        /// Test and emulation error messages.
        /// </summary>
        public static class Testing
        {
            public const string TEST_FAILURE = "Test failure";
            public const string TEST_FAILURE_DETAILS = "Test failure: {0}";
            public const string ISD_SELECTION_FAILED = "Test failure - ISD selection failed";
            public const string CARD_INFO_RETRIEVAL_FAILED =
                "Test failure - card info retrieval failed";
            public const string NO_OPERATION_SUPPORTED =
                "Empty card service - no operation supported";
            public const string NO_ATR_AVAILABLE = "Empty card service - no ATR available";
            public const string TEST_CONTEXT_NO_SECURE_CHANNELS =
                "Test context does not support secure channels";
        }

        /// <summary>
        /// Format methods for constructing consistent error messages with parameters.
        /// These replace the 576+ duplicate string interpolation patterns found throughout the codebase.
        /// </summary>
        public static class Format
        {
            /// <summary>
            /// Formats "Invalid {field}: {value}" pattern.
            /// REPLACES: $"Invalid {field}: {value}"
            /// </summary>
            public static string InvalidField(string field, object value) =>
                string.Format(Templates.INVALID_FIELD, field, value);

            /// <summary>
            /// Formats "Failed to {operation}: {message}" pattern.
            /// REPLACES: $"Failed to {operation}: {message}"
            /// </summary>
            public static string OperationFailed(string operation, string message) =>
                string.Format(Templates.OPERATION_FAILED, operation, message);

            /// <summary>
            /// Formats "Expected {expected} but got {actual}" pattern.
            /// REPLACES: $"Expected {expected} but got {actual}"
            /// </summary>
            public static string ExpectedButGot(object expected, object actual) =>
                string.Format(Templates.EXPECTED_BUT_GOT, expected, actual);

            /// <summary>
            /// Formats "Invalid length: expected {expected}, got {actual}" pattern.
            /// REPLACES: $"Invalid length: expected {expected}, got {actual}"
            /// </summary>
            public static string InvalidLength(int expected, int actual) =>
                string.Format(Templates.INVALID_LENGTH, expected, actual);

            /// <summary>
            /// Formats "{field} must be {expected} bytes, got {actual}" pattern.
            /// REPLACES: $"{field} must be {expected} bytes, got {actual}"
            /// </summary>
            public static string InvalidLengthField(string field, int expected, int actual) =>
                string.Format(Templates.INVALID_LENGTH_FIELD, field, expected, actual);

            /// <summary>
            /// Formats "Unsupported {field}: {value}" pattern.
            /// REPLACES: $"Unsupported {field}: {value}"
            /// </summary>
            public static string UnsupportedValue(string field, object value) =>
                string.Format(Templates.UNSUPPORTED_VALUE, field, value);

            /// <summary>
            /// Formats "{field} cannot be null" pattern.
            /// REPLACES: $"{field} cannot be null"
            /// </summary>
            public static string NullArgument(string field) =>
                string.Format(Templates.NULL_ARGUMENT, field);

            /// <summary>
            /// Formats "{field} cannot be empty" pattern.
            /// REPLACES: $"{field} cannot be empty"
            /// </summary>
            public static string EmptyArgument(string field) =>
                string.Format(Templates.EMPTY_ARGUMENT, field);

            /// <summary>
            /// Formats "{field} must be between {min} and {max}, got {actual}" pattern.
            /// REPLACES: $"{field} must be between {min} and {max}, got {actual}"
            /// </summary>
            public static string InvalidRange(string field, int min, int max, int actual) =>
                string.Format(Templates.INVALID_RANGE, field, min, max, actual);

            /// <summary>
            /// Formats "Invalid {dataType} format: {details}" pattern.
            /// REPLACES: $"Invalid {dataType} format: {details}"
            /// </summary>
            public static string InvalidFormatDetails(string dataType, string details) =>
                string.Format(Templates.INVALID_FORMAT_DETAILS, dataType, details);

            /// <summary>
            /// Formats "Malformed {dataType}: {details}" pattern.
            /// REPLACES: $"Malformed {dataType}: {details}"
            /// </summary>
            public static string MalformedData(string dataType, string details) =>
                string.Format(Templates.MALFORMED_DATA, dataType, details);

            /// <summary>
            /// Formats "Operation timed out after {timeout}ms" pattern.
            /// REPLACES: $"Operation timed out after {timeout}ms"
            /// </summary>
            public static string OperationTimeout(int timeoutMs) =>
                string.Format(Templates.OPERATION_TIMEOUT, timeoutMs);

            /// <summary>
            /// Formats "Reader not found: {readerName}" pattern.
            /// REPLACES: $"Reader not found: {readerName}"
            /// </summary>
            public static string ReaderNotFound(string readerName) =>
                string.Format(Communication.READER_NOT_FOUND, readerName);

            /// <summary>
            /// Formats "APDU transmission failed: {details}" pattern.
            /// REPLACES: $"APDU transmission failed: {details}"
            /// </summary>
            public static string TransmissionFailed(string details) =>
                string.Format(Communication.TRANSMISSION_FAILED, details);

            /// <summary>
            /// Formats "Invalid {keyType} key: {details}" pattern.
            /// REPLACES: $"Invalid {keyType} key: {details}"
            /// </summary>
            public static string InvalidKey(string keyType, string details) =>
                string.Format(Cryptography.INVALID_KEY, keyType, details);

            /// <summary>
            /// Formats "Encryption failed: {details}" pattern.
            /// REPLACES: $"Encryption failed: {details}"
            /// </summary>
            public static string EncryptionFailed(string details) =>
                string.Format(Cryptography.ENCRYPTION_FAILED, details);

            /// <summary>
            /// Formats "Decryption failed: {details}" pattern.
            /// REPLACES: $"Decryption failed: {details}"
            /// </summary>
            public static string DecryptionFailed(string details) =>
                string.Format(Cryptography.DECRYPTION_FAILED, details);

            /// <summary>
            /// Formats "Key derivation failed: {details}" pattern.
            /// REPLACES: $"Key derivation failed: {details}"
            /// </summary>
            public static string KeyDerivationFailed(string details) =>
                string.Format(Cryptography.KEY_DERIVATION_FAILED, details);

            /// <summary>
            /// Formats "Invalid {protocol} implementation: {implementation:X2}" pattern.
            /// REPLACES: $"Invalid {protocol} implementation: {implementation:X2}"
            /// </summary>
            public static string InvalidImplementation(string protocol, byte implementation) =>
                string.Format(Protocol.INVALID_IMPLEMENTATION, protocol, implementation);

            /// <summary>
            /// Formats "Invalid security level for {protocol}: {level:X2}" pattern.
            /// REPLACES: $"Invalid security level for {protocol}: {level:X2}"
            /// </summary>
            public static string InvalidSecurityLevel(string protocol, byte level) =>
                string.Format(Protocol.INVALID_SECURITY_LEVEL, protocol, level);

            /// <summary>
            /// Formats "Unexpected status word: {sw:X4}" pattern.
            /// REPLACES: $"Unexpected status word: {sw:X4}"
            /// </summary>
            public static string UnexpectedStatusWord(ushort statusWord) =>
                string.Format(Apdu.UNEXPECTED_STATUS_WORD, statusWord);

            /// <summary>
            /// Formats "{field} TLV (tag 0x{tag:X2}) not found" pattern.
            /// REPLACES: $"{field} TLV (tag 0x{tag:X2}) not found"
            /// </summary>
            public static string TlvTagNotFound(string field, byte tag) =>
                string.Format(Tlv.TAG_NOT_FOUND, field, tag);

            /// <summary>
            /// Formats "{field} TLV invalid length: expected {expected}, got {actual}" pattern.
            /// REPLACES: $"{field} TLV invalid length: expected {expected}, got {actual}"
            /// </summary>
            public static string TlvInvalidLength(string field, int expected, int actual) =>
                string.Format(Tlv.INVALID_LENGTH, field, expected, actual);
        }
    }
}
