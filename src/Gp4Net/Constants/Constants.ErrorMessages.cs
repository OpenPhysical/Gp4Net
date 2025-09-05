// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using JetBrains.Annotations;

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
///
/// Usage Patterns:
/// OLD: SmartCardError.InvalidArgument($"Invalid key type: {keyType}")
/// NEW: SmartCardError.InvalidArgument(ErrorMessages.FormatInvalidField("key type", keyType))
///
/// OLD: SmartCardError.CryptographicError($"Failed to decrypt: {ex.Message}")
/// NEW: SmartCardError.CryptographicError(ErrorMessages.FormatOperationFailed("decrypt", ex.Message))
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
            public const string NullArgument = "{0} cannot be null";
            public const string EmptyArgument = "{0} cannot be empty";
            public const string InvalidField = "Invalid {0}: {1}";
            public const string UnsupportedValue = "Unsupported {0}: {1}";
            
            // Length validation templates
            public const string InvalidLength = "Invalid length: expected {0}, got {1}";
            public const string InvalidLengthField = "{0} must be {1} bytes, got {2}";
            public const string InvalidRange = "{0} must be between {1} and {2}, got {3}";
            public const string DataTooLarge = "{0} too large: {1} > {2}";
            
            // Operation failure templates
            public const string OperationFailed = "Failed to {0}: {1}";
            public const string OperationTimeout = "Operation timed out after {0}ms";
            public const string InitializationFailed = "{0} initialization failed: {1}";
            
            // Comparison and expectation templates
            public const string ExpectedButGot = "Expected {0} but got {1}";
            public const string UnexpectedValue = "Unexpected {0}: {1}";
            public const string Mismatch = "{0} mismatch: expected {1}, got {2}";
            
            // Data format templates
            public const string InvalidFormat = "Invalid {0} format";
            public const string InvalidFormatDetails = "Invalid {0} format: {1}";
            public const string MalformedData = "Malformed {0}: {1}";
            public const string InsufficientData = "Insufficient data for {0}";
            public const string MissingRequired = "Missing required {0}";
            public const string NotFound = "{0} not found";
            public const string NotFoundDetails = "{0} not found: {1}";
        }

        /// <summary>
        /// Smart card communication error messages for transport layer failures.
        /// </summary>
        public static class Communication
        {
            public const string NoCardPresent = "No card present in reader";
            public const string ReaderNotFound = "Reader not found: {0}";
            public const string TransmissionFailed = "APDU transmission failed: {0}";
            public const string ServiceDisposed = "Service has been disposed";
            public const string NoReadersFound = "No card readers found";
            public const string ConnectionFailed = "Failed to connect to reader: {0}";
            public const string SendCommandFailed = "Send command failed";
            public const string GetReadersFailed = "Failed to get readers";
            public const string CommandExecutionFailed = "Command execution failed";
        }

        /// <summary>
        /// Cryptographic operation error messages for security layer failures.
        /// </summary>
        public static class Cryptography
        {
            public const string MacVerificationFailed = "MAC verification failed";
            public const string CryptogramVerificationFailed = "Cryptogram verification failed";
            public const string EncryptionFailed = "Encryption failed: {0}";
            public const string DecryptionFailed = "Decryption failed: {0}";
            public const string KeyDerivationFailed = "Key derivation failed: {0}";
            public const string InvalidKey = "Invalid {0} key: {1}";
            public const string KeyGenerationFailed = "Failed to generate {0} key: {1}";
            public const string InvalidKeyLength = "Invalid key length: expected {0}, got {1}";
            public const string UnsupportedAlgorithm = "Unsupported algorithm: {0}";
            public const string CryptoOperationFailed = "{0} operation failed: {1}";
        }

        /// <summary>
        /// Protocol-specific error messages for SCP and GlobalPlatform operations.
        /// </summary>
        public static class Protocol
        {
            public const string UnsupportedProtocol = "Unsupported SCP protocol: {0}";
            public const string ProtocolMismatch = "Protocol mismatch: expected {0}, got {1}";
            public const string InvalidProtocolState = "Invalid protocol state for {0}";
            public const string InvalidImplementation = "Invalid {0} implementation: {1:X2}";
            public const string InvalidSecurityLevel = "Invalid security level for {0}: {1:X2}";
            public const string ProtocolVersionInvalid = "Invalid protocol version: 0x{0:X2}";
            public const string AuthenticationFailed = "Authentication failed";
            public const string SecureChannelFailed = "Secure channel establishment failed: {0}";
            public const string UnsupportedScpVersion = "Unsupported SCP version: {0}";
        }

        /// <summary>
        /// APDU and response processing error messages.
        /// </summary>
        public static class Apdu
        {
            public const string InvalidApduFormat = "Invalid APDU format: {0}";
            public const string ApduTooLarge = "APDU too large: {0} bytes";
            public const string ResponseTooShort = "Response too short: expected {0}, got {1}";
            public const string MalformedResponse = "Malformed response: {0}";
            public const string UnexpectedStatusWord = "Unexpected status word: {0:X4}";
            public const string NoResponseConfigured = "No response configured";
        }

        /// <summary>
        /// TLV parsing and data structure error messages.
        /// </summary>
        public static class Tlv
        {
            public const string ParsingFailed = "TLV parsing failed: {0}";
            public const string TagNotFound = "{0} TLV (tag 0x{1:X2}) not found";
            public const string InvalidLength = "{0} TLV invalid length: expected {1}, got {2}";
            public const string StructureInvalid = "Invalid TLV structure: {0}";
            public const string ExcessiveLengthBytes = "Excessive length bytes in TLV";
            public const string InvalidTag = "Invalid TLV tag: {0}";
            public const string UnexpectedEndOfData = "Unexpected end of TLV data";
        }

        /// <summary>
        /// Card application management error messages.
        /// </summary>
        public static class Applications
        {
            public const string NotFound = "Application not found: {0}";
            public const string InstallationFailed = "Application installation failed: {0}";
            public const string DeletionFailed = "Application deletion failed: {0}";
            public const string LoadFileTooLarge = "Load file too large: {0} bytes";
            public const string InvalidAid = "Invalid AID: {0}";
            public const string AidConflict = "AID conflict: {0}";
            public const string InsufficientMemory = "Insufficient memory for application";
            public const string LoadFailed = "Load failed: {0}";
            public const string InstallFailed = "Install failed: {0}";
        }

        /// <summary>
        /// CAP file processing error messages.
        /// </summary>
        public static class CapFile
        {
            public const string InvalidCapFile = "Invalid CAP file: {0}";
            public const string FailedToReadProfile = "Failed to read profile file: {0}";
            public const string FailedToLoadProfile = "Failed to load profile: {0}";
            public const string InvalidJsonFormat = "Invalid JSON format: {0}";
            public const string FailedToDeserialize = "Failed to deserialize JSON profile";
            public const string FailedToParse = "Failed to parse {0}: {1}";
            public const string ComponentMissing = "Missing CAP file component: {0}";
            public const string ComponentInvalid = "Invalid CAP file component: {0}";
        }

        /// <summary>
        /// Key management and validation error messages.
        /// </summary>
        public static class Keys
        {
            public const string InvalidKeySet = "Invalid key set: {0}";
            public const string KeyNotFound = "Key not found: {0}";
            public const string KeyVersionInvalid = "Invalid key version: {0}";
            public const string UnsupportedKeyType = "Unsupported key type: {0}";
            public const string KeyDerivationError = "Key derivation error: {0}";
            public const string InvalidKeyData = "Invalid key data: {0}";
            public const string KeystoreError = "Keystore error: {0}";
        }

        /// <summary>
        /// Test and emulation error messages.
        /// </summary>
        public static class Testing
        {
            public const string TestFailure = "Test failure";
            public const string TestFailureDetails = "Test failure: {0}";
            public const string IsdSelectionFailed = "Test failure - ISD selection failed";
            public const string CardInfoRetrievalFailed = "Test failure - card info retrieval failed";
            public const string NoOperationSupported = "Empty card service - no operation supported";
            public const string NoAtrAvailable = "Empty card service - no ATR available";
            public const string TestContextNoSecureChannels = "Test context does not support secure channels";
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
                string.Format(Templates.InvalidField, field, value);

            /// <summary>
            /// Formats "Failed to {operation}: {message}" pattern.
            /// REPLACES: $"Failed to {operation}: {message}"
            /// </summary>
            public static string OperationFailed(string operation, string message) =>
                string.Format(Templates.OperationFailed, operation, message);

            /// <summary>
            /// Formats "Expected {expected} but got {actual}" pattern.
            /// REPLACES: $"Expected {expected} but got {actual}"
            /// </summary>
            public static string ExpectedButGot(object expected, object actual) =>
                string.Format(Templates.ExpectedButGot, expected, actual);

            /// <summary>
            /// Formats "Invalid length: expected {expected}, got {actual}" pattern.
            /// REPLACES: $"Invalid length: expected {expected}, got {actual}"
            /// </summary>
            public static string InvalidLength(int expected, int actual) =>
                string.Format(Templates.InvalidLength, expected, actual);

            /// <summary>
            /// Formats "{field} must be {expected} bytes, got {actual}" pattern.
            /// REPLACES: $"{field} must be {expected} bytes, got {actual}"
            /// </summary>
            public static string InvalidLengthField(string field, int expected, int actual) =>
                string.Format(Templates.InvalidLengthField, field, expected, actual);

            /// <summary>
            /// Formats "Unsupported {field}: {value}" pattern.
            /// REPLACES: $"Unsupported {field}: {value}"
            /// </summary>
            public static string UnsupportedValue(string field, object value) =>
                string.Format(Templates.UnsupportedValue, field, value);

            /// <summary>
            /// Formats "{field} cannot be null" pattern.
            /// REPLACES: $"{field} cannot be null"
            /// </summary>
            public static string NullArgument(string field) =>
                string.Format(Templates.NullArgument, field);

            /// <summary>
            /// Formats "{field} cannot be empty" pattern.
            /// REPLACES: $"{field} cannot be empty"
            /// </summary>
            public static string EmptyArgument(string field) =>
                string.Format(Templates.EmptyArgument, field);

            /// <summary>
            /// Formats "{field} must be between {min} and {max}, got {actual}" pattern.
            /// REPLACES: $"{field} must be between {min} and {max}, got {actual}"
            /// </summary>
            public static string InvalidRange(string field, int min, int max, int actual) =>
                string.Format(Templates.InvalidRange, field, min, max, actual);

            /// <summary>
            /// Formats "Invalid {dataType} format: {details}" pattern.
            /// REPLACES: $"Invalid {dataType} format: {details}"
            /// </summary>
            public static string InvalidFormatDetails(string dataType, string details) =>
                string.Format(Templates.InvalidFormatDetails, dataType, details);

            /// <summary>
            /// Formats "Malformed {dataType}: {details}" pattern.
            /// REPLACES: $"Malformed {dataType}: {details}"
            /// </summary>
            public static string MalformedData(string dataType, string details) =>
                string.Format(Templates.MalformedData, dataType, details);

            /// <summary>
            /// Formats "Operation timed out after {timeout}ms" pattern.
            /// REPLACES: $"Operation timed out after {timeout}ms"
            /// </summary>
            public static string OperationTimeout(int timeoutMs) =>
                string.Format(Templates.OperationTimeout, timeoutMs);

            /// <summary>
            /// Formats "Reader not found: {readerName}" pattern.
            /// REPLACES: $"Reader not found: {readerName}"
            /// </summary>
            public static string ReaderNotFound(string readerName) =>
                string.Format(Communication.ReaderNotFound, readerName);

            /// <summary>
            /// Formats "APDU transmission failed: {details}" pattern.
            /// REPLACES: $"APDU transmission failed: {details}"
            /// </summary>
            public static string TransmissionFailed(string details) =>
                string.Format(Communication.TransmissionFailed, details);

            /// <summary>
            /// Formats "Invalid {keyType} key: {details}" pattern.
            /// REPLACES: $"Invalid {keyType} key: {details}"
            /// </summary>
            public static string InvalidKey(string keyType, string details) =>
                string.Format(Cryptography.InvalidKey, keyType, details);

            /// <summary>
            /// Formats "Encryption failed: {details}" pattern.
            /// REPLACES: $"Encryption failed: {details}"
            /// </summary>
            public static string EncryptionFailed(string details) =>
                string.Format(Cryptography.EncryptionFailed, details);

            /// <summary>
            /// Formats "Decryption failed: {details}" pattern.
            /// REPLACES: $"Decryption failed: {details}"
            /// </summary>
            public static string DecryptionFailed(string details) =>
                string.Format(Cryptography.DecryptionFailed, details);

            /// <summary>
            /// Formats "Key derivation failed: {details}" pattern.
            /// REPLACES: $"Key derivation failed: {details}"
            /// </summary>
            public static string KeyDerivationFailed(string details) =>
                string.Format(Cryptography.KeyDerivationFailed, details);

            /// <summary>
            /// Formats "Invalid {protocol} implementation: {implementation:X2}" pattern.
            /// REPLACES: $"Invalid {protocol} implementation: {implementation:X2}"
            /// </summary>
            public static string InvalidImplementation(string protocol, byte implementation) =>
                string.Format(Protocol.InvalidImplementation, protocol, implementation);

            /// <summary>
            /// Formats "Invalid security level for {protocol}: {level:X2}" pattern.
            /// REPLACES: $"Invalid security level for {protocol}: {level:X2}"
            /// </summary>
            public static string InvalidSecurityLevel(string protocol, byte level) =>
                string.Format(Protocol.InvalidSecurityLevel, protocol, level);

            /// <summary>
            /// Formats "Unexpected status word: {sw:X4}" pattern.
            /// REPLACES: $"Unexpected status word: {sw:X4}"
            /// </summary>
            public static string UnexpectedStatusWord(ushort statusWord) =>
                string.Format(Apdu.UnexpectedStatusWord, statusWord);

            /// <summary>
            /// Formats "{field} TLV (tag 0x{tag:X2}) not found" pattern.
            /// REPLACES: $"{field} TLV (tag 0x{tag:X2}) not found"
            /// </summary>
            public static string TlvTagNotFound(string field, byte tag) =>
                string.Format(Tlv.TagNotFound, field, tag);

            /// <summary>
            /// Formats "{field} TLV invalid length: expected {expected}, got {actual}" pattern.
            /// REPLACES: $"{field} TLV invalid length: expected {expected}, got {actual}"
            /// </summary>
            public static string TlvInvalidLength(string field, int expected, int actual) =>
                string.Format(Tlv.InvalidLength, field, expected, actual);
        }
    }
}