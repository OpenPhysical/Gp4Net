// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.Shared;

/// <summary>
/// BRUTAL static factory for ALL error construction.
/// REPLACES 50+ duplicate error construction sites across the codebase.
/// NO MERCY - delete all manual SmartCardError construction patterns.
/// </summary>
[PublicAPI]
public static class ErrorFactory
{

    /// <summary>
    /// Creates null argument error.
    /// REPLACES: SmartCardError.InvalidArgument("{field} cannot be null")
    /// </summary>
    public static SmartCardError NullArgument(string fieldName) =>
        SmartCardError.InvalidArgument($"{fieldName} cannot be null");

    /// <summary>
    /// Creates empty argument error.
    /// REPLACES: SmartCardError.InvalidArgument("{field} cannot be empty")
    /// </summary>
    public static SmartCardError EmptyArgument(string fieldName) =>
        SmartCardError.InvalidArgument($"{fieldName} cannot be empty");

    /// <summary>
    /// Creates invalid length error.
    /// REPLACES: SmartCardError.InvalidArgument("{field} must be {expected} bytes, got {actual}")
    /// </summary>
    public static SmartCardError InvalidLength(string fieldName, int expectedLength, int actualLength) =>
        SmartCardError.InvalidArgument($"{fieldName} must be {expectedLength} bytes, got {actualLength}");

    /// <summary>
    /// Creates invalid range error.
    /// REPLACES: SmartCardError.InvalidArgument("{field} must be between {min} and {max}")
    /// </summary>
    public static SmartCardError InvalidRange(string fieldName, int min, int max, int actual) =>
        SmartCardError.InvalidArgument($"{fieldName} must be between {min} and {max}, got {actual}");

    /// <summary>
    /// Creates unsupported value error.
    /// REPLACES: SmartCardError.InvalidArgument("Unsupported {field}: {value}")
    /// </summary>
    public static SmartCardError UnsupportedValue(string fieldName, object value) =>
        SmartCardError.InvalidArgument($"Unsupported {fieldName}: {value}");

    /// <summary>
    /// Creates invalid data format error.
    /// REPLACES: SmartCardError.InvalidData("Invalid {dataType} format")
    /// </summary>
    public static SmartCardError InvalidDataFormat(string dataType) =>
        SmartCardError.InvalidData($"Invalid {dataType} format");

    /// <summary>
    /// Creates insufficient data error.
    /// REPLACES: SmartCardError.InvalidData("Insufficient data for {operation}")
    /// </summary>
    public static SmartCardError InsufficientData(string operation) =>
        SmartCardError.InvalidData($"Insufficient data for {operation}");

    /// <summary>
    /// Creates malformed data error.
    /// REPLACES: SmartCardError.InvalidData("Malformed {dataType}: {details}")
    /// </summary>
    public static SmartCardError MalformedData(string dataType, string details) =>
        SmartCardError.InvalidData($"Malformed {dataType}: {details}");

    /// <summary>
    /// Creates data too large error.
    /// REPLACES: SmartCardError.InvalidData("{field} too large: {size} > {maxSize}")
    /// </summary>
    public static SmartCardError DataTooLarge(string fieldName, int size, int maxSize) =>
        SmartCardError.InvalidData($"{fieldName} too large: {size} > {maxSize}");

    /// <summary>
    /// Creates missing required field error.
    /// REPLACES: SmartCardError.InvalidData("Missing required field: {field}")
    /// </summary>
    public static SmartCardError MissingRequiredField(string fieldName) =>
        SmartCardError.InvalidData($"Missing required field: {fieldName}");

    /// <summary>
    /// Creates unsupported protocol error.
    /// REPLACES: SmartCardError.UnsupportedOperation("Unsupported SCP protocol: {protocol}")
    /// </summary>
    public static SmartCardError UnsupportedProtocol(string protocolName) =>
        SmartCardError.Unsupported($"Unsupported SCP protocol: {protocolName}");

    /// <summary>
    /// Creates protocol mismatch error.
    /// REPLACES: SmartCardError.InvalidData("Protocol mismatch: expected {expected}, got {actual}")
    /// </summary>
    public static SmartCardError ProtocolMismatch(string expected, string actual) =>
        SmartCardError.InvalidData($"Protocol mismatch: expected {expected}, got {actual}");

    /// <summary>
    /// Creates invalid protocol state error.
    /// REPLACES: SmartCardError.InvalidData("Invalid protocol state for {operation}")
    /// </summary>
    public static SmartCardError InvalidProtocolState(string operation) =>
        SmartCardError.InvalidData($"Invalid protocol state for {operation}");

    /// <summary>
    /// Creates protocol initialization failed error.
    /// REPLACES: SmartCardError.InitializationFailed("{protocol} initialization failed: {reason}")
    /// </summary>
    public static SmartCardError ProtocolInitializationFailed(string protocol, string reason) =>
        SmartCardError.InitializationFailed($"{protocol} initialization failed: {reason}");

    /// <summary>
    /// Creates cryptographic operation failed error.
    /// REPLACES: SmartCardError.CryptographicError("{operation} failed: {details}")
    /// </summary>
    public static SmartCardError CryptographicFailed(string operation, string details) =>
        SmartCardError.CryptographicError($"{operation} failed: {details}");

    /// <summary>
    /// Creates invalid key error.
    /// REPLACES: SmartCardError.CryptographicError("Invalid {keyType} key: {details}")
    /// </summary>
    public static SmartCardError InvalidKey(string keyType, string details) =>
        SmartCardError.CryptographicError($"Invalid {keyType} key: {details}");

    /// <summary>
    /// Creates key derivation failed error.
    /// REPLACES: SmartCardError.CryptographicError("Key derivation failed: {details}")
    /// </summary>
    public static SmartCardError KeyDerivationFailed(string details) =>
        SmartCardError.CryptographicError($"Key derivation failed: {details}");

    /// <summary>
    /// Creates MAC verification failed error.
    /// REPLACES: SmartCardError.SecurityError("MAC verification failed")
    /// </summary>
    public static SmartCardError MacVerificationFailed() =>
        SmartCardError.SecurityError("MAC verification failed");

    /// <summary>
    /// Creates cryptogram verification failed error.
    /// REPLACES: SmartCardError.SecurityError("Cryptogram verification failed")
    /// </summary>
    public static SmartCardError CryptogramVerificationFailed() =>
        SmartCardError.SecurityError("Cryptogram verification failed");

    /// <summary>
    /// Creates encryption failed error.
    /// REPLACES: SmartCardError.CryptographicError("Encryption failed: {details}")
    /// </summary>
    public static SmartCardError EncryptionFailed(string details) =>
        SmartCardError.CryptographicError($"Encryption failed: {details}");

    /// <summary>
    /// Creates decryption failed error.
    /// REPLACES: SmartCardError.CryptographicError("Decryption failed: {details}")
    /// </summary>
    public static SmartCardError DecryptionFailed(string details) =>
        SmartCardError.CryptographicError($"Decryption failed: {details}");

    /// <summary>
    /// Creates card not present error.
    /// REPLACES: SmartCardError.CommunicationError("No card present in reader")
    /// </summary>
    public static SmartCardError CardNotPresent() =>
        SmartCardError.CommunicationError("No card present in reader");

    /// <summary>
    /// Creates reader not found error.
    /// REPLACES: SmartCardError.CommunicationError("Reader not found: {readerName}")
    /// </summary>
    public static SmartCardError ReaderNotFound(string readerName) =>
        SmartCardError.CommunicationError($"Reader not found: {readerName}");

    /// <summary>
    /// Creates transmission failed error.
    /// REPLACES: SmartCardError.CommunicationError("APDU transmission failed: {details}")
    /// </summary>
    public static SmartCardError TransmissionFailed(string details) =>
        SmartCardError.CommunicationError($"APDU transmission failed: {details}");

    /// <summary>
    /// Creates unexpected status word error.
    /// REPLACES: SmartCardError.CardError("Unexpected status word: {sw:X4}")
    /// </summary>
    public static SmartCardError UnexpectedStatusWord(ushort statusWord) =>
        SmartCardError.CardError($"Unexpected status word: {statusWord:X4}");

    /// <summary>
    /// Creates timeout error.
    /// REPLACES: SmartCardError.CommunicationError("Operation timed out after {timeout}ms")
    /// </summary>
    public static SmartCardError OperationTimeout(int timeoutMs) =>
        SmartCardError.CommunicationError($"Operation timed out after {timeoutMs}ms");

    /// <summary>
    /// Creates invalid APDU format error.
    /// REPLACES: SmartCardError.InvalidData("Invalid APDU format: {details}")
    /// </summary>
    public static SmartCardError InvalidApduFormat(string details) =>
        SmartCardError.InvalidData($"Invalid APDU format: {details}");

    /// <summary>
    /// Creates APDU too large error.
    /// REPLACES: SmartCardError.InvalidData("APDU too large: {size} bytes")
    /// </summary>
    public static SmartCardError ApduTooLarge(int size) =>
        SmartCardError.InvalidData($"APDU too large: {size} bytes");

    /// <summary>
    /// Creates response too short error.
    /// REPLACES: SmartCardError.InvalidResponse("Response too short: expected {expected}, got {actual}")
    /// </summary>
    public static SmartCardError ResponseTooShort(int expected, int actual) =>
        SmartCardError.InvalidResponse($"Response too short: expected {expected}, got {actual}");

    /// <summary>
    /// Creates malformed response error.
    /// REPLACES: SmartCardError.InvalidResponse("Malformed response: {details}")
    /// </summary>
    public static SmartCardError MalformedResponse(string details) =>
        SmartCardError.InvalidResponse($"Malformed response: {details}");

    /// <summary>
    /// Creates TLV parsing failed error.
    /// REPLACES: SmartCardError.InvalidData("TLV parsing failed: {details}")
    /// </summary>
    public static SmartCardError TlvParsingFailed(string details) =>
        SmartCardError.InvalidData($"TLV parsing failed: {details}");

    /// <summary>
    /// Creates TLV tag not found error.
    /// REPLACES: SmartCardError.InvalidData("{field} TLV (tag 0x{tag:X2}) not found")
    /// </summary>
    public static SmartCardError TlvTagNotFound(string fieldName, byte tag) =>
        SmartCardError.InvalidData($"{fieldName} TLV (tag 0x{tag:X2}) not found");

    /// <summary>
    /// Creates TLV invalid length error.
    /// REPLACES: SmartCardError.InvalidData("{field} TLV invalid length: expected {expected}, got {actual}")
    /// </summary>
    public static SmartCardError TlvInvalidLength(string fieldName, int expected, int actual) =>
        SmartCardError.InvalidData($"{fieldName} TLV invalid length: expected {expected}, got {actual}");

    /// <summary>
    /// Creates TLV structure invalid error.
    /// REPLACES: SmartCardError.InvalidData("Invalid TLV structure: {details}")
    /// </summary>
    public static SmartCardError TlvStructureInvalid(string details) =>
        SmartCardError.InvalidData($"Invalid TLV structure: {details}");

    /// <summary>
    /// Creates application not found error.
    /// REPLACES: SmartCardError.CardError("Application not found: {aid}")
    /// </summary>
    public static SmartCardError ApplicationNotFound(string aid) =>
        SmartCardError.CardError($"Application not found: {aid}");

    /// <summary>
    /// Creates application installation failed error.
    /// REPLACES: SmartCardError.CardError("Application installation failed: {details}")
    /// </summary>
    public static SmartCardError ApplicationInstallationFailed(string details) =>
        SmartCardError.CardError($"Application installation failed: {details}");

    /// <summary>
    /// Creates application deletion failed error.
    /// REPLACES: SmartCardError.CardError("Application deletion failed: {details}")
    /// </summary>
    public static SmartCardError ApplicationDeletionFailed(string details) =>
        SmartCardError.CardError($"Application deletion failed: {details}");

    /// <summary>
    /// Creates load file too large error.
    /// REPLACES: SmartCardError.CardError("Load file too large: {size} bytes")
    /// </summary>
    public static SmartCardError LoadFileTooLarge(int size) =>
        SmartCardError.CardError($"Load file too large: {size} bytes");

    /// <summary>
    /// Creates failed Result with null argument error.
    /// REPLACES: Result.Failure&lt;T, SmartCardError&gt;(SmartCardError.InvalidArgument("{field} cannot be null"))
    /// </summary>
    public static Result<T, SmartCardError> FailureNullArgument<T>(string fieldName) =>
        Result.Failure<T, SmartCardError>(NullArgument(fieldName));

    /// <summary>
    /// Creates failed Result with invalid length error.
    /// REPLACES: Result.Failure&lt;T, SmartCardError&gt;(SmartCardError.InvalidArgument(...))
    /// </summary>
    public static Result<T, SmartCardError> FailureInvalidLength<T>(string fieldName, int expected, int actual) =>
        Result.Failure<T, SmartCardError>(InvalidLength(fieldName, expected, actual));

    /// <summary>
    /// Creates failed Result with cryptographic error.
    /// REPLACES: Result.Failure&lt;T, SmartCardError&gt;(SmartCardError.CryptographicError(...))
    /// </summary>
    public static Result<T, SmartCardError> FailureCryptographicError<T>(string operation, string details) =>
        Result.Failure<T, SmartCardError>(CryptographicFailed(operation, details));

    /// <summary>
    /// Creates failed Result with MAC verification error.
    /// REPLACES: Result.Failure&lt;T, SmartCardError&gt;(SmartCardError.SecurityError("MAC verification failed"))
    /// </summary>
    public static Result<T, SmartCardError> FailureMacVerification<T>() =>
        Result.Failure<T, SmartCardError>(MacVerificationFailed());

    /// <summary>
    /// Creates failed Result with TLV tag not found error.
    /// REPLACES: Result.Failure&lt;T, SmartCardError&gt;(SmartCardError.InvalidData(...))
    /// </summary>
    public static Result<T, SmartCardError> FailureTlvTagNotFound<T>(string fieldName, byte tag) =>
        Result.Failure<T, SmartCardError>(TlvTagNotFound(fieldName, tag));

    /// <summary>
    /// Creates failed Result from exception with proper error categorization.
    /// REPLACES: Result.Try patterns with manual exception handling
    /// </summary>
    public static Result<T, SmartCardError> FailureFromException<T>(Exception ex, string operation)
    {
        return ex switch
        {
            ArgumentNullException argEx => FailureNullArgument<T>(argEx.ParamName ?? "parameter"),
            ArgumentException argEx => Result.Failure<T, SmartCardError>(SmartCardError.InvalidArgument(argEx.Message)),
            InvalidOperationException => Result.Failure<T, SmartCardError>(SmartCardError.InvalidData(ex.Message)),
            UnauthorizedAccessException => Result.Failure<T, SmartCardError>(SmartCardError.SecurityError(ex.Message)),
            TimeoutException => Result.Failure<T, SmartCardError>(SmartCardError.CommunicationError($"Operation timed out: {operation}")),
            _ => Result.Failure<T, SmartCardError>(SmartCardError.UnexpectedError($"{operation} failed", ex))
        };
    }

}