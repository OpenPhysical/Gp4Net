using System;
using System.Collections.Generic;
using CSharpFunctionalExtensions;

namespace Gp4Net.Core;

/// <summary>
/// Represents an error that occurred during smart card operations.
/// </summary>
public record SmartCardError(
    string Code,
    string Message,
    Maybe<ushort> StatusWord,
    Maybe<Exception> InnerException,
    Maybe<IReadOnlyDictionary<string, object>> Context
)
{
    /// <summary>
    /// Creates a simple error with just code and message.
    /// </summary>
    private static SmartCardError Simple(string code, string message)
    {
        return new(
            code,
            message,
            Maybe<ushort>.None,
            Maybe<Exception>.None,
            Maybe<IReadOnlyDictionary<string, object>>.None
        );
    }

    /// <summary>
    /// Creates an error with status word.
    /// </summary>
    private static SmartCardError WithStatus(string code, string message, ushort sw)
    {
        return new(
            code,
            message,
            Maybe<ushort>.From(sw),
            Maybe<Exception>.None,
            Maybe<IReadOnlyDictionary<string, object>>.None
        );
    }

    /// <summary>
    /// Creates an error from a status word.
    /// </summary>
    public static SmartCardError FromStatusWord(ushort sw)
    {
        return WithStatus($"SW_{sw:X4}", GetStatusWordDescription(sw), sw);
    }

    /// <summary>
    /// Creates an error for a communication failure.
    /// </summary>
    public static SmartCardError CommunicationError(string message, Maybe<Exception> ex = default)
    {
        return new(
            "COMMUNICATION_ERROR",
            message,
            Maybe<ushort>.None,
            ex,
            Maybe<IReadOnlyDictionary<string, object>>.None
        );
    }

    /// <summary>
    /// Creates an error for a security failure.
    /// </summary>
    public static SmartCardError SecurityError(string message, Maybe<ushort> sw = default)
    {
        return new(
            "SECURITY_ERROR",
            message,
            sw,
            Maybe<Exception>.None,
            Maybe<IReadOnlyDictionary<string, object>>.None
        );
    }

    /// <summary>
    /// Creates an error for invalid data.
    /// </summary>
    public static SmartCardError InvalidData(string message)
    {
        return Simple("INVALID_DATA", message);
    }

    /// <summary>
    /// Creates an error for invalid arguments.
    /// </summary>
    public static SmartCardError InvalidArgument(string message)
    {
        return Simple("INVALID_ARGUMENT", message);
    }

    /// <summary>
    /// Creates an error for unsupported operations.
    /// </summary>
    public static SmartCardError Unsupported(string message)
    {
        return Simple("UNSUPPORTED", message);
    }

    /// <summary>
    /// Creates an error for invalid response data.
    /// </summary>
    public static SmartCardError InvalidResponse(string message)
    {
        return Simple("INVALID_RESPONSE", message);
    }

    /// <summary>
    /// Creates an error for card-specific errors.
    /// </summary>
    public static SmartCardError CardError(string message)
    {
        return Simple("CARD_ERROR", message);
    }

    /// <summary>
    /// Creates an error for unsupported instructions (6D00).
    /// </summary>
    public static SmartCardError InstructionNotSupported()
    {
        return WithStatus("INSTRUCTION_NOT_SUPPORTED", "Invalid instruction", 0x6D00);
    }

    /// <summary>
    /// Creates an error for wrong length (6700).
    /// </summary>
    public static SmartCardError WrongLength()
    {
        return WithStatus("WRONG_LENGTH", "Wrong length", 0x6700);
    }

    /// <summary>
    /// Creates an error for wrong length with custom message (6700).
    /// </summary>
    public static SmartCardError WrongLength(string message)
    {
        return WithStatus("WRONG_LENGTH", message, 0x6700);
    }

    /// <summary>
    /// Creates an error for incorrect data (6A80).
    /// </summary>
    public static SmartCardError IncorrectData()
    {
        return WithStatus("INCORRECT_DATA", "Wrong data", 0x6A80);
    }

    /// <summary>
    /// Creates an error for security status not satisfied (6982).
    /// </summary>
    public static SmartCardError SecurityStatusNotSatisfied()
    {
        return WithStatus("SECURITY_STATUS_NOT_SATISFIED", "Security status not satisfied", 0x6982);
    }

    /// <summary>
    /// Creates an error for security status not satisfied with custom message (6982).
    /// </summary>
    public static SmartCardError SecurityStatusNotSatisfied(string message)
    {
        return WithStatus("SECURITY_STATUS_NOT_SATISFIED", message, 0x6982);
    }

    /// <summary>
    /// Creates an error for algorithm not supported (6A81).
    /// </summary>
    public static SmartCardError AlgorithmNotSupported()
    {
        return WithStatus("ALGORITHM_NOT_SUPPORTED", "Algorithm not supported", 0x6A81);
    }

    /// <summary>
    /// Creates an error for conditions of use not satisfied (6985).
    /// </summary>
    public static SmartCardError ConditionsOfUseNotSatisfied()
    {
        return WithStatus("CONDITIONS_OF_USE_NOT_SATISFIED", "Conditions of use not satisfied", 0x6985);
    }

    /// <summary>
    /// Creates an error for referenced data not found (6A88).
    /// </summary>
    public static SmartCardError ReferencedDataNotFound()
    {
        return WithStatus("REFERENCED_DATA_NOT_FOUND", "Referenced data not found", 0x6A88);
    }

    /// <summary>
    /// Creates an error for cryptographic operations.
    /// </summary>
    public static SmartCardError CryptographicError(string message)
    {
        return Simple("CRYPTOGRAPHIC_ERROR", message);
    }

    /// <summary>
    /// Creates an error for data integrity failures.
    /// </summary>
    public static SmartCardError IntegrityError(string message)
    {
        return Simple("INTEGRITY_ERROR", message);
    }

    /// <summary>
    /// Creates an error for file not found (6A82).
    /// </summary>
    public static SmartCardError FileNotFound()
    {
        return WithStatus("FILE_NOT_FOUND", "File not found", 0x6A82);
    }

    /// <summary>
    /// Creates an error for authentication failures.
    /// </summary>
    public static SmartCardError AuthenticationFailed(string message)
    {
        return WithStatus("AUTHENTICATION_FAILED", message, 0x6300);
    }

    /// <summary>
    /// Creates an error for blocked authentication due to too many attempts.
    /// </summary>
    public static SmartCardError AuthenticationBlocked(string message)
    {
        return Simple("AUTHENTICATION_BLOCKED", message);
    }

    /// <summary>
    /// Creates an error for initialization failures.
    /// </summary>
    public static SmartCardError InitializationFailed(string message)
    {
        return Simple("INITIALIZATION_FAILED", message);
    }

    /// <summary>
    /// Creates an error for unexpected errors.
    /// </summary>
    public static SmartCardError UnexpectedError(string message, Maybe<Exception> ex = default)
    {
        return new(
            "UNEXPECTED_ERROR",
            message,
            Maybe<ushort>.None,
            ex,
            Maybe<IReadOnlyDictionary<string, object>>.None
        );
    }

    /// <summary>
    /// Creates an error for conditions not satisfied (6985).
    /// </summary>
    public static SmartCardError ConditionsNotSatisfied()
    {
        return WithStatus("CONDITIONS_NOT_SATISFIED", "Conditions of use not satisfied", 0x6985);
    }

    /// <summary>
    /// Creates an error for incorrect P1 P2 parameters (6A86).
    /// </summary>
    public static SmartCardError IncorrectP1P2()
    {
        return WithStatus("INCORRECT_P1P2", "Incorrect P1 P2", 0x6A86);
    }

    /// <summary>
    /// Creates an error for incorrect P1 P2 parameters with custom message (6A86).
    /// </summary>
    public static SmartCardError IncorrectP1P2(string message)
    {
        return WithStatus("INCORRECT_P1P2", message, 0x6A86);
    }

    /// <summary>
    /// Creates an error for cancelled operations.
    /// </summary>
    public static SmartCardError OperationCancelled(string message)
    {
        return Simple("OPERATION_CANCELLED", message);
    }

    /// <summary>
    /// Adds context information to the error.
    /// </summary>
    public SmartCardError WithContext(string key, object value)
    {
        IReadOnlyDictionary<string, object> currentContext = Context.GetValueOrDefault(
            new Dictionary<string, object>()
        );
        Dictionary<string, object> newContext = new Dictionary<string, object>(currentContext)
        {
            [key] = value,
        };
        return this with { Context = Maybe<IReadOnlyDictionary<string, object>>.From(newContext) };
    }

    /// <summary>
    /// Adds multiple context values to the error.
    /// </summary>
    public SmartCardError WithContext(IReadOnlyDictionary<string, object> additionalContext)
    {
        IReadOnlyDictionary<string, object> currentContext = Context.GetValueOrDefault(
            new Dictionary<string, object>()
        );
        Dictionary<string, object> newContext = new Dictionary<string, object>(currentContext);
        foreach (KeyValuePair<string, object> kvp in additionalContext)
        {
            newContext[kvp.Key] = kvp.Value;
        }
        return this with { Context = Maybe<IReadOnlyDictionary<string, object>>.From(newContext) };
    }

    private static string GetStatusWordDescription(ushort sw)
    {
        return sw switch
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
            _ => $"Unknown status word: {sw:X4}",
        };
    }

    public override string ToString()
    {
        return StatusWord
            .Map(sw => $"{Code}: {Message} (SW={sw:X4})")
            .GetValueOrDefault($"{Code}: {Message}");
    }
}

/// <summary>
/// Common error codes for smart card operations.
/// </summary>
public static class ErrorCodes
{
    public const string Success = "SUCCESS";
    public const string CommunicationError = "COMMUNICATION_ERROR";
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

/// <summary>
/// Strongly typed error for null parameter violations.
/// </summary>
public record NullParameterError(string ParameterName)
    : SmartCardError(
        "NULL_PARAMETER",
        $"Parameter '{ParameterName}' cannot be null",
        Maybe<ushort>.None,
        Maybe<Exception>.None,
        Maybe<IReadOnlyDictionary<string, object>>.None
    );

/// <summary>
/// Strongly typed error for invalid length violations.
/// </summary>
public record InvalidLengthError(string Field, int Expected, int Actual)
    : SmartCardError(
        "INVALID_LENGTH",
        $"Field '{Field}' must be {Expected} bytes, got {Actual}",
        Maybe<ushort>.None,
        Maybe<Exception>.None,
        Maybe<IReadOnlyDictionary<string, object>>.None
    );

/// <summary>
/// Strongly typed error for invalid format violations.
/// </summary>
public record InvalidFormatError(string Field, string ExpectedFormat)
    : SmartCardError(
        "INVALID_FORMAT",
        $"Field '{Field}' has invalid format, expected {ExpectedFormat}",
        Maybe<ushort>.None,
        Maybe<Exception>.None,
        Maybe<IReadOnlyDictionary<string, object>>.None
    );

/// <summary>
/// Strongly typed error for cryptographic operation failures.
/// </summary>
public record CryptographicError(string Operation, string Details)
    : SmartCardError(
        "CRYPTOGRAPHIC_ERROR",
        $"Cryptographic operation '{Operation}' failed: {Details}",
        Maybe<ushort>.None,
        Maybe<Exception>.None,
        Maybe<IReadOnlyDictionary<string, object>>.None
    );

/// <summary>
/// Strongly typed error for authentication failures.
/// </summary>
public record AuthenticationFailedError(string Reason)
    : SmartCardError(
        "AUTHENTICATION_FAILED",
        $"Authentication failed: {Reason}",
        Maybe<ushort>.From(0x6300),
        Maybe<Exception>.None,
        Maybe<IReadOnlyDictionary<string, object>>.None
    );

/// <summary>
/// Strongly typed error for cryptogram verification failures.
/// </summary>
public record CryptogramVerificationError(string Details)
    : SmartCardError(
        "CRYPTOGRAM_VERIFICATION_FAILED",
        $"Cryptogram verification failed: {Details}",
        Maybe<ushort>.None,
        Maybe<Exception>.None,
        Maybe<IReadOnlyDictionary<string, object>>.None
    );

/// <summary>
/// Strongly typed error for unsupported protocol operations.
/// </summary>
public record UnsupportedProtocolError(string Protocol)
    : SmartCardError(
        "UNSUPPORTED_PROTOCOL",
        $"Protocol '{Protocol}' is not supported",
        Maybe<ushort>.None,
        Maybe<Exception>.None,
        Maybe<IReadOnlyDictionary<string, object>>.None
    );

/// <summary>
/// Strongly typed error for unsupported implementation features.
/// </summary>
public record UnsupportedImplementationError(string Implementation)
    : SmartCardError(
        "UNSUPPORTED_IMPLEMENTATION",
        $"Implementation '{Implementation}' is not supported",
        Maybe<ushort>.None,
        Maybe<Exception>.None,
        Maybe<IReadOnlyDictionary<string, object>>.None
    );

/// <summary>
/// Strongly typed error for invalid key operations.
/// </summary>
public record InvalidKeyError(string KeyType, string Reason)
    : SmartCardError(
        "INVALID_KEY",
        $"Invalid {KeyType} key: {Reason}",
        Maybe<ushort>.None,
        Maybe<Exception>.None,
        Maybe<IReadOnlyDictionary<string, object>>.None
    );

/// <summary>
/// Strongly typed error for missing required data.
/// </summary>
public record MissingDataError(string DataType)
    : SmartCardError(
        "MISSING_DATA",
        $"Required data '{DataType}' is missing",
        Maybe<ushort>.None,
        Maybe<Exception>.None,
        Maybe<IReadOnlyDictionary<string, object>>.None
    );

/// <summary>
/// Strongly typed error for empty data violations.
/// </summary>
public record EmptyDataError(string FieldName)
    : SmartCardError(
        "EMPTY_DATA",
        $"Field '{FieldName}' cannot be empty",
        Maybe<ushort>.None,
        Maybe<Exception>.None,
        Maybe<IReadOnlyDictionary<string, object>>.None
    );

/// <summary>
/// Strongly typed error for invalid data violations.
/// </summary>
public record InvalidDataError(string Field, string Reason)
    : SmartCardError(
        "INVALID_DATA",
        $"Field '{Field}': {Reason}",
        Maybe<ushort>.None,
        Maybe<Exception>.None,
        Maybe<IReadOnlyDictionary<string, object>>.None
    );
