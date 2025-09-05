// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.Services;

/// <summary>
/// Static service for translating smart card errors and status words into human-readable messages.
/// Provides functional methods for error translation without requiring service instantiation.
/// </summary>
/// <remarks>
/// All methods are static and pure functional, mapping error codes and status words
/// to descriptive messages based on GlobalPlatform Card Specification v2.3.1.
/// This service extracts error translation logic from CLI commands.
/// </remarks>
[PublicAPI]
public static class ErrorTranslationService
{
    /// <summary>
    /// Detailed error information structure containing translated error details.
    /// </summary>
    /// <param name="StatusWord">The original status word if available</param>
    /// <param name="ErrorCode">The smart card error code</param>
    /// <param name="HumanMessage">Human-readable error message</param>
    /// <param name="TechnicalDetails">Technical details about the error</param>
    /// <param name="PossibleCauses">List of possible causes for the error</param>
    /// <param name="RecommendedActions">List of recommended actions to resolve the error</param>
    /// <param name="Severity">Error severity level</param>
    public sealed record ErrorDetails(
        Maybe<ushort> StatusWord,
        string ErrorCode,
        string HumanMessage,
        Maybe<string> TechnicalDetails,
        ImmutableList<string> PossibleCauses,
        ImmutableList<string> RecommendedActions,
        ErrorSeverity Severity
    );

    /// <summary>
    /// Error severity enumeration for categorizing errors.
    /// </summary>
    public enum ErrorSeverity
    {
        /// <summary>Informational message, not an error</summary>
        Info,
        /// <summary>Warning that doesn't prevent operation</summary>
        Warning,
        /// <summary>Error that prevents operation but is recoverable</summary>
        Error,
        /// <summary>Critical error that may cause permanent damage</summary>
        Critical
    }

    /// <summary>
    /// Translates a SmartCardError into a human-readable error message.
    /// Maps status words and error codes to user-friendly descriptions based on GlobalPlatform specifications.
    /// </summary>
    /// <param name="error">The SmartCardError to translate</param>
    /// <returns>
    /// Human-readable error message suitable for display to users.
    /// If the status word is not recognized, returns the original error message.
    /// </returns>
    /// <remarks>
    /// This method extracts error translation logic from DeleteCommand.GetHumanReadableError method.
    /// It maps GlobalPlatform Card Specification v2.3.1 status words to user-friendly descriptions.
    /// 
    /// Status word mappings include:
    /// - 0x6283: Application is locked (personalized state)
    /// - 0x6581: Memory allocation problem
    /// - 0x6982: Security status not satisfied
    /// - 0x6985: Cannot delete - application has dependencies
    /// - 0x6A80: Incorrect parameters in command data
    /// - 0x6A82: Application or package not found
    /// - And many more from the GlobalPlatform specification
    /// </remarks>
    public static string TranslateStatusWord(SmartCardError error)
    {
        return error.StatusWord.Match(
            statusWord => TranslateStatusWordValue(statusWord),
            () => error.Message
        );
    }

    /// <summary>
    /// Converts a SmartCardError to comprehensive human-readable error information.
    /// Provides detailed error analysis including causes and recommended actions.
    /// </summary>
    /// <param name="error">The SmartCardError to analyze</param>
    /// <returns>
    /// ErrorDetails structure containing comprehensive error information including
    /// human-readable message, possible causes, and recommended actions.
    /// </returns>
    /// <remarks>
    /// This method provides enhanced error reporting beyond simple message translation.
    /// It analyzes the error context and provides actionable guidance for resolution.
    /// </remarks>
    public static ErrorDetails GetHumanReadableError(SmartCardError error)
    {
        return error.StatusWord.Match(
            statusWord => GenerateDetailedErrorInfo(error, statusWord),
            () => GenerateGenericErrorInfo(error)
        );
    }

    /// <summary>
    /// Translates a raw status word value to a human-readable message.
    /// </summary>
    /// <param name="statusWord">The status word to translate</param>
    /// <returns>Human-readable description of the status word</returns>
    private static string TranslateStatusWordValue(ushort statusWord)
    {
        return statusWord switch
        {
            // Success cases
            0x9000 => "Operation completed successfully",

            // Warning/informational status words
            0x6283 => "Application is locked (personalized state)",
            0x6300 => "Authentication failed - verify counter may be decreased",

            // Memory and resource errors
            0x6581 => "Memory allocation problem",
            0x6A84 => "Not enough memory space in file",

            // Security-related errors
            0x6982 => "Security status not satisfied - authentication required",
            0x6983 => "Authentication method blocked",
            0x6984 => "Referenced data invalidated",
            0x6987 => "Expected secure messaging data objects missing",
            0x6988 => "Secure messaging data objects incorrect",

            // Condition and dependency errors
            0x6985 => "Cannot delete - application has dependencies or conditions not satisfied",
            0x6986 => "Command not allowed - no current EF or wrong file type",

            // Parameter and data errors
            0x6A80 => "Incorrect parameters in command data",
            0x6A81 => "Function not supported",
            0x6A82 => "Application or package not found",
            0x6A83 => "Record not found",
            0x6A85 => "Lc inconsistent with TLV structure",
            0x6A86 => "Incorrect P1/P2 parameters",
            0x6A87 => "Lc inconsistent with P1-P2",
            0x6A88 => "Referenced data not found",

            // Length and format errors
            0x6700 => "Wrong length",
            0x6B00 => "Wrong parameters P1-P2",
            0x6C00 => "Wrong Le field",

            // Instruction errors
            0x6D00 => "Invalid instruction (command not supported)",
            0x6E00 => "Invalid class",
            0x6F00 => "No precise diagnosis available",

            // Handle ranges
            _ when (statusWord & 0xFF00) == 0x6100 => 
                $"More data available ({statusWord & 0xFF} bytes)",
            _ when (statusWord & 0xFF00) == 0x6C00 => 
                $"Wrong length ({statusWord & 0xFF} bytes expected)",

            // Default case
            _ => $"Unknown status word: 0x{statusWord:X4}"
        };
    }

    /// <summary>
    /// Generates detailed error information for a status word-based error.
    /// </summary>
    private static ErrorDetails GenerateDetailedErrorInfo(SmartCardError error, ushort statusWord)
    {
        var (severity, causes, actions) = AnalyzeStatusWordContext(statusWord);

        return new ErrorDetails(
            StatusWord: Maybe<ushort>.From(statusWord),
            ErrorCode: error.Code,
            HumanMessage: TranslateStatusWordValue(statusWord),
            TechnicalDetails: Maybe<string>.From($"Status Word: 0x{statusWord:X4}"),
            PossibleCauses: causes,
            RecommendedActions: actions,
            Severity: severity
        );
    }

    /// <summary>
    /// Generates error information for non-status word errors.
    /// </summary>
    private static ErrorDetails GenerateGenericErrorInfo(SmartCardError error)
    {
        var severity = DetermineGenericErrorSeverity(error.Code);
        var (causes, actions) = AnalyzeGenericErrorContext(error.Code);

        return new ErrorDetails(
            StatusWord: Maybe<ushort>.None,
            ErrorCode: error.Code,
            HumanMessage: error.Message,
            TechnicalDetails: error.InnerException.Match(
                ex => Maybe<string>.From($"Inner exception: {ex.Message}"),
                () => Maybe<string>.None
            ),
            PossibleCauses: causes,
            RecommendedActions: actions,
            Severity: severity
        );
    }

    /// <summary>
    /// Analyzes status word context to provide causes and recommended actions.
    /// </summary>
    private static (ErrorSeverity Severity, ImmutableList<string> Causes, ImmutableList<string> Actions) 
        AnalyzeStatusWordContext(ushort statusWord)
    {
        return statusWord switch
        {
            0x6982 => (
                ErrorSeverity.Error,
                ImmutableList.Create(
                    "Secure channel not established",
                    "Authentication required",
                    "Insufficient privileges"
                ),
                ImmutableList.Create(
                    "Establish secure channel with valid keys",
                    "Verify authentication state",
                    "Check required privileges for operation"
                )
            ),

            0x6985 => (
                ErrorSeverity.Error,
                ImmutableList.Create(
                    "Application has dependent objects",
                    "Lifecycle state prevents deletion",
                    "Security conditions not met"
                ),
                ImmutableList.Create(
                    "Delete dependent objects first",
                    "Use delete-related option if appropriate",
                    "Check application lifecycle state"
                )
            ),

            0x6A82 => (
                ErrorSeverity.Error,
                ImmutableList.Create(
                    "Application not installed on card",
                    "Incorrect AID specified",
                    "Application already deleted"
                ),
                ImmutableList.Create(
                    "Verify AID is correct",
                    "Check installed applications with GET STATUS",
                    "Ensure application exists before attempting operation"
                )
            ),

            0x6283 => (
                ErrorSeverity.Warning,
                ImmutableList.Create(
                    "Application is personalized",
                    "Application locked by card issuer"
                ),
                ImmutableList.Create(
                    "Application may be protected - proceed with caution",
                    "Contact card issuer for unlock procedures"
                )
            ),

            _ => (
                ErrorSeverity.Error,
                ImmutableList.Create("Refer to GlobalPlatform specification for details"),
                ImmutableList.Create("Check card documentation", "Verify command parameters")
            )
        };
    }

    /// <summary>
    /// Analyzes generic error context for non-status word errors.
    /// </summary>
    private static (ImmutableList<string> Causes, ImmutableList<string> Actions) AnalyzeGenericErrorContext(string errorCode)
    {
        return errorCode switch
        {
            "COMMUNICATION_ERROR" => (
                ImmutableList.Create(
                    "Card not present in reader",
                    "Reader communication failure",
                    "PC/SC subsystem error"
                ),
                ImmutableList.Create(
                    "Ensure card is properly inserted",
                    "Check reader connection",
                    "Restart PC/SC service if necessary"
                )
            ),

            "SECURITY_ERROR" => (
                ImmutableList.Create(
                    "Invalid authentication keys",
                    "Secure channel establishment failed",
                    "Cryptographic operation failed"
                ),
                ImmutableList.Create(
                    "Verify key sets are correct",
                    "Check key diversification",
                    "Ensure secure channel is established"
                )
            ),

            "INVALID_DATA" => (
                ImmutableList.Create(
                    "Malformed command data",
                    "Invalid file format",
                    "Incorrect parameter values"
                ),
                ImmutableList.Create(
                    "Verify input data format",
                    "Check parameter values",
                    "Validate file integrity"
                )
            ),

            _ => (
                ImmutableList.Create("Unexpected error condition"),
                ImmutableList.Create("Check logs for detailed error information", "Retry operation")
            )
        };
    }

    /// <summary>
    /// Determines error severity for generic error codes.
    /// </summary>
    private static ErrorSeverity DetermineGenericErrorSeverity(string errorCode)
    {
        return errorCode switch
        {
            "COMMUNICATION_ERROR" => ErrorSeverity.Error,
            "SECURITY_ERROR" => ErrorSeverity.Critical,
            "INVALID_DATA" => ErrorSeverity.Error,
            "INVALID_ARGUMENT" => ErrorSeverity.Error,
            "UNSUPPORTED" => ErrorSeverity.Warning,
            _ => ErrorSeverity.Error
        };
    }
}