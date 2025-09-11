using System.IO;
using CSharpFunctionalExtensions;

namespace Gp4Net.Tests.Infrastructure;

/// <summary>
/// Extension methods for trace-based card service operations.
/// Provides utilities for creating trace-based test environments.
/// </summary>
public static class TraceBasedCardServiceExtensions
{
    /// <summary>
    /// Creates a trace-based reader name from a trace file path.
    /// Used to identify the trace file for test execution.
    /// </summary>
    /// <param name="tracePath">Path to the trace file.</param>
    /// <param name="operations">Optional operations filter.</param>
    /// <returns>Reader name formatted for trace-based testing.</returns>
    public static string CreateTraceReaderName(string tracePath, Maybe<string> operations)
    {
        return Maybe<string>
            .From(tracePath)
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Match(
                path =>
                {
                    string fileName = Path.GetFileName(path);
                    return operations
                        .Where(ops => !string.IsNullOrWhiteSpace(ops))
                        .Match(
                            ops => $"TraceReader[{fileName}:{ops}]",
                            () => $"TraceReader[{fileName}]"
                        );
                },
                () => "TraceReader[Invalid]"
            );
    }

    /// <summary>
    /// Creates a trace-based reader name from a trace file path without operations filter.
    /// Overload for backward compatibility with string parameter.
    /// </summary>
    /// <param name="tracePath">Path to the trace file.</param>
    /// <param name="operations">Optional operations filter as string.</param>
    /// <returns>Reader name formatted for trace-based testing.</returns>
    public static string CreateTraceReaderName(string tracePath, string operations)
    {
        return CreateTraceReaderName(tracePath, Maybe<string>.From(operations));
    }

    /// <summary>
    /// Creates a trace-based reader name from a trace file path without operations filter.
    /// Overload for backward compatibility.
    /// </summary>
    /// <param name="tracePath">Path to the trace file.</param>
    /// <returns>Reader name formatted for trace-based testing.</returns>
    public static string CreateTraceReaderName(string tracePath)
    {
        return CreateTraceReaderName(tracePath, Maybe<string>.None);
    }

    /// <summary>
    /// Validates that a trace file exists and is readable.
    /// </summary>
    /// <param name="tracePath">Path to the trace file to validate.</param>
    /// <returns>Result indicating if the trace file is valid.</returns>
    public static Result<string, string> ValidateTraceFile(string tracePath)
    {
        var pathResult = Maybe<string>
            .From(tracePath)
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .ToResult("Trace path cannot be null or empty");

        return pathResult.Match(
            path => File.Exists(path)
                ? Result.Success<string, string>(path)
                : Result.Failure<string, string>($"Trace file not found: {path}"),
            error => Result.Failure<string, string>(error)
        );
    }

    /// <summary>
    /// Gets the file extension of a trace file for type identification.
    /// </summary>
    /// <param name="tracePath">Path to the trace file.</param>
    /// <returns>File extension or "unknown" if path is invalid.</returns>
    public static string GetTraceFileType(string tracePath)
    {
        return Maybe<string>
            .From(tracePath)
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Map(path => Path.GetExtension(path).TrimStart('.').ToLowerInvariant())
            .Match(ext => string.IsNullOrWhiteSpace(ext) ? "unknown" : ext, () => "unknown");
    }
}
