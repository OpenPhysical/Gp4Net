using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Tool.Services.CardCommunication;
using Gp4Net.Tool.Services.CardCommunication.Wsct;
using JetBrains.Annotations;
using WSCT.Wrapper;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Service for enumerating and validating smart card readers.
/// Provides the single source of truth for reader discovery and resolution.
/// </summary>
/// <remarks>
/// Physical readers are auto-discovered via WSCT.
/// Virtual readers (format: virtual:profile.json) are not auto-discovered but are resolvable.
/// </remarks>
[PublicAPI]
public static class ReaderEnumerationService
{
    private const string VirtualPrefix = "virtual:";

    /// <summary>
    /// Enumerates available physical card readers using WSCT.
    /// Virtual readers are not included in enumeration results.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Array of physical reader names, or error</returns>
    public static Task<Result<string[], SmartCardError>> EnumeratePhysicalReadersAsync(
        CancellationToken cancellationToken = default
    )
    {
        try
        {
            using var context = new WsctCardContextWrapper();
            var errorCode = context.Establish();

            if (errorCode != ErrorCode.Success)
            {
                return Task.FromResult(
                    Result.Failure<string[], SmartCardError>(
                        SmartCardError.CommunicationError($"Failed to establish PC/SC context: {errorCode}")
                    )
                );
            }

            errorCode = context.ListReaders("");
            if (errorCode != ErrorCode.Success)
            {
                // No readers found is not an error, just return empty array
                return Task.FromResult(Result.Success<string[], SmartCardError>(Array.Empty<string>()));
            }

            var readers = context.Readers?.ToArray() ?? Array.Empty<string>();
            return Task.FromResult(Result.Success<string[], SmartCardError>(readers));
        }
        catch (Exception ex)
        {
            return Task.FromResult(
                Result.Failure<string[], SmartCardError>(
                    SmartCardError.CommunicationError($"Failed to enumerate readers: {ex.Message}")
                )
            );
        }
    }

    /// <summary>
    /// Determines if a reader specification is resolvable (can be connected to).
    /// Physical readers must exist in the system.
    /// Virtual readers must have valid format but profile existence is checked during connection.
    /// </summary>
    /// <param name="readerSpec">Reader specification to validate</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if the reader spec is potentially resolvable</returns>
    public static async Task<Result<bool, SmartCardError>> IsReaderResolvableAsync(
        string readerSpec,
        CancellationToken cancellationToken = default
    )
    {
        if (string.IsNullOrWhiteSpace(readerSpec))
        {
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument("Reader specification cannot be empty")
            );
        }

        // Check if it's a virtual reader
        if (IsVirtualReader(readerSpec))
        {
            // Virtual readers are resolvable if they have the correct format
            // Actual profile validation happens during connection
            return ParseVirtualReaderSpec(readerSpec)
                .Map(_ => true);
        }

        // For physical readers, check if it exists in the system
        var readersResult = await EnumeratePhysicalReadersAsync(cancellationToken);
        return readersResult.Map(readers =>
            readers.Any(r => string.Equals(r, readerSpec, StringComparison.OrdinalIgnoreCase))
        );
    }

    /// <summary>
    /// Determines if a reader specification refers to a virtual reader.
    /// </summary>
    /// <param name="readerSpec">Reader specification to check</param>
    /// <returns>True if the spec refers to a virtual reader</returns>
    public static bool IsVirtualReader(string readerSpec)
    {
        return !string.IsNullOrWhiteSpace(readerSpec) &&
               readerSpec.StartsWith(VirtualPrefix, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Parses a virtual reader specification to extract the profile path.
    /// </summary>
    /// <param name="spec">Virtual reader specification in format "virtual:profile.json"</param>
    /// <returns>The profile path, or error if invalid format</returns>
    public static Result<string, SmartCardError> ParseVirtualReaderSpec(string spec)
    {
        if (!IsVirtualReader(spec))
        {
            return Result.Failure<string, SmartCardError>(
                SmartCardError.InvalidArgument($"Not a virtual reader specification: {spec}")
            );
        }

        var profilePath = spec.Substring(VirtualPrefix.Length).Trim();
        
        if (string.IsNullOrWhiteSpace(profilePath))
        {
            return Result.Failure<string, SmartCardError>(
                SmartCardError.InvalidArgument("Virtual reader profile path cannot be empty")
            );
        }

        return Result.Success<string, SmartCardError>(profilePath);
    }

    /// <summary>
    /// Selects a reader from available readers based on partial matching.
    /// Used for fuzzy matching of reader names.
    /// </summary>
    /// <param name="requestedReader">Requested reader name (can be partial)</param>
    /// <param name="availableReaders">List of available readers</param>
    /// <returns>Selected reader name, or error if no match found</returns>
    public static Result<string, SmartCardError> SelectReaderByPartialMatch(
        string requestedReader,
        string[] availableReaders
    )
    {
        if (availableReaders.Length == 0)
        {
            return Result.Failure<string, SmartCardError>(
                SmartCardError.CommunicationError("No card readers found on the system")
            );
        }

        // Try exact match first using functional approach
        var exactMatches = availableReaders
            .Where(r => string.Equals(r, requestedReader, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        
        if (exactMatches.Length > 0)
        {
            return Result.Success<string, SmartCardError>(exactMatches.First());
        }

        // Try partial match
        var partialMatches = availableReaders
            .Where(r => r.Contains(requestedReader, StringComparison.OrdinalIgnoreCase))
            .ToArray();

        return partialMatches.Length switch
        {
            0 => Result.Failure<string, SmartCardError>(
                SmartCardError.InvalidArgument($"No reader found matching: {requestedReader}")
            ),
            1 => Result.Success<string, SmartCardError>(partialMatches.First()),
            _ => Result.Failure<string, SmartCardError>(
                SmartCardError.InvalidArgument(
                    $"Multiple readers match '{requestedReader}': {string.Join(", ", partialMatches)}"
                )
            )
        };
    }
}