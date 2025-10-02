using System;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Services;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Static functional service for resolving reader names from user input.
/// Provides auto-detection, exact matching, and partial matching capabilities.
/// </summary>
[PublicAPI]
public static class ReaderNameResolver
{
    /// <summary>
    /// Resolves a reader name from user input using functional composition.
    /// Handles auto-detection, exact matching, partial matching, and error cases.
    /// </summary>
    /// <param name="readerInput">The user-provided reader name input.</param>
    /// <param name="cardService">The smart card service for querying available readers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The resolved reader name or an error.</returns>
    public static async Task<Result<string, SmartCardError>> ResolveAsync(
        Maybe<string> readerInput,
        ISmartCardService cardService,
        CancellationToken cancellationToken = default
    )
    {
        return await Maybe
            .From(cardService)
            .ToResult(SmartCardError.InvalidArgument("Card service cannot be null"))
            .Bind(async service =>
                await ResolveReaderNameInternal(readerInput, service, cancellationToken)
            );
    }

    private static async Task<Result<string, SmartCardError>> ResolveReaderNameInternal(
        Maybe<string> readerInput,
        ISmartCardService cardService,
        CancellationToken cancellationToken
    )
    {
        // Get available readers first
        var readersResult = await cardService.GetReadersAsync(cancellationToken);
        if (readersResult.IsFailure)
        {
            return Result.Failure<string, SmartCardError>(
                SmartCardError.CommunicationError(
                    $"Failed to enumerate readers: {readersResult.Error.Message}"
                )
            );
        }

        ImmutableList<string> availableReaders = [.. readersResult.Value];

        // Handle empty reader list
        if (availableReaders.IsEmpty)
        {
            return Result.Failure<string, SmartCardError>(
                SmartCardError.CommunicationError("No card readers found on this system")
            );
        }

        return readerInput.Match(
            input => ResolveWithInput(input, availableReaders),
            () => AutoDetectReader(availableReaders)
        );
    }

    /// <summary>
    /// Resolves reader name when user provided specific input.
    /// </summary>
    private static Result<string, SmartCardError> ResolveWithInput(
        string input,
        ImmutableList<string> availableReaders
    )
    {
        // Handle virtual reader format: virtual:profile.json
        if (input.StartsWith("virtual:", StringComparison.OrdinalIgnoreCase))
        {
            // Return the virtual reader specification as-is for handling by the connection service
            return Result.Success<string, SmartCardError>(input);
        }

        // Handle auto-detection keywords
        if (IsAutoDetectionKeyword(input))
        {
            return AutoDetectReader(availableReaders);
        }

        // Try exact match first (case-sensitive)
        ImmutableList<string> exactMatches =
        [
            .. availableReaders.Where(reader =>
                string.Equals(reader, input, StringComparison.Ordinal)
            ),
        ];

        if (exactMatches.Count == 1)
        {
            return Result.Success<string, SmartCardError>(exactMatches.First());
        }

        // Try exact match case-insensitive
        ImmutableList<string> exactMatchesInsensitive =
        [
            .. availableReaders.Where(reader =>
                string.Equals(reader, input, StringComparison.OrdinalIgnoreCase)
            ),
        ];

        if (exactMatchesInsensitive.Count == 1)
        {
            return Result.Success<string, SmartCardError>(exactMatchesInsensitive.First());
        }

        // Try partial matching (case-insensitive)
        ImmutableList<string> partialMatches =
        [
            .. availableReaders.Where(reader =>
                reader.Contains(input, StringComparison.OrdinalIgnoreCase)
            ),
        ];

        return partialMatches.Count switch
        {
            0 => CreateNoMatchError(input, availableReaders),
            1 => Result.Success<string, SmartCardError>(partialMatches.First()),
            _ => CreateMultipleMatchError(input, partialMatches),
        };
    }

    /// <summary>
    /// Auto-detects the first available reader for connection.
    /// </summary>
    private static Result<string, SmartCardError> AutoDetectReader(
        ImmutableList<string> availableReaders
    )
    {
        // Filter out virtual readers for auto-detection (prefer physical readers)
        ImmutableList<string> physicalReaders =
        [
            .. availableReaders.Where(reader => !IsVirtualReader(reader)),
        ];

        var selectedReaders = physicalReaders.IsEmpty ? availableReaders : physicalReaders;

        return selectedReaders.IsEmpty
            ? Result.Failure<string, SmartCardError>(
                SmartCardError.CommunicationError("No readers available for auto-detection")
            )
            : Result.Success<string, SmartCardError>(selectedReaders.First());
    }

    /// <summary>
    /// Checks if input represents an auto-detection request.
    /// </summary>
    private static bool IsAutoDetectionKeyword(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return true;
        }

        string normalizedInput = input.Trim().ToLowerInvariant();
        return normalizedInput is "auto" or "detect" or "first" or "";
    }

    /// <summary>
    /// Determines if a reader name represents a virtual reader.
    /// </summary>
    private static bool IsVirtualReader(string readerName)
    {
        string lowerName = readerName.ToLowerInvariant();
        return lowerName.Contains("virtual")
            || lowerName.Contains("simulator")
            || lowerName.Contains("emulator");
    }

    /// <summary>
    /// Creates error for when no readers match the input.
    /// </summary>
    private static Result<string, SmartCardError> CreateNoMatchError(
        string input,
        ImmutableList<string> availableReaders
    )
    {
        string readerList = string.Join(", ", availableReaders.Select(r => $"'{r}'"));
        return Result.Failure<string, SmartCardError>(
            SmartCardError.InvalidArgument(
                $"Reader '{input}' not found. Available readers: {readerList}"
            )
        );
    }

    /// <summary>
    /// Creates error for when multiple readers match the input.
    /// </summary>
    private static Result<string, SmartCardError> CreateMultipleMatchError(
        string input,
        ImmutableList<string> matches
    )
    {
        string matchList = string.Join(", ", matches.Select(m => $"'{m}'"));
        return Result.Failure<string, SmartCardError>(
            SmartCardError.InvalidArgument(
                $"Multiple readers match '{input}': {matchList}. Please be more specific."
            )
        );
    }
}
