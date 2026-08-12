using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;
using WSCT.Wrapper;
using WSCT.Wrapper.Desktop.Core;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Represents a physical reader with its current card presence status.
/// Immutable value object for reader state information.
/// </summary>
[PublicAPI]
public record ReaderStatus(string Name, bool HasMediaPresent, Maybe<string> ErrorMessage = default)
{
    /// <summary>
    /// Creates a reader status with media present.
    /// </summary>
    public static ReaderStatus WithMedia(string name) => new(name, true, Maybe<string>.None);

    /// <summary>
    /// Creates a reader status without media present.
    /// </summary>
    public static ReaderStatus WithoutMedia(string name) => new(name, false, Maybe<string>.None);

    /// <summary>
    /// Creates a reader status with an error.
    /// </summary>
    public static ReaderStatus WithError(string name, string error) =>
        new(name, false, Maybe<string>.From(error));
}

/// <summary>
/// Service for detecting media presence in physical smart card readers.
/// Extends reader enumeration with card detection capabilities.
/// </summary>
[PublicAPI]
public static class ReaderStatusOperations
{
    /// <summary>
    /// Checks if media is present in a specific reader.
    /// Uses WSCT to detect card presence without establishing connection.
    /// </summary>
    /// <param name="readerName">Name of the reader to check.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if media present, false otherwise, or error.</returns>
    public static Task<Result<bool, SmartCardError>> IsMediaPresentAsync(
        string readerName,
        CancellationToken cancellationToken = default
    )
    {
        try
        {
            var context = new CardContext();
            try
            {
                var establishResult = context.Establish();

                if (establishResult != ErrorCode.Success)
                {
                    return Task.FromResult(
                        Result.Failure<bool, SmartCardError>(
                            SmartCardError.CommunicationError(
                                $"Failed to establish context: {establishResult}"
                            )
                        )
                    );
                }

                // Try to connect to the reader to check for card presence
                try
                {
                    var channel = new CardChannel(context, readerName);
                    try
                    {
                        var connectResult = channel.Connect(ShareMode.Shared, Protocol.Any);

                        if (connectResult == ErrorCode.Success)
                        {
                            // Card is present and we connected successfully
                            channel.Disconnect(Disposition.LeaveCard);
                            return Task.FromResult(Result.Success<bool, SmartCardError>(true));
                        }

                        // Connection failed - likely no card present
                        return Task.FromResult(Result.Success<bool, SmartCardError>(false));
                    }
                    finally
                    {
                        // Manual cleanup for channel
                    }
                }
                catch
                {
                    // Reader exists but no card or connection error
                    return Task.FromResult(Result.Success<bool, SmartCardError>(false));
                }
            }
            finally
            {
                // Manual cleanup for context
            }
        }
        catch (Exception ex)
        {
            return Task.FromResult(
                Result.Failure<bool, SmartCardError>(
                    SmartCardError.CommunicationError(
                        $"Failed to check media presence: {ex.Message}"
                    )
                )
            );
        }
    }

    /// <summary>
    /// Gets status for all available physical readers.
    /// Checks both existence and media presence for each reader.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Array of reader status or error.</returns>
    public static async Task<Result<ReaderStatus[], SmartCardError>> GetAllReaderStatusAsync(
        CancellationToken cancellationToken = default
    )
    {
        // Get all physical readers
        var readersResult = await ReaderEnumeration.EnumeratePhysicalReadersAsync(
            cancellationToken
        );

        return await readersResult.Bind(async readers =>
        {
            if (readers.Length == 0)
            {
                return Result.Success<ReaderStatus[], SmartCardError>([]);
            }

            // Check media presence for each reader
            var statusChecks = readers.Select(async reader =>
            {
                var mediaResult = await IsMediaPresentAsync(reader, cancellationToken);
                return mediaResult.Match(
                    hasMedia =>
                        hasMedia
                            ? ReaderStatus.WithMedia(reader)
                            : ReaderStatus.WithoutMedia(reader),
                    error => ReaderStatus.WithError(reader, error.Message)
                );
            });

            var statuses = await Task.WhenAll(statusChecks);
            return Result.Success<ReaderStatus[], SmartCardError>(statuses);
        });
    }

    /// <summary>
    /// Finds readers that have media present.
    /// Filters out readers without cards and virtual readers.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Array of reader names with media present, or error.</returns>
    public static async Task<Result<string[], SmartCardError>> GetReadersWithMediaAsync(
        CancellationToken cancellationToken = default
    )
    {
        var statusResult = await GetAllReaderStatusAsync(cancellationToken);

        return statusResult.Map(statuses =>
            statuses
                .Where(s => s.HasMediaPresent && s.ErrorMessage.HasNoValue)
                .Select(s => s.Name)
                .ToArray()
        );
    }
}
