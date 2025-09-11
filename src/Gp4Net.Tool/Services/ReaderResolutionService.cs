using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Implementation of reader resolution service with smart selection logic.
/// Handles priority-based resolution: explicit > environment > auto-detection.
/// </summary>
[PublicAPI]
public class ReaderResolutionService : IReaderResolutionService
{
    private readonly IEnvironmentService _environmentService;

    /// <summary>
    /// Initializes a new instance of the ReaderResolutionService class.
    /// </summary>
    /// <param name="environmentService">Service for accessing environment variables.</param>
    public ReaderResolutionService(IEnvironmentService environmentService)
    {
        _environmentService = environmentService;
    }

    /// <inheritdoc/>
    public async Task<Result<ReaderResolution, SmartCardError>> ResolveReaderAsync(
        Maybe<string> explicitReader,
        CancellationToken cancellationToken = default)
    {
        // Priority 1: Explicit --reader flag
        // If explicit reader is specified, use it exclusively (no fallback)
        return await explicitReader.Match(
            async reader => await ResolveExplicitReader(reader, cancellationToken),
            async () =>
            {
                // Priority 2: GP4NET_READER environment variable
                var envReader = _environmentService.GetGp4NetReaderVariable();
                return await envReader.Match(
                    async reader => await ResolveEnvironmentReader(reader, cancellationToken),
                    // Priority 3: Auto-detection of single reader with media
                    async () => await AutoDetectReader(cancellationToken));
            });
    }

    /// <summary>
    /// Resolves an explicitly specified reader with partial matching support.
    /// </summary>
    private async Task<Result<ReaderResolution, SmartCardError>> ResolveExplicitReader(
        string readerSpec,
        CancellationToken cancellationToken)
    {
        // Check if it's a virtual reader
        if (ReaderEnumerationService.IsVirtualReader(readerSpec))
        {
            // Virtual readers don't need enumeration, just validation
            return ReaderEnumerationService.ParseVirtualReaderSpec(readerSpec)
                .Map(profilePath => ReaderResolution.FromExplicitFlag(readerSpec, true));
        }

        // For physical readers, enumerate and match
        var readersResult = await ReaderEnumerationService.EnumeratePhysicalReadersAsync(cancellationToken);
        
        return readersResult.Bind(readers =>
        {
            if (readers.Length == 0)
            {
                return Result.Failure<ReaderResolution, SmartCardError>(
                    SmartCardError.CommunicationError("No smart card readers found on this system"));
            }

            // Try partial matching
            return ReaderEnumerationService.SelectReaderByPartialMatch(readerSpec, readers)
                .Map(matchedReader => ReaderResolution.FromExplicitFlag(matchedReader, false));
        });
    }

    /// <summary>
    /// Resolves a reader specified via environment variable.
    /// </summary>
    private async Task<Result<ReaderResolution, SmartCardError>> ResolveEnvironmentReader(
        string readerSpec,
        CancellationToken cancellationToken)
    {
        // Check if it's a virtual reader
        if (ReaderEnumerationService.IsVirtualReader(readerSpec))
        {
            return ReaderEnumerationService.ParseVirtualReaderSpec(readerSpec)
                .Map(profilePath => ReaderResolution.FromEnvironment(readerSpec, true));
        }

        // For physical readers, enumerate and match
        var readersResult = await ReaderEnumerationService.EnumeratePhysicalReadersAsync(cancellationToken);
        
        return readersResult.Bind(readers =>
        {
            if (readers.Length == 0)
            {
                return Result.Failure<ReaderResolution, SmartCardError>(
                    SmartCardError.CommunicationError("No smart card readers found on this system"));
            }

            // Try partial matching for environment variable too
            return ReaderEnumerationService.SelectReaderByPartialMatch(readerSpec, readers)
                .Map(matchedReader => ReaderResolution.FromEnvironment(matchedReader, false))
                .MapError(error => SmartCardError.InvalidArgument(
                    $"Reader '{readerSpec}' from GP4NET_READER environment variable not found. " +
                    $"Update the environment variable or use --reader option to override."));
        });
    }

    /// <summary>
    /// Auto-detects a single reader with media present.
    /// </summary>
    private async Task<Result<ReaderResolution, SmartCardError>> AutoDetectReader(
        CancellationToken cancellationToken)
    {
        // Get all readers with media present
        var readersWithMediaResult = await ReaderStatusService.GetReadersWithMediaAsync(cancellationToken);
        
        return readersWithMediaResult.Bind(readersWithMedia =>
        {
            return readersWithMedia.Length switch
            {
                0 => Result.Failure<ReaderResolution, SmartCardError>(
                    SmartCardError.CommunicationError(
                        "No smart cards detected in any reader. Please insert a smart card.")),
                
                1 => Result.Success<ReaderResolution, SmartCardError>(
                    ReaderResolution.FromAutoDetection(readersWithMedia[0])),
                
                _ => Result.Failure<ReaderResolution, SmartCardError>(
                    SmartCardError.InvalidArgument(
                        $"Multiple readers have cards present: {string.Join(", ", readersWithMedia)}. " +
                        "Use --reader option to specify which reader to use."))
            };
        });
    }
}