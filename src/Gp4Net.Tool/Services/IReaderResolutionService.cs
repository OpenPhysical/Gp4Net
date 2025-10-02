using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Represents a resolved reader specification with its resolution method.
/// Immutable value object ensuring reader resolution traceability.
/// </summary>
[PublicAPI]
public record ReaderResolution(string ReaderName, ResolutionMethod Method, bool IsVirtual)
{
    /// <summary>
    /// Creates a resolution from an explicit --reader flag.
    /// </summary>
    public static ReaderResolution FromExplicitFlag(string readerName, bool isVirtual) =>
        new(readerName, ResolutionMethod.ExplicitFlag, isVirtual);

    /// <summary>
    /// Creates a resolution from GP4NET_READER environment variable.
    /// </summary>
    public static ReaderResolution FromEnvironment(string readerName, bool isVirtual) =>
        new(readerName, ResolutionMethod.Environment, isVirtual);

    /// <summary>
    /// Creates a resolution from auto-detection of single reader with media.
    /// </summary>
    public static ReaderResolution FromAutoDetection(string readerName) =>
        new(readerName, ResolutionMethod.AutoDetection, false);
}

/// <summary>
/// Method used to resolve the reader specification.
/// </summary>
[PublicAPI]
public enum ResolutionMethod
{
    /// <summary>
    /// Reader specified via --reader command line flag.
    /// </summary>
    ExplicitFlag,

    /// <summary>
    /// Reader specified via GP4NET_READER environment variable.
    /// </summary>
    Environment,

    /// <summary>
    /// Reader auto-detected as single reader with media present.
    /// </summary>
    AutoDetection,
}

/// <summary>
/// Service for resolving smart card readers based on CLI parameters and environment.
/// Implements the complete reader resolution flow with priority hierarchy.
/// </summary>
[PublicAPI]
public interface IReaderResolutionService
{
    /// <summary>
    /// Resolves a reader specification using the priority hierarchy:
    /// 1. Explicit --reader flag (with partial matching)
    /// 2. GP4NET_READER environment variable
    /// 3. Auto-detection (single reader with media)
    /// 4. Error if no resolution possible
    /// </summary>
    /// <param name="explicitReader">Reader from --reader flag (optional).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Resolved reader specification or detailed error.</returns>
    Task<Result<ReaderResolution, SmartCardError>> ResolveReaderAsync(
        Maybe<string> explicitReader,
        CancellationToken cancellationToken = default
    );
}
