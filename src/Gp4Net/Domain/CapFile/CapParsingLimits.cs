using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.Domain.CapFile;

/// <summary>
/// Bounds resource consumption while parsing an untrusted CAP/JAR archive.
/// Java Card 3.0.5 Virtual Machine Specification section 4.1.3 defines the JAR
/// container; these limits are implementation security policy and do not alter
/// the CAP representation defined by that specification.
/// </summary>
/// <param name="MaxArchiveBytes">Maximum compressed archive size.</param>
/// <param name="MaxEntries">Maximum number of ZIP entries.</param>
/// <param name="MaxExpandedEntryBytes">Maximum expanded size of one entry.</param>
/// <param name="MaxTotalExpandedBytes">Maximum aggregate expanded size.</param>
/// <param name="MaxCompressionRatio">Maximum expanded-to-compressed ratio for one entry.</param>
/// <param name="MaxManifestCharacters">Maximum manifest text length.</param>
/// <param name="MaxXmlCharacters">Maximum <c>javacard.xml</c> text length.</param>
[PublicAPI]
public sealed record CapParsingLimits(
    long MaxArchiveBytes = 16 * 1024 * 1024,
    int MaxEntries = 256,
    long MaxExpandedEntryBytes = 8 * 1024 * 1024,
    long MaxTotalExpandedBytes = 32 * 1024 * 1024,
    int MaxCompressionRatio = 100,
    int MaxManifestCharacters = 1024 * 1024,
    int MaxXmlCharacters = 1024 * 1024
)
{
    /// <summary>Gets the hardened default parsing limits.</summary>
    public static CapParsingLimits Default { get; } = new();

    internal Result<CapParsingLimits, SmartCardError> Validate() =>
        MaxArchiveBytes > 0
        && MaxEntries > 0
        && MaxExpandedEntryBytes > 0
        && MaxTotalExpandedBytes > 0
        && MaxCompressionRatio > 0
        && MaxManifestCharacters > 0
        && MaxXmlCharacters > 0
            ? Result.Success<CapParsingLimits, SmartCardError>(this)
            : Result.Failure<CapParsingLimits, SmartCardError>(
                SmartCardError.InvalidArgument("All CAP parsing limits must be positive.")
            );
}
