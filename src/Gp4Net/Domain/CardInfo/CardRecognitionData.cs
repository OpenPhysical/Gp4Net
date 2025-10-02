using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;

namespace Gp4Net.Domain.CardInfo;

/// <summary>
/// Represents the structured contents of Card Recognition Data (tag 73).
/// Per GP Card Specification v2.3.1 Table E-3, this contains nested application tags
/// with OIDs that identify card capabilities and configuration.
/// </summary>
/// <param name="CardRecognitionOid">Direct OID for Card Recognition (1.2.840.114283.1)</param>
/// <param name="ApplicationTags">All application tags found within tag 73</param>
public record CardRecognitionData(
    Maybe<string> CardRecognitionOid,
    IReadOnlyList<ApplicationTag> ApplicationTags
)
{
    /// <summary>
    /// Gets the GlobalPlatform version tag (tag 60) if present.
    /// </summary>
    public Maybe<ApplicationTag> GpVersionTag =>
        ApplicationTags.Where(t => t.TagNumber == 0x60).ToList() is var tags && tags.Count > 0
            ? Maybe<ApplicationTag>.From(tags[0])
            : Maybe<ApplicationTag>.None;

    /// <summary>
    /// Gets the Card Identification Scheme tag (tag 63) if present.
    /// </summary>
    public Maybe<ApplicationTag> CardIdSchemeTag =>
        ApplicationTags.Where(t => t.TagNumber == 0x63).ToList() is var tags && tags.Count > 0
            ? Maybe<ApplicationTag>.From(tags[0])
            : Maybe<ApplicationTag>.None;

    /// <summary>
    /// Gets the Secure Channel Protocol tag (tag 64) if present.
    /// Can appear multiple times for different SCP versions.
    /// </summary>
    public IReadOnlyList<ApplicationTag> ScpProtocolTags =>
        ApplicationTags.Where(t => t.TagNumber == 0x64).ToImmutableList();

    /// <summary>
    /// Gets the first SCP protocol tag if any exist.
    /// </summary>
    public Maybe<ApplicationTag> PrimaryScpTag =>
        ScpProtocolTags.Count > 0
            ? Maybe<ApplicationTag>.From(ScpProtocolTags[0])
            : Maybe<ApplicationTag>.None;

    /// <summary>
    /// Gets optional card configuration details (tag 65) if present.
    /// </summary>
    public Maybe<ApplicationTag> ConfigurationTag =>
        ApplicationTags.Where(t => t.TagNumber == 0x65).ToList() is var tags && tags.Count > 0
            ? Maybe<ApplicationTag>.From(tags[0])
            : Maybe<ApplicationTag>.None;

    /// <summary>
    /// Gets optional card/chip details (tag 66) if present.
    /// </summary>
    public Maybe<ApplicationTag> ChipDetailsTag =>
        ApplicationTags.Where(t => t.TagNumber == 0x66).ToList() is var tags && tags.Count > 0
            ? Maybe<ApplicationTag>.From(tags[0])
            : Maybe<ApplicationTag>.None;

    /// <summary>
    /// Gets all OIDs found in the recognition data, including nested ones.
    /// </summary>
    public IReadOnlyList<string> GetAllOids()
    {
        var directOid = CardRecognitionOid
            .Map(oid => new[] { oid })
            .GetValueOrDefault(Enumerable.Empty<string>().ToArray());

        var nestedOids = ApplicationTags.SelectMany(tag =>
            tag.NestedOid.Map(oid => new[] { oid })
                .GetValueOrDefault(Enumerable.Empty<string>().ToArray())
        );

        return directOid.Concat(nestedOids).ToImmutableList();
    }

    /// <summary>
    /// Empty instance for when no card recognition data is available.
    /// </summary>
    public static CardRecognitionData Empty =>
        new(Maybe<string>.None, ImmutableList<ApplicationTag>.Empty);
}
