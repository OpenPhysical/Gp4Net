using System.Collections.Generic;
using CSharpFunctionalExtensions;
using JetBrains.Annotations;

namespace Gp4Net.Core.Asn1;

/// <summary>
/// Registry of known OIDs and their descriptions used in GlobalPlatform.
/// </summary>
[PublicAPI]
public static class KnownOids
{
    /// <summary>
    /// Dictionary of known OIDs and their human-readable descriptions.
    /// </summary>
    private static readonly Dictionary<string, string> OidDescriptions =
        new()
        {
            // GlobalPlatform OIDs
            { "1.2.840.114283.1", "GlobalPlatform" },
            { "1.2.840.114283.2.2.3", "GlobalPlatform Card Specification 2.2.3" },
            { "1.2.840.114283.3", "GlobalPlatform Card Identification Scheme" },
            { "1.2.840.114283.4.3.112", "SCP03 with S-ENC and S-MAC" },
            { "1.2.840.114283.5.7.2.0.0", "GlobalPlatform Conformance Testing" },
            // Java Card OIDs
            { "1.3.6.1.4.1.42.2.110.1.3", "Oracle Java Card VM" }
        };

    /// <summary>
    /// Gets the description for a known OID.
    /// </summary>
    /// <param name="oid">The OID in dotted notation.</param>
    /// <returns>The description if known, otherwise None.</returns>
    public static Maybe<string> GetDescription(string oid)
    {
        return OidDescriptions.TryGetValue(oid, out var description) 
            ? Maybe<string>.From(description) 
            : Maybe<string>.None;
    }

    /// <summary>
    /// Checks if an OID is known.
    /// </summary>
    /// <param name="oid">The OID in dotted notation.</param>
    /// <returns>True if the OID is in the known registry.</returns>
    public static bool IsKnown(string oid)
    {
        return OidDescriptions.ContainsKey(oid);
    }

    /// <summary>
    /// Gets all known OIDs.
    /// </summary>
    /// <returns>A read-only collection of all known OIDs.</returns>
    public static IReadOnlyCollection<string> GetAllKnownOids()
    {
        return OidDescriptions.Keys;
    }
}
