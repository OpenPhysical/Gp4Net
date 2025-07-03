using System.Collections.Generic;
using System.Linq;
using JetBrains.Annotations;

namespace Gp4Net.Domain.CardInfo
{
    /// <summary>
    /// Provides mappings for known GlobalPlatform Object Identifiers (OIDs).
    /// </summary>
    [PublicAPI]
    public static class GlobalPlatformOids
    {
        /// <summary>
        /// GlobalPlatform OID prefix: 1.2.840.114283
        /// </summary>
        public const string GlobalPlatformPrefix = "1.2.840.114283";

        /// <summary>
        /// Known GlobalPlatform OIDs and their descriptions.
        /// Based on GlobalPlatform specifications and common implementations.
        /// </summary>
        private static readonly Dictionary<string, string> KnownOids = new Dictionary<
            string,
            string
        >
        {
            // GlobalPlatform main OIDs
            { "1.2.840.114283.1", "GlobalPlatform" },
            { "1.2.840.114283.2", "GlobalPlatform Application" },
            { "1.2.840.114283.2.2.3", "GlobalPlatform Card Specification 2.2.3" },
            { "1.2.840.114283.3", "GlobalPlatform Card Content Management" },
            { "1.2.840.114283.4", "GlobalPlatform Card Security" },
            { "1.2.840.114283.4.0", "Secure Channel Protocol 00 (SCP00)" },
            { "1.2.840.114283.4.1", "Secure Channel Protocol 01 (SCP01)" },
            { "1.2.840.114283.4.2", "Secure Channel Protocol 02 (SCP02)" },
            { "1.2.840.114283.4.3", "Secure Channel Protocol 03 (SCP03)" },
            { "1.2.840.114283.4.3.112", "SCP03 with S-ENC and S-MAC" },
            { "1.2.840.114283.5", "GlobalPlatform Conformance" },
            { "1.2.840.114283.5.7.2.0.0", "GlobalPlatform Conformance Testing" },
            // Contactless and additional protocols
            { "1.2.840.114283.4.3.96", "SCP03 Contactless" },
            { "1.2.840.114283.4.3.97", "SCP03 Contactless with R-MAC" },
            { "1.2.840.114283.4.3.98", "SCP03 Contactless with R-ENC and R-MAC" },
            // Amendment specifications
            { "1.2.840.114283.2.2.1", "GlobalPlatform Card Specification 2.2.1" },
            { "1.2.840.114283.2.2.2", "GlobalPlatform Card Specification 2.2.2" },
            { "1.2.840.114283.2.3", "GlobalPlatform Card Specification 2.3" },
            { "1.2.840.114283.2.3.1", "GlobalPlatform Card Specification 2.3.1" },
            // Common vendor-specific OIDs that may appear
            { "1.3.6.1.4.1.42.2.110.1.2", "Oracle Java Card API" },
            { "1.3.6.1.4.1.42.2.110.1.3", "Oracle Java Card VM" },
            // NIST PIV related
            { "2.16.840.1.101.3.7.2.96.80", "PIV Card Application" },
            // ISO 7816 related
            { "1.0", "ISO Standard" },
            { "2.5.29", "X.509 Certificate Extensions" }
        };

        /// <summary>
        /// Gets the description for a known OID.
        /// </summary>
        /// <param name="oid">The OID in dotted notation.</param>
        /// <returns>The description if known, otherwise null.</returns>
        public static string? GetDescription(string oid)
        {
            if (string.IsNullOrEmpty(oid))
            {
                return null;
            }

            return KnownOids.TryGetValue(oid, out var description) ? description : null;
        }

        /// <summary>
        /// Determines if an OID is a GlobalPlatform OID.
        /// </summary>
        /// <param name="oid">The OID in dotted notation.</param>
        /// <returns>True if the OID is a GlobalPlatform OID.</returns>
        public static bool IsGlobalPlatformOid(string oid)
        {
            return !string.IsNullOrEmpty(oid) && oid.StartsWith(GlobalPlatformPrefix);
        }

        /// <summary>
        /// Gets the SCP version from an OID if applicable.
        /// </summary>
        /// <param name="oid">The OID in dotted notation.</param>
        /// <returns>The SCP version (e.g., "SCP03") or null if not an SCP OID.</returns>
        public static string? GetScpVersion(string oid)
        {
            if (string.IsNullOrEmpty(oid))
            {
                return null;
            }

            if (oid.StartsWith("1.2.840.114283.4."))
            {
                var parts = oid.Split('.');
                if (parts.Length >= 6)
                {
                    switch (parts[5])
                    {
                        case "0":
                            return "SCP00";
                        case "1":
                            return "SCP01";
                        case "2":
                            return "SCP02";
                        case "3":
                            return "SCP03";
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Formats an OID with its description if known.
        /// </summary>
        /// <param name="oid">The OID in dotted notation.</param>
        /// <returns>A formatted string with OID and description.</returns>
        public static string? FormatOid(string? oid)
        {
            if (string.IsNullOrEmpty(oid))
            {
                return oid;
            }

            var description = GetDescription(oid);
            return description != null ? $"{oid} ({description})" : oid;
        }

        /// <summary>
        /// Gets all known GlobalPlatform OIDs.
        /// </summary>
        /// <returns>A dictionary of OIDs and their descriptions.</returns>
        public static IReadOnlyDictionary<string, string> GetAllKnownOids()
        {
            return new Dictionary<string, string>(KnownOids);
        }

        /// <summary>
        /// Analyzes a list of OIDs and provides a summary of capabilities.
        /// </summary>
        /// <param name="oids">List of OIDs to analyze.</param>
        /// <returns>A summary of the capabilities.</returns>
        public static CapabilitiesSummary AnalyzeOids(IEnumerable<string> oids)
        {
            var summary = new CapabilitiesSummary();

            foreach (var oid in oids)
            {
                if (string.IsNullOrEmpty(oid))
                {
                    continue;
                }

                // Check for SCP support
                var scpVersion = GetScpVersion(oid);
                if (scpVersion != null)
                {
                    _ = summary.SupportedScpVersions.Add(scpVersion);

                    // Check for specific SCP03 variants
                    if (oid == "1.2.840.114283.4.3.112")
                    {
                        summary.SupportsScp03WithEncryption = true;
                    }
                }

                // Check for specification version
                if (oid.StartsWith("1.2.840.114283.2."))
                {
                    var description = GetDescription(oid);
                    if (description != null && description.Contains("Card Specification"))
                    {
                        _ = summary.SpecificationVersions.Add(description);
                    }
                }

                // Store all OIDs with descriptions
                summary.AllOids[oid] = GetDescription(oid) ?? "Unknown";
            }

            return summary;
        }

        /// <summary>
        /// Represents a summary of capabilities derived from OIDs.
        /// </summary>
        public class CapabilitiesSummary
        {
            /// <summary>
            /// Gets the supported SCP versions.
            /// </summary>
            public HashSet<string> SupportedScpVersions { get; } = [];

            /// <summary>
            /// Gets whether SCP03 with encryption is supported.
            /// </summary>
            public bool SupportsScp03WithEncryption { get; set; }

            /// <summary>
            /// Gets the GlobalPlatform specification versions.
            /// </summary>
            public HashSet<string> SpecificationVersions { get; } = [];

            /// <summary>
            /// Gets all OIDs with their descriptions.
            /// </summary>
            public Dictionary<string, string> AllOids { get; } = [];

            /// <summary>
            /// Formats the summary as a human-readable string.
            /// </summary>
            public override string ToString()
            {
                var lines = new List<string>();

                if (SupportedScpVersions.Count > 0)
                {
                    lines.Add("Supported Secure Channel Protocols:");
                    foreach (var scp in SupportedScpVersions.OrderBy(s => s))
                    {
                        lines.Add($"  - {scp}");
                    }
                }

                if (SpecificationVersions.Count > 0)
                {
                    lines.Add("\nGlobalPlatform Specifications:");
                    foreach (var spec in SpecificationVersions.OrderBy(s => s))
                    {
                        lines.Add($"  - {spec}");
                    }
                }

                if (AllOids.Count > 0)
                {
                    lines.Add("\nAll Capabilities:");
                    foreach (var kvp in AllOids.OrderBy(k => k.Key))
                    {
                        lines.Add($"  - {kvp.Key}: {kvp.Value}");
                    }
                }

                return string.Join("\n", lines);
            }
        }
    }
}
