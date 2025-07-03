using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text.Json;
using JetBrains.Annotations;

namespace Gp4Net.Services
{
    /// <summary>
    /// Service for resolving Java Card package AIDs to human-readable names and versions.
    /// </summary>
    [PublicAPI]
    public class PackageRegistry
    {
        private readonly Dictionary<string, PackageInfo> _packages;
        private readonly Dictionary<string, PackageInfo> _aidLookup;

        /// <summary>
        /// Initializes a new instance of the <see cref="PackageRegistry"/> class.
        /// </summary>
        public PackageRegistry()
        {
            _packages = [];
            _aidLookup = [];
            LoadPackageDatabase();
        }

        /// <summary>
        /// Gets the total number of packages in the registry.
        /// </summary>
        public int PackageCount => _packages.Count;

        /// <summary>
        /// Tries to resolve an AID to package information.
        /// </summary>
        /// <param name="aid">The AID bytes.</param>
        /// <param name="packageInfo">The resolved package information, if found.</param>
        /// <returns>True if the AID was resolved, false otherwise.</returns>
        public bool TryResolveAid(byte[] aid, out PackageInfo? packageInfo)
        {
            var aidHex = Convert.ToHexString(aid).ToUpper();
            return TryResolveAid(aidHex, out packageInfo);
        }

        /// <summary>
        /// Tries to resolve an AID to package information.
        /// </summary>
        /// <param name="aidHex">The AID as a hex string.</param>
        /// <param name="packageInfo">The resolved package information, if found.</param>
        /// <returns>True if the AID was resolved, false otherwise.</returns>
        public bool TryResolveAid(string aidHex, out PackageInfo? packageInfo)
        {
            return _aidLookup.TryGetValue(aidHex.ToUpper(), out packageInfo);
        }

        /// <summary>
        /// Gets all packages in the registry.
        /// </summary>
        /// <returns>An enumerable of all package information.</returns>
        public IEnumerable<PackageInfo> GetAllPackages()
        {
            return _packages.Values;
        }

        /// <summary>
        /// Formats an AID for display purposes.
        /// </summary>
        /// <param name="aid">The AID bytes.</param>
        /// <returns>A formatted hex string.</returns>
        public static string FormatAidAsHex(byte[] aid)
        {
            return Convert.ToHexString(aid).ToUpper();
        }

        private void LoadPackageDatabase()
        {
            try
            {
                var assembly = Assembly.GetExecutingAssembly();
                var resourceName = "Gp4Net.Data.known-packages.json";

                using var stream = assembly.GetManifestResourceStream(resourceName);
                if (stream == null)
                {
                    throw new InvalidOperationException(
                        $"Could not find embedded resource: {resourceName}"
                    );
                }

                using var reader = new StreamReader(stream);
                var json = reader.ReadToEnd();

                var options = new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                };

                var database = JsonSerializer.Deserialize<PackageDatabase>(json, options);
                if (database?.Packages == null)
                {
                    throw new InvalidOperationException("Invalid package database format");
                }

                // Load packages and create AID lookup
                foreach (var kvp in database.Packages)
                {
                    var packageInfo = new PackageInfo
                    {
                        Key = kvp.Key,
                        Name = kvp.Value.Name ?? string.Empty,
                        Aid = kvp.Value.Aid ?? string.Empty,
                        Version = kvp.Value.Version ?? string.Empty,
                        MajorVersion = kvp.Value.MajorVersion,
                        MinorVersion = kvp.Value.MinorVersion,
                        SourceFile = kvp.Value.SourceFile ?? string.Empty,
                        SdkVersion = kvp.Value.SdkVersion ?? string.Empty,
                    };

                    _packages[kvp.Key] = packageInfo;

                    // Also index by AID for quick lookup
                    if (!string.IsNullOrEmpty(packageInfo.Aid))
                    {
                        _aidLookup[packageInfo.Aid.ToUpper()] = packageInfo;
                    }
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to load package database", ex);
            }
        }

        private class PackageDatabase
        {
            public Dictionary<string, PackageEntry>? Packages { get; set; }
        }

        private class PackageEntry
        {
            public string? Name { get; set; }
            public string? Aid { get; set; }
            public string? Version { get; set; }
            public int MajorVersion { get; set; }
            public int MinorVersion { get; set; }
            public string? SourceFile { get; set; }
            public string? SdkVersion { get; set; }
        }
    }

    /// <summary>
    /// Information about a Java Card package.
    /// </summary>
    [PublicAPI]
    public class PackageInfo
    {
        /// <summary>
        /// Gets or sets the package key (compound key with AID and version).
        /// </summary>
        public string Key { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the package name.
        /// </summary>
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the package AID as a hex string.
        /// </summary>
        public string Aid { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the package version.
        /// </summary>
        public string Version { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the major version number.
        /// </summary>
        public int MajorVersion { get; set; }

        /// <summary>
        /// Gets or sets the minor version number.
        /// </summary>
        public int MinorVersion { get; set; }

        /// <summary>
        /// Gets or sets the source file path.
        /// </summary>
        public string SourceFile { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the SDK version.
        /// </summary>
        public string SdkVersion { get; set; } = string.Empty;

        /// <summary>
        /// Gets the display name for the package.
        /// </summary>
        public string DisplayName => $"{Name} v{Version}";
    }
}
