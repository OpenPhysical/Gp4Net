using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Packages;

/// <summary>
/// Command to analyze individual Oracle Java Card .exp files.
/// </summary>
[PublicAPI]
public class AnalyzeExpCommand : AsyncCommand<AnalyzeExpCommand.Settings>
{
    /// <inheritdoc />
    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings)
    {
        if (!File.Exists(settings.ExpFilePath))
        {
            AnsiConsole.MarkupLine(
                $"[red].exp file not found: {Markup.Escape(settings.ExpFilePath)}[/]"
            );
            return 1;
        }

        try
        {
            AnsiConsole.MarkupLine(
                $"[cyan]Analyzing .exp file: {Markup.Escape(settings.ExpFilePath)}[/]"
            );

            var analysis = await AnalyzeExpFileAsync(settings.ExpFilePath, settings.SdkVersion);

            DisplayAnalysis(analysis, settings);

            // Save to database if package was discovered and output path is specified
            if (analysis.PackageInfo != null && !string.IsNullOrEmpty(settings.DatabasePath))
            {
                await SaveToDatabase(analysis.PackageInfo, settings.DatabasePath);
            }

            return 0;
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine(
                $"[red]Error analyzing .exp file: {Markup.Escape(ex.Message)}[/]"
            );
            if (settings.Verbose)
            {
                AnsiConsole.WriteException(ex);
            }
            return 1;
        }
    }

    private static Task<ExpFileAnalysis> AnalyzeExpFileAsync(
        string expFilePath,
        string? sdkVersion = null
    )
    {
        var fileBytes = File.ReadAllBytes(expFilePath);
        var analysis = new ExpFileAnalysis
        {
            FilePath = expFilePath,
            FileSize = fileBytes.Length,
            FileName = Path.GetFileName(expFilePath),
            SdkVersion = sdkVersion,
            // Extract basic file info
            RelativePath = Path.GetRelativePath(Directory.GetCurrentDirectory(), expFilePath)
        };

        // Look for magic bytes and file format indicators
        AnalyzeFileFormat(fileBytes, analysis);

        // Extract strings for package name detection
        ExtractStrings(fileBytes, analysis);

        // Look for package information using jcalgscan method
        ExtractPackageInfo(fileBytes, analysis);

        // Look for additional useful data
        ExtractAdditionalInfo(fileBytes, analysis);

        return Task.FromResult(analysis);
    }

    private static void AnalyzeFileFormat(byte[] fileBytes, ExpFileAnalysis analysis)
    {
        if (fileBytes.Length < 16)
        {
            analysis.FormatNotes.Add("File too small for analysis");
            return;
        }

        // Check for common magic bytes
        var header = fileBytes.Take(16).ToArray();
        var headerHex = Convert.ToHexString(header);
        analysis.HeaderHex = headerHex;

        // Look for ZIP/JAR signatures
        if (fileBytes[0] == 0x50 && fileBytes[1] == 0x4B)
        {
            analysis.FormatNotes.Add("ZIP/JAR format detected");
        }

        // Look for Java class file signature
        if (
            fileBytes[0] == 0xCA
            && fileBytes[1] == 0xFE
            && fileBytes[2] == 0xBA
            && fileBytes[3] == 0xBE
        )
        {
            analysis.FormatNotes.Add("Java class file format detected");
        }

        // Check for common export file patterns
        if (headerHex.Contains("4A43"))
        {
            analysis.FormatNotes.Add("Contains 'JC' pattern (possible Java Card marker)");
        }
    }

    private static void ExtractStrings(byte[] fileBytes, ExpFileAnalysis analysis)
    {
        var strings = new List<string>();
        var currentString = new StringBuilder();

        for (var i = 0; i < fileBytes.Length; i++)
        {
            var b = fileBytes[i];

            // Look for printable ASCII characters
            if (b is >= 32 and <= 126)
            {
                _ = currentString.Append((char)b);
            }
            else
            {
                if (currentString.Length >= 4) // Minimum string length
                {
                    strings.Add(currentString.ToString());
                }
                _ = currentString.Clear();
            }
        }

        // Don't forget the last string
        if (currentString.Length >= 4)
        {
            strings.Add(currentString.ToString());
        }

        analysis.ExtractedStrings = [.. strings.Distinct().OrderBy(s => s)];

        // Look for package-like strings
        analysis.PossiblePackageNames =
        [
            .. strings
                .Where(s => s.Contains('.') && s.Length > 5)
                .Where(s => s.All(c => char.IsLetterOrDigit(c) || c == '.' || c == '/'))
        ];
    }

    private static void ExtractPackageInfo(byte[] fileBytes, ExpFileAnalysis analysis)
    {
        // Try to extract package name from file path
        var pathBasedPackageName = ExtractPackageNameFromPath(analysis.FilePath);
        if (!string.IsNullOrEmpty(pathBasedPackageName))
        {
            analysis.PathBasedPackageName = pathBasedPackageName;

            // Use jcalgscan method to find AID
            var packageInfo = TryExtractAidMapping(
                fileBytes,
                pathBasedPackageName,
                analysis.SdkVersion,
                analysis.FilePath
            );
            if (packageInfo != null)
            {
                analysis.PackageInfo = packageInfo;
            }
        }

        // Also try with detected package names from strings
        foreach (var possibleName in analysis.PossiblePackageNames.Take(5)) // Limit to first 5
        {
            var packageInfo = TryExtractAidMapping(
                fileBytes,
                possibleName,
                analysis.SdkVersion,
                analysis.FilePath
            );
            if (packageInfo != null && analysis.PackageInfo == null)
            {
                analysis.PackageInfo = packageInfo;
                analysis.DetectedPackageName = possibleName;
                break;
            }
        }
    }

    private static void ExtractAdditionalInfo(byte[] fileBytes, ExpFileAnalysis analysis)
    {
        // Look for version patterns
        ExtractVersionInfo(fileBytes, analysis);

        // Look for AID patterns (even if not associated with package names)
        ExtractAidPatterns(fileBytes, analysis);

        // Look for export/import information
        ExtractExportImportInfo(fileBytes, analysis);
    }

    private static void ExtractVersionInfo(byte[] fileBytes, ExpFileAnalysis analysis)
    {
        // Look for version-like patterns in the strings
        var versionPatterns = analysis
            .ExtractedStrings.Where(s =>
                System.Text.RegularExpressions.Regex.IsMatch(s, @"\d+\.\d+(\.\d+)?")
            )
            .ToList();

        analysis.PossibleVersions = versionPatterns;
    }

    private static void ExtractAidPatterns(byte[] fileBytes, ExpFileAnalysis analysis)
    {
        var aidPatterns = new List<string>();

        // Look for potential AID patterns (sequences that might be AIDs)
        for (var i = 0; i < fileBytes.Length - 8; i++)
        {
            // Look for length byte followed by potential AID
            var length = fileBytes[i];
            if (length is >= 5 and <= 16 && i + length < fileBytes.Length)
            {
                var potentialAid = fileBytes.Skip(i + 1).Take(length).ToArray();

                // Check if it looks like an AID (starts with A0 or similar)
                if (
                    potentialAid.Length >= 5
                    && (potentialAid[0] == 0xA0 || potentialAid[0] == 0xA1)
                )
                {
                    var aidHex = Convert.ToHexString(potentialAid);
                    if (!aidPatterns.Contains(aidHex))
                    {
                        aidPatterns.Add(aidHex);
                    }
                }
            }
        }

        analysis.PossibleAids = aidPatterns;
    }

    private static void ExtractExportImportInfo(byte[] fileBytes, ExpFileAnalysis analysis)
    {
        // Look for export/import related strings
        var exportImportKeywords = new[]
        {
            "export",
            "import",
            "Export",
            "Import",
            "EXPORT",
            "IMPORT",
        };

        analysis.ExportImportInfo =
        [
            .. analysis.ExtractedStrings.Where(s =>
                exportImportKeywords.Any(keyword => s.Contains(keyword))
            )
        ];
    }

    private static string? ExtractPackageNameFromPath(string expFilePath)
    {
        var parts = expFilePath.Replace('\\', '/').Split('/');

        // Look for patterns like: api_export_files/javacard/framework/javacard/framework.exp
        for (var i = 0; i < parts.Length - 1; i++)
        {
            if (parts[i] == "api_export_files" && i + 2 < parts.Length)
            {
                var packageParts = new List<string>();
                for (var j = i + 1; j < parts.Length - 1; j++)
                {
                    packageParts.Add(parts[j]);
                }
                return string.Join('.', packageParts);
            }
        }

        return Path.GetFileNameWithoutExtension(expFilePath);
    }

    private static string ExtractSdkVersionFromPath(string expFilePath)
    {
        // Extract SDK version from path like: external/oracle_javacard_sdks/jc221_kit/...
        // Returns: jc221 (removes _kit suffix)
        var parts = expFilePath.Replace('\\', '/').Split('/');

        foreach (var part in parts)
        {
            if (part.StartsWith("jc") && part.EndsWith("_kit"))
            {
                return part.Substring(0, part.Length - "_kit".Length);
            }
            // Handle versions like jc310b43_kit -> jc310b43
            if (part.StartsWith("jc") && part.Contains("_kit"))
            {
                return part.Replace("_kit", "");
            }
        }

        return "unknown";
    }

    private static PackageInfo? TryExtractAidMapping(
        byte[] fileBytes,
        string packageName,
        string? sdkVersion,
        string expFilePath
    )
    {
        var packageNameBytes = Encoding.UTF8.GetBytes(packageName.Replace('.', '/'));
        var lastIndex = FindLastOccurrence(fileBytes, packageNameBytes);

        if (lastIndex == -1)
        {
            return null;
        }

        var dataStart = lastIndex + packageNameBytes.Length + 4;

        if (dataStart + 3 >= fileBytes.Length)
        {
            return null;
        }

        try
        {
            var minorVersion = fileBytes[dataStart];
            var majorVersion = fileBytes[dataStart + 1];
            var aidLength = fileBytes[dataStart + 2];

            if (dataStart + 3 + aidLength > fileBytes.Length)
            {
                return null;
            }

            var aid = new byte[aidLength];
            Array.Copy(fileBytes, dataStart + 3, aid, 0, aidLength);

            // Use provided SDK version or extract from path
            var finalSdkVersion = sdkVersion ?? ExtractSdkVersionFromPath(expFilePath);

            return new PackageInfo
            {
                Name = packageName,
                Aid = aid,
                MajorVersion = majorVersion,
                MinorVersion = minorVersion,
                Version = $"{majorVersion}.{minorVersion}",
                SdkVersion = finalSdkVersion,
                SourceFile = expFilePath,
            };
        }
        catch
        {
            return null;
        }
    }

    private static int FindLastOccurrence(byte[] haystack, byte[] needle)
    {
        for (var i = haystack.Length - needle.Length; i >= 0; i--)
        {
            var found = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j])
                {
                    found = false;
                    break;
                }
            }
            if (found)
            {
                return i;
            }
        }
        return -1;
    }

    private static void DisplayAnalysis(ExpFileAnalysis analysis, Settings settings)
    {
        // Basic file information
        var basicTable = new Table().AddColumn("Property").AddColumn("Value");

        _ = basicTable.AddRow("File Path", Markup.Escape(analysis.RelativePath));
        _ = basicTable.AddRow("File Size", $"{analysis.FileSize} bytes");
        _ = basicTable.AddRow("Header (hex)", $"[dim]{analysis.HeaderHex}[/]");

        AnsiConsole.Write(
            new Panel(basicTable)
                .Header("[bold]Basic File Information[/]")
                .BorderColor(Color.Blue)
        );

        // Format analysis
        if (analysis.FormatNotes.Any())
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold]Format Analysis:[/]");
            foreach (var note in analysis.FormatNotes)
            {
                AnsiConsole.MarkupLine($"  • {Markup.Escape(note)}");
            }
        }

        // Package information
        if (analysis.PackageInfo != null)
        {
            AnsiConsole.WriteLine();
            var packageTable = new Table().AddColumn("Property").AddColumn("Value");

            _ = packageTable.AddRow("Package Name", analysis.PackageInfo.Name);
            _ = packageTable.AddRow(
                "Package AID",
                $"[dim]{Convert.ToHexString(analysis.PackageInfo.Aid)}[/]"
            );
            _ = packageTable.AddRow("Version", analysis.PackageInfo.Version);
            _ = packageTable.AddRow(
                "Major Version",
                analysis.PackageInfo.MajorVersion.ToString()
            );
            _ = packageTable.AddRow(
                "Minor Version",
                analysis.PackageInfo.MinorVersion.ToString()
            );
            _ = packageTable.AddRow(
                "SDK Version",
                $"[yellow]{analysis.PackageInfo.SdkVersion}[/]"
            );

            if (!string.IsNullOrEmpty(analysis.DetectedPackageName))
            {
                _ = packageTable.AddRow("Detection Method", "String analysis");
            }
            else if (!string.IsNullOrEmpty(analysis.PathBasedPackageName))
            {
                _ = packageTable.AddRow("Detection Method", "Path analysis");
            }

            AnsiConsole.Write(
                new Panel(packageTable)
                    .Header("[bold]Package Information[/]")
                    .BorderColor(Color.Green)
            );
        }

        // Additional findings
        if (settings.Detailed)
        {
            DisplayDetailedAnalysis(analysis);
        }
    }

    private static void DisplayDetailedAnalysis(ExpFileAnalysis analysis)
    {
        // Possible package names
        if (analysis.PossiblePackageNames.Any())
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold]Detected Package Names:[/]");
            foreach (var name in analysis.PossiblePackageNames.Take(10))
            {
                AnsiConsole.MarkupLine($"  • {Markup.Escape(name)}");
            }
        }

        // Possible AIDs
        if (analysis.PossibleAids.Any())
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold]Possible AIDs:[/]");
            foreach (var aid in analysis.PossibleAids.Take(10))
            {
                AnsiConsole.MarkupLine($"  • [dim]{aid}[/]");
            }
        }

        // Version information
        if (analysis.PossibleVersions.Any())
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold]Possible Versions:[/]");
            foreach (var version in analysis.PossibleVersions.Take(5))
            {
                AnsiConsole.MarkupLine($"  • {Markup.Escape(version)}");
            }
        }

        // Export/Import info
        if (analysis.ExportImportInfo.Any())
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold]Export/Import Related:[/]");
            foreach (var info in analysis.ExportImportInfo.Take(5))
            {
                AnsiConsole.MarkupLine($"  • {Markup.Escape(info)}");
            }
        }

        // Sample strings
        if (analysis.ExtractedStrings.Any())
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold]Sample Extracted Strings:[/]");
            foreach (var str in analysis.ExtractedStrings.Take(15))
            {
                AnsiConsole.MarkupLine($"  • [dim]{Markup.Escape(str)}[/]");
            }
        }
    }

    private static async Task SaveToDatabase(PackageInfo packageInfo, string databasePath)
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        };

        // Load existing data if file exists
        var existingData = new Dictionary<string, object>();
        var existingPackages = new Dictionary<string, object>();

        if (File.Exists(databasePath))
        {
            try
            {
                var existingJson = await File.ReadAllTextAsync(databasePath);
                var existingDoc = JsonDocument.Parse(existingJson);

                // Preserve existing non-package data
                foreach (var element in existingDoc.RootElement.EnumerateObject())
                {
                    if (element.Name != "packages")
                    {
                        var deserializedValue = JsonSerializer.Deserialize<object>(
                            element.Value.GetRawText(),
                            options
                        );
                        if (deserializedValue != null)
                        {
                            existingData[element.Name] = deserializedValue;
                        }
                    }
                    else
                    {
                        // Load existing packages
                        foreach (var pkg in element.Value.EnumerateObject())
                        {
                            var deserializedPackage = JsonSerializer.Deserialize<object>(
                                pkg.Value.GetRawText(),
                                options
                            );
                            if (deserializedPackage != null)
                            {
                                existingPackages[pkg.Name] = deserializedPackage;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine(
                    $"[yellow]Warning: Could not parse existing JSON file: {ex.Message}[/]"
                );
                AnsiConsole.MarkupLine("[yellow]Creating new file...[/]");
            }
        }

        // Convert AID to hex string and create compound key with version
        var aidHex = Convert.ToHexString(packageInfo.Aid).ToUpper();
        var packageKey = $"{aidHex}-v{packageInfo.Version}";

        // Check for duplicate (same AID and version)
        var isDuplicate = existingPackages.ContainsKey(packageKey);

        // Add or update the package
        existingPackages[packageKey] = new
        {
            name = packageInfo.Name,
            aid = aidHex,
            version = packageInfo.Version,
            majorVersion = packageInfo.MajorVersion,
            minorVersion = packageInfo.MinorVersion,
            sourceFile = Path.GetRelativePath(
                Directory.GetCurrentDirectory(),
                packageInfo.SourceFile ?? ""
            ),
            sdkVersion = packageInfo.SdkVersion,
            lastUpdated = DateTime.UtcNow,
        };

        // Create final JSON structure
        var jsonData = new Dictionary<string, object>(existingData)
        {
            ["generatedAt"] = DateTime.UtcNow,
            ["packageCount"] = existingPackages.Count,
            ["packages"] = existingPackages,
        };

        var json = JsonSerializer.Serialize(jsonData, options);
        await File.WriteAllTextAsync(databasePath, json);

        var action = isDuplicate ? "Updated" : "Added";
        AnsiConsole.MarkupLine(
            $"[green]{action} package {packageInfo.Name} v{packageInfo.Version} (AID: {aidHex}) to database[/]"
        );
    }

    /// <summary>
    /// Settings for the analyze-exp command.
    /// </summary>
    public class Settings : CommandSettings
    {
        /// <summary>
        /// Gets or sets the .exp file path to analyze.
        /// </summary>
        [CommandArgument(0, "<EXP_FILE>")]
        [Description("Path to the .exp file to analyze")]
        public string ExpFilePath { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets a value indicating whether to show detailed analysis.
        /// </summary>
        [CommandOption("-d|--detailed")]
        [Description("Show detailed analysis including all extracted data")]
        public bool Detailed { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to show verbose output.
        /// </summary>
        [CommandOption("-v|--verbose")]
        [Description("Show verbose output including errors")]
        public bool Verbose { get; set; }

        /// <summary>
        /// Gets or sets the SDK version to use for the package.
        /// </summary>
        [CommandOption("-s|--sdk-version")]
        [Description("Specify the SDK version for the package (e.g., jc310b43)")]
        public string? SdkVersion { get; set; }

        /// <summary>
        /// Gets or sets the database path to save discovered packages.
        /// </summary>
        [CommandOption("-o|--output")]
        [Description("Save discovered package to JSON database file")]
        public string? DatabasePath { get; set; }

        /// <inheritdoc />
        public override ValidationResult Validate()
        {
            if (string.IsNullOrWhiteSpace(ExpFilePath))
            {
                return ValidationResult.Error(".exp file path is required");
            }

            return ValidationResult.Success();
        }
    }

    private class ExpFileAnalysis
    {
        public string FilePath { get; set; } = string.Empty;
        public string RelativePath { get; set; } = string.Empty;
        public string FileName { get; set; } = string.Empty;
        public long FileSize { get; set; }
        public string HeaderHex { get; set; } = string.Empty;
        public List<string> FormatNotes { get; set; } = [];
        public List<string> ExtractedStrings { get; set; } = [];
        public List<string> PossiblePackageNames { get; set; } = [];
        public List<string> PossibleAids { get; set; } = [];
        public List<string> PossibleVersions { get; set; } = [];
        public List<string> ExportImportInfo { get; set; } = [];
        public string? PathBasedPackageName { get; set; }
        public string? DetectedPackageName { get; set; }
        public string? SdkVersion { get; set; }
        public PackageInfo? PackageInfo { get; set; }
    }

    private class PackageInfo
    {
        public string Name { get; set; } = string.Empty;
        public byte[] Aid { get; set; } = [];
        public byte MajorVersion { get; set; }
        public byte MinorVersion { get; set; }
        public string Version { get; set; } = string.Empty;
        public string SdkVersion { get; set; } = string.Empty;
        public string? SourceFile { get; set; }
    }
}