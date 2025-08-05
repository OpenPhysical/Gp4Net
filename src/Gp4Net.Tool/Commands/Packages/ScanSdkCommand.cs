using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Packages;

/// <summary>
/// Command to scan Oracle Java Card SDKs and extract package AID mappings.
/// </summary>
[PublicAPI]
public class ScanSdkCommand : AsyncCommand<ScanSdkCommand.Settings>
{
    /// <inheritdoc />
    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings)
    {
        if (!Directory.Exists(settings.SdkPath))
        {
            AnsiConsole.MarkupLine(
                $"[red]SDK path not found: {Markup.Escape(settings.SdkPath)}[/]"
            );
            return 1;
        }

        try
        {
            AnsiConsole.MarkupLine(
                $"[cyan]Scanning Oracle Java Card SDKs at: {Markup.Escape(settings.SdkPath)}[/]"
            );

            var mappings = await ScanForPackageMappingsAsync(settings.SdkPath);

            AnsiConsole.MarkupLine($"[green]Found {mappings.Count} package mappings[/]");

            if (!string.IsNullOrEmpty(settings.OutputPath))
            {
                await WritePackageMappingsAsync(mappings, settings.OutputPath);
                AnsiConsole.MarkupLine(
                    $"[green]Package mappings written to: {Markup.Escape(settings.OutputPath)}[/]"
                );
            }
            else
            {
                DisplayPackageMappings(mappings);
            }

            return 0;
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Error scanning SDK: {Markup.Escape(ex.Message)}[/]");
            if (settings.Verbose)
            {
                AnsiConsole.WriteException(ex);
            }
            return 1;
        }
    }

    private static Task<Dictionary<string, PackageInfo>> ScanForPackageMappingsAsync(
        string sdkPath
    )
    {
        var mappings = new Dictionary<string, PackageInfo>();

        AnsiConsole
            .Status()
            .Start(
                "Scanning .exp files...",
                ctx =>
                {
                    var expFiles = Directory.GetFiles(
                        sdkPath,
                        "*.exp",
                        SearchOption.AllDirectories
                    );
                    AnsiConsole.MarkupLine($"[dim]Found {expFiles.Length} .exp files[/]");

                    foreach (var expFile in expFiles)
                    {
                        _ = ctx.Status($"Processing {Path.GetFileName(expFile)}...");

                        try
                        {
                            var packageInfo = ParseExpFile(expFile);
                            if (packageInfo != null)
                            {
                                var aidHex = Convert.ToHexString(packageInfo.Aid).ToUpper();
                                if (!mappings.ContainsKey(aidHex))
                                {
                                    mappings[aidHex] = packageInfo;
                                    AnsiConsole.MarkupLine(
                                        $"[dim]  Found: {packageInfo.Name} -> {aidHex}[/]"
                                    );
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            AnsiConsole.MarkupLine(
                                $"[yellow]Warning: Failed to parse {Path.GetFileName(expFile)}: {ex.Message}[/]"
                            );
                        }
                    }
                }
            );

        return Task.FromResult(mappings);
    }

    private static PackageInfo ParseExpFile(string expFilePath)
    {
        var fileBytes = File.ReadAllBytes(expFilePath);
        var relativePath = Path.GetRelativePath(Directory.GetCurrentDirectory(), expFilePath);

        // Extract SDK version from path (e.g., jc221_kit -> jc221)
        var sdkVersion = ExtractSdkVersionFromPath(expFilePath);

        // Look for package name pattern in the file
        var packageName = ExtractPackageNameFromPath(expFilePath);
        if (string.IsNullOrEmpty(packageName))
        {
            return null;
        }

        // Find the last occurrence of the package name in the file
        var packageNameBytes = System.Text.Encoding.UTF8.GetBytes(
            packageName.Replace('.', '/')
        );
        var lastIndex = FindLastOccurrence(fileBytes, packageNameBytes);

        if (lastIndex == -1)
        {
            return null;
        }

        // Skip the package name and 4 bytes as per jcalgscan documentation
        var dataStart = lastIndex + packageNameBytes.Length + 4;

        if (dataStart + 3 >= fileBytes.Length)
        {
            return null;
        }

        try
        {
            // Parse: minor_version(1) major_version(1) aid_length(1) aid(aid_length)
            var minorVersion = fileBytes[dataStart];
            var majorVersion = fileBytes[dataStart + 1];
            var aidLength = fileBytes[dataStart + 2];

            if (dataStart + 3 + aidLength > fileBytes.Length)
            {
                return null;
            }

            var aid = new byte[aidLength];
            Array.Copy(fileBytes, dataStart + 3, aid, 0, aidLength);

            return new PackageInfo
            {
                Name = packageName,
                Aid = aid,
                MajorVersion = majorVersion,
                MinorVersion = minorVersion,
                Version = $"{majorVersion}.{minorVersion}",
                SourceFile = relativePath,
                SdkVersion = sdkVersion,
            };
        }
        catch
        {
            return null;
        }
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

    private static string ExtractPackageNameFromPath(string expFilePath)
    {
        // Extract package name from path structure
        // e.g., javacard\framework\javacard\framework.exp -> javacard.framework
        var parts = expFilePath.Replace('\\', '/').Split('/');

        // Look for patterns like: api_export_files/javacard/framework/javacard/framework.exp
        for (var i = 0; i < parts.Length - 1; i++)
        {
            if (parts[i] == "api_export_files" && i + 2 < parts.Length)
            {
                // Take the next parts as package components
                var packageParts = new List<string>();
                for (var j = i + 1; j < parts.Length - 1; j++)
                {
                    packageParts.Add(parts[j]);
                }

                // Determine the full package name with proper prefix
                var packageName = string.Join('.', packageParts);

                // Add proper prefixes based on the package structure
                if (
                    !packageName.StartsWith("java.")
                    && !packageName.StartsWith("javacard.")
                    && !packageName.StartsWith("javacardx.")
                )
                {
                    // Map common packages to their full names
                    packageName = packageName switch
                    {
                        "framework" => "javacard.framework",
                        "framework.service" => "javacard.framework.service",
                        "security" => "javacard.security",
                        "crypto" => "javacardx.crypto",
                        "biometry" => "javacardx.biometry",
                        "biometry1toN" => "javacardx.biometry1toN",
                        "external" => "javacardx.external",
                        "io" => "java.io",
                        "lang" => "java.lang",
                        "rmi" => "java.rmi",
                        "nio" => "java.nio",
                        "framework.tlv" => "javacardx.framework.tlv",
                        "framework.util" => "javacardx.framework.util",
                        "framework.math" => "javacardx.framework.math",
                        "framework.string" => "javacardx.framework.string",
                        "framework.time" => "javacardx.framework.time",
                        "framework.nio" => "javacardx.framework.nio",
                        "framework.event" => "javacardx.framework.event",
                        "apdu.util" => "javacardx.apdu.util",
                        "security.derivation" => "javacardx.security.derivation",
                        "security.cert" => "javacardx.security.cert",
                        "framework.util.intx" => "javacardx.framework.util.intx",
                        _ => packageName,
                    };
                }

                return packageName;
            }
        }

        // Fallback: use filename without extension
        var filename = Path.GetFileNameWithoutExtension(expFilePath);

        // Apply prefix mapping for fallback cases too
        return filename switch
        {
            "framework" => "javacard.framework",
            "security" => "javacard.security",
            "crypto" => "javacardx.crypto",
            _ => filename,
        };
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

    private static async Task WritePackageMappingsAsync(
        Dictionary<string, PackageInfo> mappings,
        string outputPath
    )
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        };

        // Load existing data if file exists
        var existingData = new Dictionary<string, object>();
        var existingPackages = new Dictionary<string, object>();

        if (File.Exists(outputPath))
        {
            try
            {
                var existingJson = await File.ReadAllTextAsync(outputPath);
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

        // Merge new packages with existing ones (new ones take precedence)
        var allPackages = new Dictionary<string, object>(existingPackages);
        foreach (var mapping in mappings)
        {
            allPackages[mapping.Key] = new
            {
                name = mapping.Value.Name,
                version = mapping.Value.Version,
                majorVersion = mapping.Value.MajorVersion,
                minorVersion = mapping.Value.MinorVersion,
                sourceFile = mapping.Value.SourceFile,
                sdkVersion = mapping.Value.SdkVersion,
                lastUpdated = DateTime.UtcNow,
            };
        }

        // Create final JSON structure
        var jsonData = new Dictionary<string, object>(existingData)
        {
            ["generatedAt"] = DateTime.UtcNow,
            ["packageCount"] = allPackages.Count,
            ["packages"] = allPackages,
        };

        var json = JsonSerializer.Serialize(jsonData, options);
        await File.WriteAllTextAsync(outputPath, json);

        var newCount = mappings.Count;
        var totalCount = allPackages.Count;
        AnsiConsole.MarkupLine(
            $"[dim]Added {newCount} new mappings, total: {totalCount} packages[/]"
        );
    }

    private static void DisplayPackageMappings(Dictionary<string, PackageInfo> mappings)
    {
        var table = new Table()
            .AddColumn("Package AID")
            .AddColumn("Package Name")
            .AddColumn("Version")
            .AddColumn("SDK Version")
            .AddColumn("Source File");

        foreach (
            var mapping in mappings.OrderBy(m => m.Value.SdkVersion).ThenBy(m => m.Value.Name)
        )
        {
            _ = table.AddRow(
                $"[dim]{mapping.Key}[/]",
                mapping.Value.Name,
                mapping.Value.Version,
                $"[yellow]{mapping.Value.SdkVersion}[/]",
                $"[dim]{mapping.Value.SourceFile}[/]"
            );
        }

        AnsiConsole.Write(
            new Panel(table)
                .Header("[bold]Discovered Package Mappings[/]")
                .BorderColor(Color.Green)
        );
    }

    /// <summary>
    /// Settings for the scan-sdk command.
    /// </summary>
    public class Settings : CommandSettings
    {
        /// <summary>
        /// Gets or sets the SDK path to scan.
        /// </summary>
        [CommandArgument(0, "<SDK_PATH>")]
        [Description("Path to Oracle Java Card SDK directory")]
        public string SdkPath { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the output file path for JSON mappings.
        /// </summary>
        [CommandOption("-o|--output")]
        [Description("Output file path for JSON package mappings")]
        public string OutputPath { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to show verbose output.
        /// </summary>
        [CommandOption("-v|--verbose")]
        [Description("Show verbose output including errors")]
        public bool Verbose { get; set; }

        /// <inheritdoc />
        public override ValidationResult Validate()
        {
            if (string.IsNullOrWhiteSpace(SdkPath))
            {
                return ValidationResult.Error("SDK path is required");
            }

            return ValidationResult.Success();
        }
    }

    private class PackageInfo
    {
        public string Name { get; set; } = string.Empty;
        public byte[] Aid { get; set; } = [];
        public byte MajorVersion { get; set; }
        public byte MinorVersion { get; set; }
        public string Version { get; set; } = string.Empty;
        public string SourceFile { get; set; } = string.Empty;
        public string SdkVersion { get; set; } = string.Empty;
    }
}