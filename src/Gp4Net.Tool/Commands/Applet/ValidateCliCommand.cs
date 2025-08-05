using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Threading.Tasks;
using Gp4Net.Domain.CapFile;
using Gp4Net.Services;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Applet;

/// <summary>
/// Command to validate a CAP file without installing it.
/// </summary>
[PublicAPI]
public class ValidateCommand : BaseCommand<ValidateCommand.Settings>
{
    private readonly PackageRegistry _packageRegistry;

    /// <summary>
    /// Initializes a new instance of the ValidateCommand class.
    /// </summary>
    public ValidateCommand(
        ICardService cardService,
        Gp4Net.Services.IGlobalPlatformService globalPlatformService,
        PackageRegistry packageRegistry,
        IKeysetResolver keysetResolver
    )
        : base(cardService, globalPlatformService, keysetResolver)
    {
        _packageRegistry = packageRegistry;
    }

    /// <summary>
    /// Executes the validate command to check the integrity of a CAP file.
    /// </summary>
    /// <param name="context">The command context.</param>
    /// <param name="settings">The command settings.</param>
    /// <returns>0 if validation succeeds, 1 if failed.</returns>
    protected override async Task<int> ExecuteCommandAsync(
        CommandContext context,
        Settings settings
    )
    {
        if (!File.Exists(settings.CapFile))
        {
            AnsiConsole.MarkupLine(
                $"[red]CAP file not found: {Markup.Escape(settings.CapFile)}[/]"
            );
            return 1;
        }

        try
        {
            AnsiConsole.MarkupLine(
                $"[cyan]Validating CAP file: {Markup.Escape(settings.CapFile)}[/]"
            );

            var capFileData = await File.ReadAllBytesAsync(settings.CapFile);
            AnsiConsole.MarkupLine($"[dim]File size: {capFileData.Length} bytes[/]");

            var validationResult = CapFileLoadingWorkflow.ValidateCapFile(capFileData);

            if (validationResult.IsValid)
            {
                AnsiConsole.MarkupLine("[green]✓ CAP file is valid[/]");

                // Extract the CAP file structure from Maybe<T>
                if (!validationResult.CapFile.HasValue)
                {
                    AnsiConsole.MarkupLine("[yellow]Warning: CAP file structure not available[/]");
                    return 0;
                }
                
                var capFile = validationResult.CapFile.Value;

                // Display CAP file information without panel
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine("[bold]CAP File Information:[/]");

                var table = new Table().AddColumn("Property").AddColumn("Value");

                _ = table.AddRow("Format", "ZIP/JAR");
                _ = table.AddRow(
                    "Package AID",
                    $"[dim]{Convert.ToHexString(capFile.PackageAid)}[/]"
                );
                _ = table.AddRow(
                    "Package Version",
                    $"{capFile.PackageVersion.Major}.{capFile.PackageVersion.Minor}"
                );
                _ = table.AddRow(
                    "CAP File Version",
                    $"{capFile.CapFileVersion.Major}.{capFile.CapFileVersion.Minor}"
                );

                // Interpret header flags
                var flagsInterpreted = new List<string>();
                if ((capFile.HeaderFlags & 0x01) != 0)
                {
                    flagsInterpreted.Add("INT");
                }

                if ((capFile.HeaderFlags & 0x02) != 0)
                {
                    flagsInterpreted.Add("EXPORT");
                }

                if ((capFile.HeaderFlags & 0x04) != 0)
                {
                    flagsInterpreted.Add("APPLET");
                }

                var flagsDisplay =
                    flagsInterpreted.Count > 0
                        ? $"0x{capFile.HeaderFlags:X2} ({string.Join(", ", flagsInterpreted)})"
                        : $"0x{capFile.HeaderFlags:X2}";
                _ = table.AddRow("Header Flags", flagsDisplay);

                _ = table.AddRow("Total Size", $"{capFile.TotalSize} bytes");
                _ = table.AddRow("Components", capFile.Components.Count.ToString());
                _ = table.AddRow("Applets", capFile.Applets.Count.ToString());

                // Add load blocks estimate
                var binaryData = capFile.ToBinaryFormat();
                var estimatedBlocks = (int)Math.Ceiling((double)binaryData.Length / 245);
                _ = table.AddRow("Est. Load Blocks", estimatedBlocks.ToString());

                AnsiConsole.Write(table);

                // Show memory estimation right after CAP file info
                AnsiConsole.WriteLine();
                DisplayMemoryEstimate(capFileData);

                // Show security analysis
                AnsiConsole.WriteLine();
                DisplaySecurityAnalysis(capFile);

                // Show components and applets (without static field arrays if verbose)
                AnsiConsole.WriteLine();
                DisplayDetailedInformation(capFile, settings.Verbose);

                if (capFile.Manifest != null)
                {
                    AnsiConsole.WriteLine();
                    DisplayManifestInformation(capFile.Manifest, _packageRegistry);
                }

                // Check for embedded class files
                AnsiConsole.WriteLine();
                DisplayClassFileInfo(capFileData);

                // Show static field arrays at the bottom if verbose
                if (settings.Verbose)
                {
                    AnsiConsole.WriteLine();
                    DisplayStaticFieldArrays(capFile);
                }
            }
            else
            {
                AnsiConsole.MarkupLine(
                    $"[red]✗ CAP file validation failed: {Markup.Escape(validationResult.ErrorMessage.GetValueOrDefault("Unknown error"))}[/]"
                );
                return 1;
            }

            return 0;
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine(
                $"[red]Error validating CAP file: {Markup.Escape(ex.Message)}[/]"
            );
            if (settings.Verbose)
            {
                AnsiConsole.WriteException(ex);
            }
            return 1;
        }
    }

    private static void DisplayDetailedInformation(CapFileStructure capFile, bool verbose)
    {
        AnsiConsole.MarkupLine("[bold]Components:[/]");

        var componentsTable = new Table()
            .AddColumn("Tag")
            .AddColumn("Name")
            .AddColumn("Size")
            .AddColumn("Notes");

        foreach (var component in capFile.Components)
        {
            var componentName = GetComponentName(component.Tag);
            var notes = GetComponentNotes(component.Tag, component.Size);
            _ = componentsTable.AddRow(
                $"0x{component.Tag:X2}",
                componentName,
                $"{component.Size} bytes",
                notes
            );
        }

        AnsiConsole.Write(componentsTable);

        if (capFile.Applets.Count > 0)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold]Applets:[/]");

            var appletsTable = new Table().AddColumn("AID").AddColumn("Install Method Offset");

            foreach (var applet in capFile.Applets)
            {
                _ = appletsTable.AddRow(
                    $"[dim]{Convert.ToHexString(applet.Aid)}[/]",
                    $"0x{applet.InstallMethodOffset:X4}"
                );
            }

            AnsiConsole.Write(appletsTable);
        }
    }

    private static void DisplaySecurityAnalysis(CapFileStructure capFile)
    {
        AnsiConsole.MarkupLine("[bold]Security Analysis:[/]");

        var securityTable = new Table().AddColumn("Aspect").AddColumn("Details");

        // Analyze header flags from security perspective
        var capabilities = new List<string>();
        if ((capFile.HeaderFlags & 0x01) != 0)
        {
            capabilities.Add("Requires 32-bit integer support");
        }

        if ((capFile.HeaderFlags & 0x02) != 0)
        {
            capabilities.Add("Exports APIs to other packages");
        }

        if ((capFile.HeaderFlags & 0x04) != 0)
        {
            capabilities.Add("Contains installable applets");
        }

        if (capabilities.Count > 0)
        {
            _ = securityTable.AddRow("Capabilities", string.Join("\n", capabilities));
        }
        else
        {
            _ = securityTable.AddRow("Capabilities", "[dim]None declared[/]");
        }

        // Check for sensitive components
        var hasExport = capFile.Components.Any(c =>
            c.Tag == CapFileStructure.ComponentTags.Export
        );
        var hasDebug = capFile.Components.Any(c =>
            c.Tag == CapFileStructure.ComponentTags.Debug
        );

        var sensitiveComponents = new List<string>();
        if (hasExport)
        {
            sensitiveComponents.Add("Export component present (exposes APIs)");
        }

        if (hasDebug)
        {
            sensitiveComponents.Add(
                "[yellow]Debug component present (may contain sensitive info)[/]"
            );
        }

        if (sensitiveComponents.Count > 0)
        {
            _ = securityTable.AddRow(
                "Sensitive Components",
                string.Join("\n", sensitiveComponents)
            );
        }

        // Analyze imports for crypto usage
        if (
            capFile.Manifest?.ImportedPackages is { Count: > 0 }
        )
        {
            var cryptoImports = new List<string>();
            foreach (var import in capFile.Manifest.ImportedPackages)
            {
                var aidUpper = import.Aid.ToUpper().Replace(":", "").Replace("0X", "");
                if (aidUpper.Contains("A0000000620102"))
                {
                    cryptoImports.Add("[green]javacard.security[/] v" + import.Version);
                }

                if (aidUpper.Contains("A0000000620201"))
                {
                    cryptoImports.Add("[green]javacardx.crypto[/] v" + import.Version);
                }
            }

            if (cryptoImports.Count > 0)
            {
                _ = securityTable.AddRow("Crypto Usage", string.Join("\n", cryptoImports));
            }
        }

        // Static field analysis summary
        var staticFieldComponent = capFile.Components.FirstOrDefault(c =>
            c.Tag == CapFileStructure.ComponentTags.StaticField
        );
        if (staticFieldComponent is { Size: > 0 })
        {
            _ = securityTable.AddRow(
                "Static Data",
                $"{staticFieldComponent.Size} bytes (use --verbose to inspect)"
            );
        }

        // Applet installation info
        if (capFile.Applets.Count > 0)
        {
            var appletInfo = new List<string>();
            foreach (var applet in capFile.Applets)
            {
                appletInfo.Add($"AID: {Convert.ToHexString(applet.Aid)}");
            }
            _ = securityTable.AddRow("Installable Applets", string.Join("\n", appletInfo));
        }

        AnsiConsole.Write(securityTable);
    }

    private static void DisplayMemoryEstimate(byte[] capFileData)
    {
        try
        {
            var memoryReq = CapFileLoadingWorkflow.EstimateMemoryRequirements(capFileData);

            AnsiConsole.MarkupLine("[bold]Memory Requirements (Estimated):[/]");

            var memoryTable = new Table().AddColumn("Memory Type").AddColumn("Estimated Size");

            _ = memoryTable.AddRow("Code Memory", $"{memoryReq.CodeMemory} bytes");
            _ = memoryTable.AddRow("Data Memory", $"{memoryReq.DataMemory} bytes");
            _ = memoryTable.AddRow("Total Size", $"{memoryReq.TotalSize} bytes");

            AnsiConsole.Write(memoryTable);
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine(
                $"[yellow]Could not estimate memory requirements: {Markup.Escape(ex.Message)}[/]"
            );
        }
    }

    private static void DisplayManifestInformation(
        ManifestInfo manifest,
        PackageRegistry packageRegistry
    )
    {
        try
        {
            AnsiConsole.MarkupLine("[bold]Manifest Information:[/]");

            var manifestTable = new Table().AddColumn("Property").AddColumn("Value");

            if (!string.IsNullOrEmpty(manifest.PackageName))
            {
                _ = manifestTable.AddRow("Package Name", Markup.Escape(manifest.PackageName));
            }

            if (!string.IsNullOrEmpty(manifest.CapFileVersion))
            {
                _ = manifestTable.AddRow(
                    "CAP File Version",
                    Markup.Escape(manifest.CapFileVersion)
                );
            }

            if (!string.IsNullOrEmpty(manifest.ConverterVersion))
            {
                _ = manifestTable.AddRow(
                    "Converter Version",
                    Markup.Escape(manifest.ConverterVersion)
                );
            }

            if (!string.IsNullOrEmpty(manifest.ConverterProvider))
            {
                _ = manifestTable.AddRow(
                    "Converter Provider",
                    Markup.Escape(manifest.ConverterProvider)
                );
            }

            if (!string.IsNullOrEmpty(manifest.CreationTime))
            {
                _ = manifestTable.AddRow("Creation Time", Markup.Escape(manifest.CreationTime));
            }

            if (manifest.IntegerSupportRequired.HasValue)
            {
                _ = manifestTable.AddRow(
                    "Integer Support Required",
                    manifest.IntegerSupportRequired.Value ? "Yes" : "No"
                );
            }

            AnsiConsole.Write(manifestTable);

            if (manifest.ImportedPackages.Count > 0)
            {
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine("[bold]Import Dependencies:[/]");

                var importsTable = new Table()
                    .AddColumn("Package AID")
                    .AddColumn("Required Version")
                    .AddColumn("Resolved Package")
                    .AddColumn("SDK Version");

                foreach (var import in manifest.ImportedPackages)
                {
                    var formattedAid = FormatAidAsHex(import.Aid);

                    // Try to resolve the package
                    var resolvedName = "[dim]Unknown[/]";
                    var sdkVersion = "[dim]N/A[/]";

                    if (packageRegistry.TryResolveAid(formattedAid, out var packageInfo))
                    {
                        resolvedName = $"[green]{packageInfo?.DisplayName ?? "Unknown"}[/]";
                        sdkVersion = $"[yellow]{packageInfo?.SdkVersion ?? "Unknown"}[/]";
                    }

                    _ = importsTable.AddRow(
                        $"[dim]{formattedAid}[/]",
                        Markup.Escape(import.Version),
                        resolvedName,
                        sdkVersion
                    );
                }

                AnsiConsole.Write(importsTable);
            }
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine(
                $"[yellow]Could not display manifest information: {Markup.Escape(ex.Message)}[/]"
            );
        }
    }

    private static string GetComponentNotes(byte tag, int size)
    {
        return tag switch
        {
            0x01 => "Package metadata",
            0x02 => "Component directory",
            0x03 => "Applet definitions",
            0x04 => "Package dependencies",
            0x05 => "Shared constants",
            0x06 => "Class definitions",
            0x07 => size > 10000 ? "[yellow]Large bytecode[/]" : "Bytecode",
            0x08 => "Static fields/arrays",
            0x09 => "Relocation info",
            0x0A => "[green]Exported APIs[/]",
            0x0B => "Type descriptors",
            0x0C => "[yellow]Debug info[/]",
            _ => "[dim]Unknown[/]",
        };
    }

    private static string GetComponentName(byte tag)
    {
        return tag switch
        {
            0x01 => "Header",
            0x02 => "Directory",
            0x03 => "Applet",
            0x04 => "Import",
            0x05 => "Constant Pool",
            0x06 => "Class",
            0x07 => "Method",
            0x08 => "Static Field",
            0x09 => "Reference Location",
            0x0A => "Export",
            0x0B => "Descriptor",
            0x0C => "Debug",
            _ => "Unknown",
        };
    }

    private static string FormatAidAsHex(string aid)
    {
        return aid.Replace("0x", "").Replace(":", "").ToUpper();
    }

    private static void DisplayClassFileInfo(byte[] capFileData)
    {
        try
        {
            AnsiConsole.MarkupLine("[bold]Class File Analysis:[/]");

            // Check if this is a ZIP/JAR file
            using var stream = new MemoryStream(capFileData);
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read);

            var classFiles = new List<string>();
            var otherFiles = new Dictionary<string, int>();

            foreach (var entry in archive.Entries)
            {
                if (entry.FullName.EndsWith(".class", StringComparison.OrdinalIgnoreCase))
                {
                    classFiles.Add(entry.FullName);
                }
                else if (!entry.FullName.EndsWith("/") && !entry.FullName.Contains("/."))
                {
                    // Count other file types
                    var extension = Path.GetExtension(entry.FullName).ToLowerInvariant();
                    if (string.IsNullOrEmpty(extension))
                    {
                        extension = "[no extension]";
                    }

                    if (!otherFiles.ContainsKey(extension))
                    {
                        otherFiles[extension] = 0;
                    }

                    otherFiles[extension]++;
                }
            }

            if (classFiles.Count > 0)
            {
                AnsiConsole.MarkupLine(
                    $"[yellow]Found {classFiles.Count} Java class files embedded in CAP[/]"
                );
                AnsiConsole.WriteLine();

                // Extract package structure
                var packages = new HashSet<string>();
                var classNames = new List<string>();

                foreach (var classFile in classFiles)
                {
                    var className = Path.GetFileNameWithoutExtension(classFile);
                    classNames.Add(className);

                    // Extract package path
                    var lastSlash = classFile.LastIndexOf('/');
                    if (lastSlash > 0)
                    {
                        var packagePath = classFile.Substring(0, lastSlash);
                        if (packagePath.Contains("/classes/"))
                        {
                            packagePath = packagePath.Substring(
                                packagePath.IndexOf("/classes/") + 9
                            );
                        }

                        _ = packages.Add(packagePath.Replace('/', '.'));
                    }
                }

                // Display packages
                if (packages.Count > 0)
                {
                    AnsiConsole.WriteLine("Packages found:");
                    foreach (var pkg in packages.OrderBy(p => p))
                    {
                        AnsiConsole.WriteLine($"  • {pkg}");
                    }
                    AnsiConsole.WriteLine();
                }

                // Display class names (limit to first 20)
                AnsiConsole.WriteLine("Classes found:");
                var sortedClasses = classNames.OrderBy(c => c).ToList();
                foreach (var className in sortedClasses.Take(20))
                {
                    AnsiConsole.WriteLine($"  • {className}");
                }
                if (sortedClasses.Count > 20)
                {
                    AnsiConsole.WriteLine($"  ... and {sortedClasses.Count - 20} more classes");
                }
            }
            else
            {
                AnsiConsole.MarkupLine(
                    "[dim]No Java class files found (standard CAP format)[/]"
                );
            }

            // Show other file types if present
            if (otherFiles.Count > 0)
            {
                AnsiConsole.WriteLine();
                AnsiConsole.WriteLine("Other file types:");
                foreach (var fileType in otherFiles.OrderBy(f => f.Key))
                {
                    AnsiConsole.WriteLine($"  • {fileType.Value} {fileType.Key} files");
                }
            }
        }
        catch (Exception)
        {
            AnsiConsole.MarkupLine($"[dim]Standard binary CAP format (no embedded files)[/]");
        }
    }

    private static void DisplayStaticFieldArrays(CapFileStructure capFile)
    {
        try
        {
            // Find the static field component
            var staticFieldComponent = capFile.Components.FirstOrDefault(c =>
                c.Tag == CapFileStructure.ComponentTags.StaticField
            );
            if (staticFieldComponent == null)
            {
                AnsiConsole.MarkupLine("[yellow]No static field component found[/]");
                return;
            }

            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold]Static Field Arrays:[/]");

            var data = staticFieldComponent.Data;
            if (data.Length < 8)
            {
                AnsiConsole.WriteLine("Static field component too short");
                return;
            }

            var offset = 0;
            // Skip image_size (2 bytes), reference_count (2 bytes)
            offset += 4;

            // Read array_init_count
            var arrayInitCount = (ushort)((data[offset] << 8) | data[offset + 1]);
            offset += 2;

            AnsiConsole.WriteLine($"Found {arrayInitCount} initialized arrays:");
            AnsiConsole.WriteLine();

            // Parse each array_init_info structure
            for (var i = 0; i < arrayInitCount; i++)
            {
                if (offset + 2 >= data.Length)
                {
                    break;
                }

                var type = data[offset++];
                var count = (ushort)((data[offset] << 8) | data[offset + 1]);
                offset += 2;

                if (offset + count > data.Length)
                {
                    break;
                }

                var arrayData = new byte[count];
                Array.Copy(data, offset, arrayData, 0, count);
                offset += count;

                DisplayArrayData(i, type, arrayData);
            }
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine(
                $"[red]Error parsing static field arrays: {Markup.Escape(ex.Message)}[/]"
            );
        }
    }

    private static void DisplayArrayData(int index, byte type, byte[] data)
    {
        var typeName = GetArrayTypeName(type);
        AnsiConsole.WriteLine($"Array #{index}: {typeName}[{data.Length}]");

        // Display as hexdump
        for (var i = 0; i < data.Length; i += 16)
        {
            var lineBytes = data.Skip(i).Take(16).ToArray();
            var hex = string.Join(" ", lineBytes.Select(b => $"{b:X2}"));
            var ascii = new string(
                [.. lineBytes.Select(b => b is >= 32 and < 127 ? (char)b : '.')]
            );
            AnsiConsole.WriteLine($"  {i:X4}:  {hex, -47} |{ascii}|");
        }
        AnsiConsole.WriteLine();
    }

    private static string GetArrayTypeName(byte type)
    {
        return type switch
        {
            0x02 => "boolean",
            0x03 => "byte",
            0x04 => "short",
            0x05 => "int",
            _ => $"unknown(0x{type:X2})",
        };
    }

    /// <summary>
    /// Settings for the validate command.
    /// </summary>
    public class Settings : BaseCommandSettings
    {
        /// <summary>
        /// Gets or sets the CAP file path.
        /// </summary>
        [CommandArgument(0, "<CAP_FILE>")]
        [Description("Path to the CAP file to validate")]
        public string CapFile { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets a value indicating whether to show detailed information.
        /// </summary>
        [CommandOption("-d|--detailed")]
        [Description("Show detailed CAP file information")]
        public bool Detailed { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to estimate memory requirements.
        /// </summary>
        [CommandOption("-m|--memory")]
        [Description("Estimate memory requirements")]
        public bool EstimateMemory { get; set; }

        /// <summary>
        /// Validates the command settings.
        /// </summary>
        /// <returns>Success if valid, or an error message if validation fails.</returns>
        public override ValidationResult Validate()
        {
            if (string.IsNullOrWhiteSpace(CapFile))
            {
                return ValidationResult.Error("CAP file path is required");
            }

            return ValidationResult.Success();
        }
    }
}