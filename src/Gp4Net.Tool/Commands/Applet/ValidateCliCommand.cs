using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using System.Xml.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.CapFile;
using Gp4Net.Services;
using Gp4Net.Tool.Commands.Common;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Pipeline;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Applet;

/// <summary>
/// Command to validate a CAP file without installing it.
/// </summary>
[PublicAPI]
[CliCommand("validate", "Validate a CAP file without installing it", "applet")]
public class ValidateCommand : AsyncCommand<ValidateCommand.Settings>
{
    private readonly IDisplayService _displayService;
    private readonly IKeysetResolver _keysetResolver;
    private readonly PackageRegistry _packageRegistry;

    /// <summary>
    /// Initializes a new instance of the ValidateCommand class.
    /// </summary>
    public ValidateCommand(
        IDisplayService displayService,
        IKeysetResolver keysetResolver,
        PackageRegistry packageRegistry
    )
    {
        _displayService = displayService;
        _keysetResolver = keysetResolver;
        _packageRegistry = packageRegistry;
    }

    /// <summary>
    /// Executes the validate command to check the integrity of a CAP file.
    /// </summary>
    /// <param name="context">The command context.</param>
    /// <param name="settings">The command settings.</param>
    /// <returns>0 if validation succeeds, 1 if failed.</returns>
    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings)
    {
        return await ValidateCapFileExists(settings.CapFile)
            .Bind(_ =>
            {
                _displayService.Info($"Validating CAP file: {settings.CapFile}");
                return Result.Success<bool, SmartCardError>(true);
            })
            .Bind(_ => LoadAndValidateCapFile(settings.CapFile))
            .Bind(async result =>
                await ProcessValidationResult(result.validationResult, result.capFileData, settings)
            )
            .Match(
                success => Task.FromResult(0),
                error =>
                {
                    _displayService.Error($"Validation failed: {error.Message}");
                    return Task.FromResult(1);
                }
            );
    }

    private static Result<bool, SmartCardError> ValidateCapFileExists(string capFilePath)
    {
        return File.Exists(capFilePath)
            ? Result.Success<bool, SmartCardError>(true)
            : Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument($"CAP file not found: {capFilePath}")
            );
    }

    private async Task<
        Result<(CapFileValidationResult validationResult, byte[] capFileData), SmartCardError>
    > LoadAndValidateCapFile(string capFilePath)
    {
        return await Result.Try(
            async () =>
            {
                byte[] capFileData = await File.ReadAllBytesAsync(capFilePath);
                _displayService.Info($"File size: {capFileData.Length} bytes");

                var validationResult = CapFileLoadingWorkflow.ValidateCapFile(capFileData);
                return (validationResult, capFileData);
            },
            ex => SmartCardError.InvalidArgument($"Failed to load/validate CAP file: {ex.Message}")
        );
    }

    private async Task<Result<bool, SmartCardError>> ProcessValidationResult(
        CapFileValidationResult validationResult,
        byte[] capFileData,
        Settings settings
    )
    {
        if (!validationResult.IsValid)
        {
            string errorMessage = validationResult.ErrorMessage.GetValueOrDefault(
                "Unknown validation error"
            );
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument($"CAP file validation failed: {errorMessage}")
            );
        }

        _displayService.Success("✓ CAP file is valid");

        return await validationResult.CapFile.Match(
            async capFile => await DisplayCapFileAnalysis(capFile, capFileData, settings),
            () =>
            {
                _displayService.Warning("Warning: CAP file structure not available");
                return Task.FromResult(Result.Success<bool, SmartCardError>(true));
            }
        );
    }

    private async Task<Result<bool, SmartCardError>> DisplayCapFileAnalysis(
        CapFileStructure capFile,
        byte[] capFileData,
        Settings settings
    )
    {
        return await Task.Run(() =>
        {
            if (settings.Format == OutputFormat.Json)
            {
                DisplayJsonOutput(capFile, settings);
            }
            else
            {
                DisplayCapFileInformation(capFile);
                DisplayMemoryEstimate(capFileData);
                DisplaySecurityAnalysis(capFile);
                DisplayExportedApis(capFile);
                DisplayDetailedInformation(capFile, settings.Detailed);
                DisplayCapInternals(capFile, _packageRegistry, settings.Detailed, settings.Verbose);

                _ = capFile.Manifest.Match(
                    manifest =>
                    {
                        DisplayManifestInformation(manifest, _packageRegistry);
                        return true;
                    },
                    () => true
                );

                DisplayArchiveMetadata(capFileData);
                DisplayClassFileInfo(capFileData);
            }

            return Result.Success<bool, SmartCardError>(true);
        });
    }

    private void DisplayJsonOutput(CapFileStructure capFile, Settings settings)
    {
        var components = capFile.Components.Select(c => ComponentSummary.FromComponent(c)).ToList();

        var errors = new List<ValidationMessage>();
        var warnings = new List<ValidationMessage>();
        var infos = new List<ValidationMessage>();

        if (!capFile.Manifest.HasValue)
        {
            warnings.Add(
                ValidationMessage.Warning(
                    "MANIFEST-MISSING",
                    "Manifest not found",
                    Maybe<string>.From("META-INF/MANIFEST.MF"),
                    Maybe<string>.From("Add manifest with Package-Name and Package-Version")
                )
            );
        }

        var debugComponent = capFile.Components.FirstOrDefault(c =>
            c.Tag == Constants.Constants.JavaCard.ComponentTags.DEBUG
        );
        if (debugComponent != null)
        {
            infos.Add(
                ValidationMessage.Info(
                    "DEBUG-COMPONENT",
                    "Debug component included",
                    Maybe<string>.From(
                        $"Component tag 0x{debugComponent.Tag:X2}, {debugComponent.Size} bytes"
                    ),
                    Maybe<string>.From("Strip debug component for production builds")
                )
            );
        }

        var validationResult = CapValidationResult.FromCapFile(
            settings.CapFile,
            capFile,
            components,
            errors,
            warnings,
            infos
        );

        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = System
                .Text
                .Json
                .Serialization
                .JsonIgnoreCondition
                .WhenWritingNull,
            Converters = { new Tool.Common.ByteArrayHexConverter() },
        };

        string json = JsonSerializer.Serialize(validationResult, options);
        AnsiConsole.WriteLine(json);
    }

    private void DisplayCapFileInformation(CapFileStructure capFile)
    {
        var table = new Table()
            .AddColumn("[cyan]Property[/]")
            .AddColumn("[cyan]Value[/]")
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Blue);

        table.Caption = new TableTitle("[dim]Summary[/]");

        _ = table.AddRow("[cyan]Format[/]", "[green]ZIP/JAR[/]");
        _ = table.AddRow(
            "[cyan]Package AID[/]",
            $"[cyan]{Convert.ToHexString(capFile.PackageAid)}[/]"
        );
        _ = table.AddRow(
            "[cyan]Package Version[/]",
            $"[yellow]{capFile.PackageVersion.Major}.{capFile.PackageVersion.Minor}[/]"
        );
        _ = table.AddRow(
            "[cyan]CAP File Version[/]",
            $"[yellow]{capFile.CapFileVersion.Major}.{capFile.CapFileVersion.Minor}[/]"
        );

        // Create header flags display functionally
        string headerFlags = CreateHeaderFlagsDisplay(capFile.HeaderFlags);
        _ = table.AddRow("[cyan]Header Flags[/]", $"[yellow]{headerFlags}[/]");

        _ = table.AddRow("[cyan]Total Size[/]", $"[green]{capFile.TotalSize} bytes[/]");
        _ = table.AddRow("[cyan]Components[/]", $"[green]{capFile.Components.Count}[/]");
        _ = table.AddRow("[cyan]Applets[/]", $"[green]{capFile.Applets.Count}[/]");

        // Add load blocks estimate
        byte[] binaryData = capFile.ToBinaryFormat();
        int estimatedBlocks = (int)Math.Ceiling((double)binaryData.Length / 245);
        _ = table.AddRow("[cyan]Est. Load Blocks[/]", $"[green]{estimatedBlocks}[/]");

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[bold blue]CAP File Information:[/]");
        AnsiConsole.Write(table);
    }

    private static string CreateHeaderFlagsDisplay(byte headerFlags)
    {
        (byte mask, string name)[] flagMappings =
        [
            (0x01, "INT"),
            (0x02, "EXPORT"),
            (0x04, "APPLET"),
        ];

        List<string> flagsInterpreted =
        [
            .. flagMappings
                .Where(mapping => (headerFlags & mapping.mask) != 0)
                .Select(mapping => mapping.name),
        ];

        return flagsInterpreted.Any()
            ? $"0x{headerFlags:X2} ({string.Join(", ", flagsInterpreted)})"
            : $"0x{headerFlags:X2}";
    }

    private static void DisplayDetailedInformation(CapFileStructure capFile, bool verbose)
    {
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[bold blue]Components:[/]");

        var componentsTable = new Table()
            .AddColumn("[cyan]Tag[/]")
            .AddColumn("[cyan]Name[/]")
            .AddColumn("[cyan]Size[/]")
            .AddColumn("[cyan]Notes[/]")
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Blue);

        componentsTable.Caption = new TableTitle("[dim]Component Overview[/]");

        foreach (var component in capFile.Components)
        {
            string componentName = GetComponentName(component.Tag);
            string notes = GetComponentNotes(component.Tag, component.Size);
            _ = componentsTable.AddRow(
                $"[cyan]0x{component.Tag:X2}[/]",
                componentName,
                $"[green]{component.Size} bytes[/]",
                notes
            );
        }

        AnsiConsole.Write(componentsTable);

        if (capFile.Applets.Count > 0)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold green]Applets:[/]");

            var appletsTable = new Table()
                .AddColumn("[cyan]AID[/]")
                .AddColumn("[cyan]Install Method Offset[/]")
                .Border(TableBorder.Rounded)
                .BorderColor(Color.Green);

            appletsTable.Caption = new TableTitle("[dim]Applet Install Targets[/]");

            foreach (var applet in capFile.Applets)
            {
                _ = appletsTable.AddRow(
                    $"[cyan]{Convert.ToHexString(applet.Aid)}[/]",
                    $"[yellow]0x{applet.InstallMethodOffset:X4}[/]"
                );
            }

            AnsiConsole.Write(appletsTable);
        }
    }

    private static void DisplaySecurityAnalysis(CapFileStructure capFile)
    {
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[bold yellow]Security Analysis:[/]");

        var securityTable = new Table()
            .AddColumn("[cyan]Aspect[/]")
            .AddColumn("[cyan]Details[/]")
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Yellow);

        securityTable.Caption = new TableTitle("[dim]Security Signals[/]");

        // Analyze header flags from security perspective
        List<string> capabilities = [];
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
            _ = securityTable.AddRow(
                "[cyan]Capabilities[/]",
                string.Join("\n", capabilities.Select(capability => $"[green]{capability}[/]"))
            );
        }
        else
        {
            _ = securityTable.AddRow("[cyan]Capabilities[/]", "[dim]None declared[/]");
        }

        // Check for sensitive components
        bool hasExport = capFile.Components.Any(c =>
            c.Tag == Constants.Constants.JavaCard.ComponentTags.EXPORT
        );
        bool hasDebug = capFile.Components.Any(c =>
            c.Tag == Constants.Constants.JavaCard.ComponentTags.DEBUG
        );

        List<string> sensitiveComponents = [];
        if (hasExport)
        {
            string exportSummary = ExportComponentAnalysis
                .Parse(capFile)
                .Map(FormatExportSummary)
                .GetValueOrDefault("Export component present (exposes APIs)");
            sensitiveComponents.Add(exportSummary);
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
                "[cyan]Sensitive Components[/]",
                string.Join("\n", sensitiveComponents)
            );
        }

        // Analyze imports for crypto usage
        capFile.Manifest.Execute(manifest =>
        {
            if (manifest.ImportedPackages.Count == 0)
            {
                return;
            }

            List<string> cryptoImports = [];
            foreach (var import in manifest.ImportedPackages)
            {
                string aidUpper = import.Aid.ToUpper().Replace(":", "").Replace("0X", "");
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
                _ = securityTable.AddRow("[cyan]Crypto Usage[/]", string.Join("\n", cryptoImports));
            }
        });

        // Static Field component summary
        var staticFieldComponent = capFile.Components.FirstOrDefault(c =>
            c.Tag == Constants.Constants.JavaCard.ComponentTags.STATIC_FIELD
        );
        if (staticFieldComponent is { Size: > 0 })
        {
            string details = StaticFieldComponentAnalysis
                .Parse(staticFieldComponent.Data)
                .Map(FormatStaticFieldSummary)
                .GetValueOrDefault($"{staticFieldComponent.Size} bytes");

            _ = securityTable.AddRow(
                "[cyan]Static Field Component[/]",
                $"[green]{details}[/] [dim](use --verbose for layout)[/]"
            );
        }

        // Applet installation info
        if (capFile.Applets.Count > 0)
        {
            List<string> appletInfo = [];
            foreach (var applet in capFile.Applets)
            {
                appletInfo.Add($"AID: [cyan]{Convert.ToHexString(applet.Aid)}[/]");
            }
            _ = securityTable.AddRow("[cyan]Installable Applets[/]", string.Join("\n", appletInfo));
        }

        AnsiConsole.Write(securityTable);
    }

    private static string FormatExportSummary(ExportComponentAnalysis analysis) =>
        $"Exports {analysis.Classes.Count} classes/interfaces, {analysis.StaticFieldCount} static fields, "
        + $"{analysis.StaticMethodCount} static methods/constructors";

    private static string FormatToken(byte token) => $"0x{token:X2}";

    private static string FormatOffset(ushort offset) => $"0x{offset:X4}";

    private static string FormatClassKind(ExportedClassInfo exportedClass) =>
        exportedClass.Descriptor.Match(
            descriptor => (descriptor.AccessFlags & 0x40) != 0 ? "interface" : "class",
            () => "[dim]unknown[/]"
        );

    private static string FormatClassAccess(ExportedClassInfo exportedClass) =>
        exportedClass.Descriptor.Match(
            descriptor =>
            {
                List<string> flags = [];
                if ((descriptor.AccessFlags & 0x01) != 0)
                {
                    flags.Add("public");
                }

                if ((descriptor.AccessFlags & 0x10) != 0)
                {
                    flags.Add("final");
                }

                if ((descriptor.AccessFlags & 0x40) != 0)
                {
                    flags.Add("interface");
                }

                if ((descriptor.AccessFlags & 0x80) != 0)
                {
                    flags.Add("abstract");
                }

                string decodedFlags = flags.Count > 0 ? string.Join(" ", flags) : "none";
                return $"{decodedFlags} [dim](0x{descriptor.AccessFlags:X2})[/]";
            },
            () => "[dim]unresolved[/]"
        );

    private static string FormatStaticFields(IReadOnlyList<ExportedStaticFieldInfo> fields)
    {
        if (fields.Count == 0)
        {
            return "[dim]none[/]";
        }

        return string.Join(
            "\n",
            fields.Select(field =>
                $"token {FormatToken(field.Token)} -> static image {FormatOffset(field.StaticFieldImageOffset)}"
            )
        );
    }

    private static string FormatStaticMethods(IReadOnlyList<ExportedStaticMethodInfo> methods)
    {
        if (methods.Count == 0)
        {
            return "[dim]none[/]";
        }

        return string.Join("\n", methods.Select(FormatStaticMethod));
    }

    private static string FormatStaticMethod(ExportedStaticMethodInfo method)
    {
        string text =
            $"token {FormatToken(method.Token)} -> method {FormatOffset(method.MethodOffset)}";

        method.Descriptor.Execute(descriptor =>
        {
            text +=
                $" ({FormatMethodAccessFlags(descriptor.AccessFlags)}; "
                + $"bytecodes {descriptor.BytecodeCount}; type {FormatOffset(descriptor.TypeOffset)}";

            if (descriptor.ExceptionHandlerCount > 0)
            {
                text +=
                    $"; handlers {descriptor.ExceptionHandlerCount}"
                    + $" @ {descriptor.ExceptionHandlerIndex}";
            }

            text += ")";
        });

        method.MethodHeader.Execute(header =>
        {
            text +=
                $" (stack {header.MaxStack}, args {header.ArgumentCount}, locals {header.MaxLocals}";

            if (header.IsExtended)
            {
                text += ", extended";
            }

            if (header.IsAbstract)
            {
                text += ", abstract";
            }

            text += ")";
        });

        return text;
    }

    private static string FormatMethodDescriptor(ExportedStaticMethodInfo method) =>
        method.Descriptor.Match(FormatMethodDescriptor, () => "[dim]unresolved[/]");

    private static string FormatMethodDescriptor(MethodDescriptorInfo descriptor)
    {
        string text =
            $"{FormatMethodAccessFlags(descriptor.AccessFlags)}; "
            + $"bytecodes {descriptor.BytecodeCount}; type {FormatOffset(descriptor.TypeOffset)}";

        if (descriptor.ExceptionHandlerCount > 0)
        {
            text +=
                $"; handlers {descriptor.ExceptionHandlerCount} @ {descriptor.ExceptionHandlerIndex}";
        }

        return text;
    }

    private static string FormatMethodHeader(ExportedStaticMethodInfo method) =>
        FormatMethodHeader(method.MethodHeader);

    private static string FormatMethodHeader(Maybe<MethodHeaderInfo> methodHeader) =>
        methodHeader.Match(
            header =>
            {
                string text =
                    $"stack {header.MaxStack}, args {header.ArgumentCount}, locals {header.MaxLocals}";

                if (header.IsExtended)
                {
                    text += ", extended";
                }

                if (header.IsAbstract)
                {
                    text += ", abstract";
                }

                return text;
            },
            () => "[dim]unresolved[/]"
        );

    private static string FormatMethodAccessFlags(byte accessFlags)
    {
        List<string> flags = [];
        if ((accessFlags & 0x01) != 0)
        {
            flags.Add("public");
        }

        if ((accessFlags & 0x02) != 0)
        {
            flags.Add("private");
        }

        if ((accessFlags & 0x04) != 0)
        {
            flags.Add("protected");
        }

        if ((accessFlags & 0x08) != 0)
        {
            flags.Add("static");
        }

        if ((accessFlags & 0x10) != 0)
        {
            flags.Add("final");
        }

        if ((accessFlags & 0x40) != 0)
        {
            flags.Add("abstract");
        }

        if ((accessFlags & 0x80) != 0)
        {
            flags.Add("init");
        }

        string decodedFlags = flags.Count > 0 ? string.Join(" ", flags) : "none";
        return $"{decodedFlags} 0x{accessFlags:X2}";
    }

    private static string FormatDescriptorClassAccess(byte accessFlags)
    {
        List<string> flags = [];
        if ((accessFlags & 0x01) != 0)
        {
            flags.Add("public");
        }

        if ((accessFlags & 0x10) != 0)
        {
            flags.Add("final");
        }

        if ((accessFlags & 0x40) != 0)
        {
            flags.Add("interface");
        }

        if ((accessFlags & 0x80) != 0)
        {
            flags.Add("abstract");
        }

        string decodedFlags = flags.Count > 0 ? string.Join(" ", flags) : "none";
        return $"{decodedFlags} 0x{accessFlags:X2}";
    }

    private static string FormatFieldAccessFlags(byte accessFlags)
    {
        List<string> flags = [];
        if ((accessFlags & 0x01) != 0)
        {
            flags.Add("public");
        }

        if ((accessFlags & 0x02) != 0)
        {
            flags.Add("private");
        }

        if ((accessFlags & 0x04) != 0)
        {
            flags.Add("protected");
        }

        if ((accessFlags & 0x08) != 0)
        {
            flags.Add("static");
        }

        if ((accessFlags & 0x10) != 0)
        {
            flags.Add("final");
        }

        string decodedFlags = flags.Count > 0 ? string.Join(" ", flags) : "none";
        return $"{decodedFlags} 0x{accessFlags:X2}";
    }

    private static void DisplayExportedApis(CapFileStructure capFile)
    {
        var exportComponent = capFile.Components.FirstOrDefault(c =>
            c.Tag == Constants.Constants.JavaCard.ComponentTags.EXPORT
        );
        if (exportComponent == null)
        {
            return;
        }

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[bold yellow]Exported APIs:[/]");

        var analysisResult = ExportComponentAnalysis.Parse(capFile);
        if (analysisResult.IsFailure)
        {
            AnsiConsole.MarkupLine($"[yellow]{Markup.Escape(analysisResult.Error.Message)}[/]");
            return;
        }

        var analysis = analysisResult.Value;
        var summaryTable = new Table()
            .AddColumn("[cyan]Metric[/]")
            .AddColumn("[cyan]Value[/]")
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Yellow);

        _ = summaryTable.AddRow(
            "[cyan]Component Body Size[/]",
            $"{analysis.ComponentBodySize} bytes"
        );
        _ = summaryTable.AddRow(
            "[cyan]Exported Classes/Interfaces[/]",
            analysis.Classes.Count.ToString()
        );
        _ = summaryTable.AddRow("[cyan]Static Fields[/]", analysis.StaticFieldCount.ToString());
        _ = summaryTable.AddRow(
            "[cyan]Static Methods/Constructors[/]",
            analysis.StaticMethodCount.ToString()
        );
        summaryTable.Caption = new TableTitle("[dim]Export Component Summary[/]");
        AnsiConsole.Write(summaryTable);

        var classTable = new Table()
            .AddColumn("[cyan]Class Token[/]")
            .AddColumn("[cyan]Offset[/]")
            .AddColumn("[cyan]Kind[/]")
            .AddColumn("[cyan]Access[/]")
            .AddColumn("[cyan]Fields[/]")
            .AddColumn("[cyan]Methods[/]")
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Yellow);

        foreach (var exportedClass in analysis.Classes)
        {
            _ = classTable.AddRow(
                FormatToken(exportedClass.Token),
                FormatOffset(exportedClass.ClassOffset),
                FormatClassKind(exportedClass),
                FormatClassAccess(exportedClass),
                exportedClass.StaticFields.Count.ToString(),
                exportedClass.StaticMethods.Count.ToString()
            );
        }

        classTable.Caption = new TableTitle("[dim]Exported Class Tokens[/]");
        AnsiConsole.Write(classTable);

        DisplayExportedStaticFields(
            analysis.Classes.SelectMany(exportedClass =>
                exportedClass.StaticFields.Select(field => (exportedClass, field))
            )
        );
        DisplayExportedStaticMethods(
            analysis.Classes.SelectMany(exportedClass =>
                exportedClass.StaticMethods.Select(method => (exportedClass, method))
            )
        );

        AnsiConsole.MarkupLine(
            "[dim]CAP Export components expose tokens and offsets, not Java names.[/]"
        );
    }

    private static void DisplayExportedStaticFields(
        IEnumerable<(ExportedClassInfo exportedClass, ExportedStaticFieldInfo field)> exportedFields
    )
    {
        var fields = exportedFields.ToList();
        if (fields.Count == 0)
        {
            return;
        }

        var fieldTable = new Table()
            .AddColumn("[cyan]Class Token[/]")
            .AddColumn("[cyan]Field Token[/]")
            .AddColumn("[cyan]Static Image Offset[/]")
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Yellow);

        foreach (var (exportedClass, field) in fields)
        {
            _ = fieldTable.AddRow(
                FormatToken(exportedClass.Token),
                FormatToken(field.Token),
                FormatOffset(field.StaticFieldImageOffset)
            );
        }

        fieldTable.Caption = new TableTitle("[dim]Exported Static Field Tokens[/]");
        AnsiConsole.Write(fieldTable);
    }

    private static void DisplayExportedStaticMethods(
        IEnumerable<(
            ExportedClassInfo exportedClass,
            ExportedStaticMethodInfo method
        )> exportedMethods
    )
    {
        var methods = exportedMethods.ToList();
        if (methods.Count == 0)
        {
            return;
        }

        var methodTable = new Table()
            .AddColumn("[cyan]Class Token[/]")
            .AddColumn("[cyan]Method Token[/]")
            .AddColumn("[cyan]Method Offset[/]")
            .AddColumn("[cyan]Descriptor[/]")
            .AddColumn("[cyan]Header[/]")
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Yellow);

        foreach (var (exportedClass, method) in methods)
        {
            _ = methodTable.AddRow(
                FormatToken(exportedClass.Token),
                FormatToken(method.Token),
                FormatOffset(method.MethodOffset),
                FormatMethodDescriptor(method),
                FormatMethodHeader(method)
            );
        }

        methodTable.Caption = new TableTitle(
            "[dim]Exported Static Method and Constructor Tokens[/]"
        );
        AnsiConsole.Write(methodTable);
    }

    private static void DisplayCapInternals(
        CapFileStructure capFile,
        PackageRegistry packageRegistry,
        bool detailed,
        bool verbose
    )
    {
        if (!detailed)
        {
            if (verbose)
            {
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine(
                    "[dim]Use --detailed with --verbose to show parsed CAP internals and raw parser diagnostics.[/]"
                );
            }

            return;
        }

        var constantPoolResult = ConstantPoolComponentAnalysis.Parse(capFile, packageRegistry);
        DisplayConstantPool(constantPoolResult, verbose);
        DisplayReferenceLocations(capFile, constantPoolResult, verbose);
        DisplayDescriptorComponent(capFile, verbose);
        DisplayStaticFieldComponent(capFile, verbose);
    }

    private static void DisplayConstantPool(
        Result<ConstantPoolComponentAnalysis, SmartCardError> analysisResult,
        bool verbose
    )
    {
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[bold blue]Constant Pool:[/]");
        if (analysisResult.IsFailure)
        {
            AnsiConsole.MarkupLine($"[yellow]{Markup.Escape(analysisResult.Error.Message)}[/]");
            return;
        }

        var analysis = analysisResult.Value;
        var table = new Table()
            .AddColumn("[cyan]Index[/]")
            .AddColumn("[cyan]Kind[/]")
            .AddColumn("[cyan]Target[/]")
            .AddColumn("[cyan]Package[/]")
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Blue);

        if (verbose)
        {
            _ = table.AddColumn("[cyan]Offset[/]").AddColumn("[cyan]Raw[/]");
        }

        foreach (var entry in analysis.Entries)
        {
            var row = new List<string>
            {
                FormatOffset(entry.Index),
                FormatConstantPoolKind(entry.Kind),
                FormatConstantPoolTarget(entry),
                FormatConstantPoolPackage(entry),
            };

            if (verbose)
            {
                row.Add(FormatOffset((ushort)entry.ComponentOffset));
                row.Add(Convert.ToHexString(entry.RawBytes));
            }

            _ = table.AddRow([.. row]);
        }

        table.Caption = new TableTitle(
            verbose
                ? $"[dim]{analysis.ComponentBodySize} byte body with raw entry bytes[/]"
                : $"[dim]{analysis.Entries.Count} entries[/]"
        );
        AnsiConsole.Write(table);
    }

    private static void DisplayReferenceLocations(
        CapFileStructure capFile,
        Result<ConstantPoolComponentAnalysis, SmartCardError> constantPoolResult,
        bool verbose
    )
    {
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[bold blue]Reference Locations:[/]");
        if (constantPoolResult.IsFailure)
        {
            AnsiConsole.MarkupLine(
                "[yellow]Reference locations require a parsed Constant Pool.[/]"
            );
            return;
        }

        var analysisResult = ReferenceLocationComponentAnalysis.Parse(
            capFile,
            constantPoolResult.Value
        );
        if (analysisResult.IsFailure)
        {
            AnsiConsole.MarkupLine($"[yellow]{Markup.Escape(analysisResult.Error.Message)}[/]");
            return;
        }

        var analysis = analysisResult.Value;
        var table = new Table()
            .AddColumn("[cyan]CP Index[/]")
            .AddColumn("[cyan]Kind[/]")
            .AddColumn("[cyan]Target[/]")
            .AddColumn("[cyan]Refs[/]")
            .AddColumn("[cyan]Widths[/]")
            .AddColumn("[cyan]Method Offsets[/]")
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Blue);

        foreach (var group in analysis.Groups)
        {
            string offsets = FormatMethodOffsets(group.MethodComponentOffsets, verbose);
            _ = table.AddRow(
                FormatOffset(group.ConstantPoolIndex),
                group.ConstantPoolEntry.Match(
                    entry => FormatConstantPoolKind(entry.Kind),
                    () => "[dim]unresolved[/]"
                ),
                group.ConstantPoolEntry.Match(FormatConstantPoolTarget, () => "[dim]unresolved[/]"),
                group.ReferenceCount.ToString(),
                $"{group.OneByteReferenceCount} byte, {group.TwoByteReferenceCount} byte2",
                offsets
            );
        }

        table.Caption = new TableTitle(
            $"[dim]{analysis.Sites.Count} sites; byte refs {analysis.ByteIndexCount}, byte2 refs {analysis.Byte2IndexCount}[/]"
        );
        AnsiConsole.Write(table);
    }

    private static void DisplayDescriptorComponent(CapFileStructure capFile, bool verbose)
    {
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[bold blue]Descriptor Component:[/]");
        var analysisResult = DescriptorComponentAnalysis.Parse(capFile);
        if (analysisResult.IsFailure)
        {
            AnsiConsole.MarkupLine($"[yellow]{Markup.Escape(analysisResult.Error.Message)}[/]");
            return;
        }

        var analysis = analysisResult.Value;
        var classTable = new Table()
            .AddColumn("[cyan]Token[/]")
            .AddColumn("[cyan]This Class[/]")
            .AddColumn("[cyan]Access[/]")
            .AddColumn("[cyan]Interfaces[/]")
            .AddColumn("[cyan]Fields[/]")
            .AddColumn("[cyan]Methods[/]")
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Blue);

        if (verbose)
        {
            _ = classTable.AddColumn("[cyan]Offset[/]");
        }

        foreach (var classInfo in analysis.Classes)
        {
            var row = new List<string>
            {
                FormatToken(classInfo.Token),
                FormatOffset(classInfo.ThisClassRef),
                FormatDescriptorClassAccess(classInfo.AccessFlags),
                classInfo.Interfaces.Count == 0
                    ? "[dim]none[/]"
                    : string.Join(", ", classInfo.Interfaces.Select(FormatOffset)),
                classInfo.Fields.Count.ToString(),
                classInfo.Methods.Count.ToString(),
            };

            if (verbose)
            {
                row.Add(FormatOffset((ushort)classInfo.ComponentOffset));
            }

            _ = classTable.AddRow([.. row]);
        }

        classTable.Caption = new TableTitle(
            $"[dim]{analysis.Classes.Count} classes/interfaces, {analysis.TypeDescriptors.Count} type entries[/]"
        );
        AnsiConsole.Write(classTable);

        if (verbose && analysis.TypeDescriptorTail.Length > 0)
        {
            AnsiConsole.MarkupLine(
                $"[dim]Descriptor type tail: {analysis.TypeDescriptorTail.Length} bytes[/]"
            );
        }

        DisplayDescriptorFields(analysis, verbose);
        DisplayDescriptorMethods(analysis, verbose);
    }

    private static void DisplayDescriptorFields(DescriptorComponentAnalysis analysis, bool verbose)
    {
        var fields = analysis
            .Classes.SelectMany(classInfo => classInfo.Fields.Select(field => (classInfo, field)))
            .ToList();
        if (fields.Count == 0)
        {
            return;
        }

        var table = new Table()
            .AddColumn("[cyan]Class[/]")
            .AddColumn("[cyan]Field[/]")
            .AddColumn("[cyan]Access[/]")
            .AddColumn("[cyan]Reference[/]")
            .AddColumn("[cyan]Type[/]")
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Blue);

        if (verbose)
        {
            _ = table.AddColumn("[cyan]Offset[/]");
        }

        foreach (var (classInfo, field) in fields)
        {
            var row = new List<string>
            {
                FormatToken(classInfo.Token),
                FormatToken(field.Token),
                FormatFieldAccessFlags(field.AccessFlags),
                FormatFieldReference(field.Reference),
                FormatDescriptorType(field.TypeReference, field.TypeRawValue),
            };

            if (verbose)
            {
                row.Add(FormatOffset((ushort)field.ComponentOffset));
            }

            _ = table.AddRow([.. row]);
        }

        table.Caption = new TableTitle("[dim]Descriptor Field Tokens[/]");
        AnsiConsole.Write(table);
    }

    private static void DisplayDescriptorMethods(DescriptorComponentAnalysis analysis, bool verbose)
    {
        var methods = analysis
            .Classes.SelectMany(classInfo =>
                classInfo.Methods.Select(method => (classInfo, method))
            )
            .ToList();
        if (methods.Count == 0)
        {
            return;
        }

        var table = new Table()
            .AddColumn("[cyan]Class[/]")
            .AddColumn("[cyan]Method[/]")
            .AddColumn("[cyan]Method Offset[/]")
            .AddColumn("[cyan]Access[/]")
            .AddColumn("[cyan]Descriptor[/]")
            .AddColumn("[cyan]Header[/]")
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Blue);

        if (verbose)
        {
            _ = table.AddColumn("[cyan]Desc Offset[/]");
        }

        foreach (var (classInfo, method) in methods)
        {
            var row = new List<string>
            {
                FormatToken(classInfo.Token),
                FormatToken(method.Token),
                FormatOffset(method.MethodOffset),
                FormatMethodAccessFlags(method.AccessFlags),
                FormatMethodDescriptor(method),
                FormatMethodHeader(method.MethodHeader),
            };

            if (verbose)
            {
                row.Add(FormatOffset((ushort)method.ComponentOffset));
            }

            _ = table.AddRow([.. row]);
        }

        table.Caption = new TableTitle("[dim]Descriptor Method Tokens[/]");
        AnsiConsole.Write(table);
    }

    private static string FormatConstantPoolKind(ConstantPoolEntryKind kind) =>
        kind switch
        {
            ConstantPoolEntryKind.Class => "class",
            ConstantPoolEntryKind.InstanceField => "instance field",
            ConstantPoolEntryKind.VirtualMethod => "virtual method",
            ConstantPoolEntryKind.SuperMethod => "super method",
            ConstantPoolEntryKind.StaticField => "static field",
            ConstantPoolEntryKind.StaticMethod => "static method",
            _ => kind.ToString(),
        };

    private static string FormatConstantPoolTarget(ConstantPoolEntryInfo entry)
    {
        var target = entry.Target;
        if (target.IsExternal)
        {
            string text =
                $"pkg {target.PackageToken.Match(FormatToken, () => "??")}, "
                + $"class {target.ClassToken.Match(FormatToken, () => "??")}";
            target.MemberToken.Execute(token => text += $", member {FormatOffset(token)}");
            return text;
        }

        string internalText = target.InternalOffset.Match(
            offset => $"internal {FormatOffset(offset)}",
            () => "internal ??"
        );
        target.MemberToken.Execute(token => internalText += $", member {FormatOffset(token)}");
        return internalText;
    }

    private static string FormatConstantPoolPackage(ConstantPoolEntryInfo entry)
    {
        if (!entry.Target.IsExternal)
        {
            return "[dim]internal[/]";
        }

        return entry.Target.ImportedPackage.Match(
            package =>
            {
                string name = package.ResolvedName.GetValueOrDefault("Unknown");
                return $"{package.AidHex} v{package.Version}\n[dim]{Markup.Escape(name)}[/]";
            },
            () => "[dim]unresolved import token[/]"
        );
    }

    private static string FormatMethodOffsets(IReadOnlyList<int> offsets, bool verbose)
    {
        var shown = verbose ? offsets : offsets.Take(8).ToList();
        string text = string.Join(", ", shown.Select(offset => $"0x{offset:X4}"));
        if (!verbose && offsets.Count > 8)
        {
            text += $"\n[dim]... +{offsets.Count - 8} more[/]";
        }

        return text;
    }

    private static string FormatFieldReference(DescriptorFieldReference reference)
    {
        if (reference.IsExternal)
        {
            return $"pkg {reference.PackageToken.Match(FormatToken, () => "??")}, "
                + $"class {reference.ClassToken.Match(FormatToken, () => "??")}, "
                + $"member {reference.MemberToken.Match(FormatToken, () => "??")}";
        }

        if (reference.IsStatic)
        {
            return reference.StaticFieldImageOffset.Match(
                offset => $"static image {FormatOffset(offset)}",
                () => "static image ??"
            );
        }

        return reference.InternalClassRef.Match(
            classRef =>
                $"class {FormatOffset(classRef)}, member {reference.MemberToken.Match(FormatToken, () => "??")}",
            () => "class ??"
        );
    }

    private static string FormatDescriptorType(DescriptorTypeReference type, ushort rawValue)
    {
        if (type.IsPrimitive)
        {
            return type.PrimitiveType.Match(
                primitive => $"{GetDescriptorPrimitiveName(primitive)} 0x{rawValue:X4}",
                () => $"primitive 0x{rawValue:X4}"
            );
        }

        return type.TypeDescriptorOffset.Match(
            offset => $"type descriptor {FormatOffset(offset)}",
            () => $"reference 0x{rawValue:X4}"
        );
    }

    private static string GetDescriptorPrimitiveName(byte primitive) =>
        primitive switch
        {
            0x02 => "boolean",
            0x03 => "byte",
            0x04 => "short",
            0x05 => "int",
            _ => $"primitive(0x{primitive:X2})",
        };

    private static void DisplayMemoryEstimate(byte[] capFileData)
    {
        try
        {
            var memoryReq = CapFileLoadingWorkflow.EstimateMemoryRequirements(capFileData);

            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold green]Memory Requirements (Estimated):[/]");

            var memoryTable = new Table()
                .AddColumn("[cyan]Memory Type[/]")
                .AddColumn("[cyan]Estimated Size[/]")
                .Border(TableBorder.Rounded)
                .BorderColor(Color.Green);

            memoryTable.Caption = new TableTitle("[dim]Estimated Load Footprint[/]");

            _ = memoryTable.AddRow(
                "[cyan]Code Memory[/]",
                $"[green]{memoryReq.CodeMemory} bytes[/]"
            );
            _ = memoryTable.AddRow(
                "[cyan]Data Memory[/]",
                $"[green]{memoryReq.DataMemory} bytes[/]"
            );
            _ = memoryTable.AddRow("[cyan]Total Size[/]", $"[green]{memoryReq.TotalSize} bytes[/]");

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
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold magenta]Manifest Information:[/]");

            var manifestTable = new Table()
                .AddColumn("[cyan]Property[/]")
                .AddColumn("[cyan]Value[/]")
                .Border(TableBorder.Rounded)
                .BorderColor(Color.Purple);

            manifestTable.Caption = new TableTitle("[dim]Package Manifest[/]");

            manifest.PackageName.Execute(value =>
                manifestTable.AddRow("[cyan]Package Name[/]", $"[green]{Markup.Escape(value)}[/]")
            );

            manifest.CapFileVersion.Execute(value =>
                manifestTable.AddRow(
                    "[cyan]CAP File Version[/]",
                    $"[yellow]{Markup.Escape(value)}[/]"
                )
            );

            manifest.ConverterVersion.Execute(value =>
                manifestTable.AddRow(
                    "[cyan]Converter Version[/]",
                    $"[yellow]{Markup.Escape(value)}[/]"
                )
            );

            manifest.ConverterProvider.Execute(value =>
                manifestTable.AddRow(
                    "[cyan]Converter Provider[/]",
                    $"[green]{Markup.Escape(value)}[/]"
                )
            );

            manifest.CreationTime.Execute(value =>
                manifestTable.AddRow("[cyan]Creation Time[/]", $"[dim]{Markup.Escape(value)}[/]")
            );

            manifest.IntegerSupportRequired.Execute(value =>
                manifestTable.AddRow(
                    "[cyan]Integer Support Required[/]",
                    value ? "[green]Yes[/]" : "[red]No[/]"
                )
            );

            AnsiConsole.Write(manifestTable);

            if (manifest.ImportedPackages.Count > 0)
            {
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine("[bold blue]Import Dependencies:[/]");

                var importsTable = new Table()
                    .AddColumn("[cyan]Package AID[/]")
                    .AddColumn("[cyan]Required Version[/]")
                    .AddColumn("[cyan]Resolved Package[/]")
                    .AddColumn("[cyan]SDK Version[/]")
                    .Border(TableBorder.Rounded)
                    .BorderColor(Color.Blue);

                importsTable.Caption = new TableTitle("[dim]Import Resolution[/]");

                foreach (var import in manifest.ImportedPackages)
                {
                    string formattedAid = FormatAidAsHex(import.Aid);

                    // Try to resolve the package
                    string resolvedName = "[dim]Unknown[/]";
                    string sdkVersion = "[dim]N/A[/]";

                    if (packageRegistry.TryResolveAid(formattedAid, out var packageInfo))
                    {
                        resolvedName = $"[green]{packageInfo?.DisplayName ?? "Unknown"}[/]";
                        sdkVersion = $"[yellow]{packageInfo?.SdkVersion ?? "Unknown"}[/]";
                    }
                    else
                    {
                        resolvedName = FormatUnknownAidHint(formattedAid);
                    }

                    _ = importsTable.AddRow(
                        $"[cyan]{formattedAid}[/]",
                        $"[yellow]{Markup.Escape(import.Version)}[/]",
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

    private static void DisplayArchiveMetadata(byte[] capFileData)
    {
        try
        {
            using var stream = new MemoryStream(capFileData);
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read);

            var manifestMetadata = ReadManifestMetadata(archive);
            var javaCardXmlMetadata = ReadJavaCardXmlMetadata(archive);

            if (manifestMetadata.Count == 0 && javaCardXmlMetadata.Count == 0)
            {
                return;
            }

            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold magenta]Archive Metadata:[/]");

            var table = new Table()
                .AddColumn("[cyan]Source[/]")
                .AddColumn("[cyan]Property[/]")
                .AddColumn("[cyan]Value[/]")
                .Border(TableBorder.Rounded)
                .BorderColor(Color.Purple);

            table.Caption = new TableTitle("[dim]Non-CAP Archive Files[/]");

            foreach (var metadata in manifestMetadata)
            {
                _ = table.AddRow(
                    "[cyan]MANIFEST.MF[/]",
                    $"[cyan]{Markup.Escape(metadata.Key)}[/]",
                    Markup.Escape(metadata.Value)
                );
            }

            foreach (var metadata in javaCardXmlMetadata)
            {
                _ = table.AddRow(
                    "[cyan]javacard.xml[/]",
                    $"[cyan]{Markup.Escape(metadata.Key)}[/]",
                    Markup.Escape(metadata.Value)
                );
            }

            AnsiConsole.Write(table);
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine(
                $"[yellow]Could not display archive metadata: {Markup.Escape(ex.Message)}[/]"
            );
        }
    }

    private static IReadOnlyDictionary<string, string> ReadManifestMetadata(ZipArchive archive)
    {
        var manifestEntry = archive.GetEntry("META-INF/MANIFEST.MF");
        if (manifestEntry == null)
        {
            return new Dictionary<string, string>();
        }

        using var manifestStream = manifestEntry.Open();
        using var reader = new StreamReader(manifestStream);
        var properties = ParseManifestProperties(reader.ReadToEnd());

        string[] usefulKeys =
        [
            "Created-By",
            "Runtime-Descriptor-Version",
            "Application-Type",
            "Classic-Package-AID",
            "Sealed",
            "Name",
        ];

        return usefulKeys
            .Where(properties.ContainsKey)
            .ToDictionary(key => key, key => properties[key]);
    }

    private static IReadOnlyDictionary<string, string> ReadJavaCardXmlMetadata(ZipArchive archive)
    {
        var xmlEntry = archive.GetEntry("META-INF/javacard.xml");
        if (xmlEntry == null)
        {
            return new Dictionary<string, string>();
        }

        using var xmlStream = xmlEntry.Open();
        var document = XDocument.Load(xmlStream);
        var root = document.Root;
        if (root == null)
        {
            return new Dictionary<string, string>();
        }

        var metadata = new Dictionary<string, string>
        {
            ["Root Element"] = root.Name.LocalName,
            ["Root Namespace"] = root.Name.NamespaceName,
        };

        foreach (var attribute in root.Attributes())
        {
            if (attribute.IsNamespaceDeclaration)
            {
                continue;
            }

            string key =
                attribute.Name.LocalName == "schemaLocation"
                    ? "Schema Location"
                    : attribute.Name.LocalName;
            metadata[key] = attribute.Value;
        }

        if (!root.Elements().Any())
        {
            metadata["Content"] = "No applet or extension declarations";
        }

        return metadata;
    }

    private static Dictionary<string, string> ParseManifestProperties(string manifestContent)
    {
        string[] lines = manifestContent.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var properties = new Dictionary<string, string>();
        string? currentKey = null;
        string? currentValue = null;

        foreach (string line in lines)
        {
            string trimmedEnd = line.TrimEnd('\r', '\n');
            if (string.IsNullOrWhiteSpace(trimmedEnd))
            {
                continue;
            }

            if (trimmedEnd.StartsWith(' ') && currentKey != null)
            {
                currentValue = string.Concat(currentValue ?? string.Empty, trimmedEnd.Trim());
                continue;
            }

            if (currentKey != null && currentValue != null)
            {
                properties[currentKey] = currentValue;
            }

            int colonIndex = trimmedEnd.IndexOf(':');
            if (colonIndex <= 0)
            {
                currentKey = null;
                currentValue = null;
                continue;
            }

            currentKey = trimmedEnd.Substring(0, colonIndex).Trim();
            currentValue = trimmedEnd.Substring(colonIndex + 1).Trim();
        }

        if (currentKey != null && currentValue != null)
        {
            properties[currentKey] = currentValue;
        }

        return properties;
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

    private static string FormatUnknownAidHint(string aidHex)
    {
        List<string> hints = [];
        if (aidHex.Length >= 10)
        {
            string rid = aidHex[..10];
            hints.Add(
                KnownAidRidNames.TryGetValue(rid, out string? name)
                    ? $"RID {rid} ({name})"
                    : $"RID {rid}"
            );
        }

        if (aidHex.Length > 10)
        {
            string suffix = aidHex[10..];
            var ascii = TryDecodePrintableAsciiHex(suffix);
            if (!string.IsNullOrWhiteSpace(ascii))
            {
                hints.Add($"suffix \"{Markup.Escape(ascii)}\"");
            }
            else
            {
                hints.Add($"PIX {suffix}");
            }
        }

        return hints.Count > 0
            ? $"[dim]Unknown[/]\n[dim]{string.Join(", ", hints)}[/]"
            : "[dim]Unknown[/]";
    }

    private static string TryDecodePrintableAsciiHex(string hex)
    {
        if (hex.Length % 2 != 0)
        {
            return string.Empty;
        }

        var chars = new List<char>();
        for (int i = 0; i < hex.Length; i += 2)
        {
            if (
                !byte.TryParse(
                    hex.Substring(i, 2),
                    System.Globalization.NumberStyles.HexNumber,
                    null,
                    out byte value
                )
            )
            {
                return string.Empty;
            }

            if (value is < 0x20 or > 0x7E)
            {
                return string.Empty;
            }

            chars.Add((char)value);
        }

        return new string([.. chars]);
    }

    private static readonly IReadOnlyDictionary<string, string> KnownAidRidNames = new Dictionary<
        string,
        string
    >
    {
        ["D276000085"] = "NXP Semiconductors / NFC Forum",
    };

    private static void DisplayClassFileInfo(byte[] capFileData)
    {
        try
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold cyan]Class File Analysis:[/]");

            // Check if this is a ZIP/JAR file
            using var stream = new MemoryStream(capFileData);
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read);

            List<string> classFiles = [];
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
                    string extension = Path.GetExtension(entry.FullName).ToLowerInvariant();
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
                HashSet<string> packages = [];
                List<string> classNames = [];

                foreach (string classFile in classFiles)
                {
                    string className = Path.GetFileNameWithoutExtension(classFile);
                    classNames.Add(className);

                    // Extract package path
                    int lastSlash = classFile.LastIndexOf('/');
                    if (lastSlash > 0)
                    {
                        string packagePath = classFile.Substring(0, lastSlash);
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
                    foreach (string pkg in packages.OrderBy(p => p))
                    {
                        AnsiConsole.WriteLine($"  • {pkg}");
                    }
                    AnsiConsole.WriteLine();
                }

                // Display class names (limit to first 20)
                AnsiConsole.WriteLine("Classes found:");
                List<string> sortedClasses = [.. classNames.OrderBy(c => c)];
                foreach (string className in sortedClasses.Take(20))
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
                AnsiConsole.MarkupLine("[dim]No Java class files found (standard CAP format)[/]");
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
            AnsiConsole.MarkupLine("[dim]Standard binary CAP format (no embedded files)[/]");
        }
    }

    private static string FormatStaticFieldSummary(StaticFieldComponentAnalysis analysis) =>
        $"{analysis.ComponentBodySize} bytes; image {analysis.ImageSize} bytes, "
        + $"refs {analysis.ReferenceCount}, arrays {analysis.ArrayInitCount}, "
        + $"defaults {analysis.DefaultValueCount}, non-defaults {analysis.NonDefaultValueCount}";

    private static void DisplayStaticFieldComponent(CapFileStructure capFile, bool verbose)
    {
        try
        {
            var staticFieldComponent = capFile.Components.FirstOrDefault(c =>
                c.Tag == Constants.Constants.JavaCard.ComponentTags.STATIC_FIELD
            );
            if (staticFieldComponent == null)
            {
                AnsiConsole.MarkupLine("[yellow]No static field component found[/]");
                return;
            }

            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold]Static Field Component:[/]");

            byte[] data = staticFieldComponent.Data;
            var analysisResult = StaticFieldComponentAnalysis.Parse(data);
            if (analysisResult.IsFailure)
            {
                AnsiConsole.MarkupLine($"[yellow]{Markup.Escape(analysisResult.Error.Message)}[/]");
                return;
            }

            var analysis = analysisResult.Value;
            var table = new Table()
                .AddColumn("[cyan]Field[/]")
                .AddColumn("[cyan]Value[/]")
                .Border(TableBorder.Rounded)
                .BorderColor(Color.Blue);

            _ = table.AddRow("[cyan]Component Body Size[/]", $"{analysis.ComponentBodySize} bytes");
            _ = table.AddRow("[cyan]Image Size[/]", $"{analysis.ImageSize} bytes");
            _ = table.AddRow("[cyan]Reference Count[/]", analysis.ReferenceCount.ToString());
            _ = table.AddRow("[cyan]Initialized Arrays[/]", analysis.ArrayInitCount.ToString());
            _ = table.AddRow("[cyan]Default Values[/]", analysis.DefaultValueCount.ToString());
            _ = table.AddRow(
                "[cyan]Non-Default Values[/]",
                analysis.NonDefaultValueCount.ToString()
            );

            if (verbose && analysis.TrailingByteCount > 0)
            {
                _ = table.AddRow("[cyan]Trailing Bytes[/]", analysis.TrailingByteCount.ToString());
            }

            AnsiConsole.Write(table);

            if (analysis.InitializedArrays.Count == 0 && analysis.NonDefaultValues.Length == 0)
            {
                AnsiConsole.MarkupLine(
                    "[dim]No initialized array data or non-default static values are present.[/]"
                );
                return;
            }

            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold]Initialized Static Arrays:[/]");

            for (int i = 0; i < analysis.InitializedArrays.Count; i++)
            {
                var array = analysis.InitializedArrays[i];
                DisplayArrayData(i, array.Type, array.Values);
            }

            if (analysis.NonDefaultValues.Length > 0)
            {
                AnsiConsole.MarkupLine("[bold]Non-Default Static Values:[/]");
                DisplayHexDump(analysis.NonDefaultValues);
            }
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine(
                $"[red]Error parsing static field component: {Markup.Escape(ex.Message)}[/]"
            );
        }
    }

    private static void DisplayArrayData(int index, byte type, byte[] data)
    {
        string typeName = GetArrayTypeName(type);
        AnsiConsole.WriteLine($"Array #{index}: {typeName}[{data.Length}]");

        DisplayHexDump(data);
        AnsiConsole.WriteLine();
    }

    private static void DisplayHexDump(byte[] data)
    {
        for (int i = 0; i < data.Length; i += 16)
        {
            byte[] lineBytes = [.. data.Skip(i).Take(16)];
            string hex = string.Join(" ", lineBytes.Select(b => $"{b:X2}"));
            string ascii = new string(
                [.. lineBytes.Select(b => b is >= 32 and < 127 ? (char)b : '.')]
            );
            AnsiConsole.WriteLine($"  {i:X4}:  {hex, -47} |{ascii}|");
        }
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
    public class Settings : CommandSettings
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
        /// Gets or sets a value indicating whether to show verbose information.
        /// </summary>
        [CommandOption("-v|--verbose")]
        [Description("Show verbose analysis including static field arrays")]
        public bool Verbose { get; set; }

        /// <summary>
        /// Gets or sets the output format for validation results.
        /// </summary>
        [CommandOption("-f|--format")]
        [Description("Output format: table (default) or json")]
        public OutputFormat Format { get; set; } = OutputFormat.Table;

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
