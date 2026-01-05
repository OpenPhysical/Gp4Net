using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Domain.CapFile;

namespace Gp4Net.Tool.Commands.Applet;

/// <summary>
/// Enhanced validation result from CAP file validation with severity-based messaging.
/// Immutable record following functional programming principles.
/// Named CapValidationResult to avoid conflict with Spectre.Console.ValidationResult.
/// </summary>
public sealed record CapValidationResult
{
    /// <summary>
    /// Gets the path to the validated CAP file.
    /// </summary>
    public string CapFilePath { get; init; }

    /// <summary>
    /// Gets the package AID from CAP file.
    /// </summary>
    public byte[] PackageAid { get; init; }

    /// <summary>
    /// Gets the package version.
    /// </summary>
    public CapVersion PackageVersion { get; init; }

    /// <summary>
    /// Gets the list of applets in the package.
    /// </summary>
    public IReadOnlyList<AppletInfo> Applets { get; init; }

    /// <summary>
    /// Gets the component summaries.
    /// </summary>
    public IReadOnlyList<ComponentSummary> Components { get; init; }

    /// <summary>
    /// Gets the manifest information if available.
    /// </summary>
    public Maybe<ManifestInfo> Manifest { get; init; }

    /// <summary>
    /// Gets the blocking validation errors.
    /// </summary>
    public IReadOnlyList<ValidationMessage> Errors { get; init; }

    /// <summary>
    /// Gets the non-blocking warnings.
    /// </summary>
    public IReadOnlyList<ValidationMessage> Warnings { get; init; }

    /// <summary>
    /// Gets the informational messages.
    /// </summary>
    public IReadOnlyList<ValidationMessage> Infos { get; init; }

    /// <summary>
    /// Gets the total CAP file size in bytes.
    /// </summary>
    public int TotalSize { get; init; }

    /// <summary>
    /// Gets whether the validation passed (no errors).
    /// </summary>
    public bool IsValid => Errors.Count == 0;

    private CapValidationResult(
        string capFilePath,
        byte[] packageAid,
        CapVersion packageVersion,
        IReadOnlyList<AppletInfo> applets,
        IReadOnlyList<ComponentSummary> components,
        Maybe<ManifestInfo> manifest,
        IReadOnlyList<ValidationMessage> errors,
        IReadOnlyList<ValidationMessage> warnings,
        IReadOnlyList<ValidationMessage> infos,
        int totalSize
    )
    {
        CapFilePath = capFilePath;
        PackageAid = packageAid;
        PackageVersion = packageVersion;
        Applets = applets;
        Components = components;
        Manifest = manifest;
        Errors = errors;
        Warnings = warnings;
        Infos = infos;
        TotalSize = totalSize;
    }

    /// <summary>
    /// Creates a new validation result from CAP file structure.
    /// </summary>
    public static CapValidationResult FromCapFile(
        string capFilePath,
        CapFileStructure capFile,
        IEnumerable<ComponentSummary> components,
        IEnumerable<ValidationMessage> errors,
        IEnumerable<ValidationMessage> warnings,
        IEnumerable<ValidationMessage> infos
    )
    {
        return new CapValidationResult(
            capFilePath,
            capFile.PackageAid,
            capFile.PackageVersion,
            capFile.Applets,
            components.ToList(),
            capFile.Manifest,
            errors.ToList(),
            warnings.ToList(),
            infos.ToList(),
            capFile.TotalSize
        );
    }

    /// <summary>
    /// Creates a validation result with explicit values.
    /// </summary>
    public static CapValidationResult Create(
        string capFilePath,
        byte[] packageAid,
        CapVersion packageVersion,
        IEnumerable<AppletInfo> applets,
        IEnumerable<ComponentSummary> components,
        Maybe<ManifestInfo> manifest,
        IEnumerable<ValidationMessage> errors,
        IEnumerable<ValidationMessage> warnings,
        IEnumerable<ValidationMessage> infos,
        int totalSize
    )
    {
        return new CapValidationResult(
            capFilePath,
            packageAid,
            packageVersion,
            applets.ToList(),
            components.ToList(),
            manifest,
            errors.ToList(),
            warnings.ToList(),
            infos.ToList(),
            totalSize
        );
    }
}
