using System;
using System.Collections.Immutable;
using CSharpFunctionalExtensions;

namespace Gp4Net.Domain;

/// <summary>
/// Represents an Executable Load File on a GlobalPlatform card.
/// Per GP Card Specification v2.3.1 Section 11.4.3.1 Table 11-37.
/// </summary>
public record ExecutableLoadFile(
    byte[] Aid,
    LifecycleState LifecycleState,
    Maybe<string> Version,
    ImmutableList<ExecutableModule> ExecutableModules,
    Maybe<byte[]> AssociatedSecurityDomainAid = default)
{
    /// <summary>
    /// Gets the AID as a hexadecimal string.
    /// </summary>
    public string AidHex => Convert.ToHexString(Aid);

    /// <summary>
    /// Gets the lifecycle state as a string.
    /// </summary>
    public string LifecycleStateString => LifecycleState.ToString();

    /// <summary>
    /// Gets the version string or "Unknown" if not available.
    /// </summary>
    public string VersionString => Version.GetValueOrDefault("Unknown");

    /// <summary>
    /// Gets the number of executable modules in this load file.
    /// </summary>
    public int ModuleCount => ExecutableModules.Count;

    /// <summary>
    /// Checks if this load file has any executable modules.
    /// </summary>
    public bool HasModules => ExecutableModules.Count > 0;

    /// <summary>
    /// Gets the associated security domain AID as hex string if available.
    /// </summary>
    public string AssociatedSecurityDomainAidHex => 
        AssociatedSecurityDomainAid.Map(Convert.ToHexString).GetValueOrDefault("None");
}

/// <summary>
/// Represents an Executable Module within an Executable Load File.
/// Per GP Card Specification v2.3.1 Section 11.4.3.1 Table 11-37.
/// </summary>
public record ExecutableModule(
    byte[] Aid,
    Maybe<string> Name = default,
    Maybe<string> Version = default)
{
    /// <summary>
    /// Gets the AID as a hexadecimal string.
    /// </summary>
    public string AidHex => Convert.ToHexString(Aid);

    /// <summary>
    /// Gets the module name or AID hex if name is not available.
    /// </summary>
    public string DisplayName => Name.GetValueOrDefault(AidHex);

    /// <summary>
    /// Gets the version string or "Unknown" if not available.
    /// </summary>
    public string VersionString => Version.GetValueOrDefault("Unknown");
}

/// <summary>
/// Lifecycle states for Executable Load Files per GlobalPlatform specification.
/// </summary>
public enum ExecutableLoadFileState : byte
{
    /// <summary>
    /// Load file is loaded but not available for execution.
    /// </summary>
    Loaded = 0x01,

    /// <summary>
    /// Load file is available for execution and instantiation.
    /// </summary>
    Available = 0x03,

    /// <summary>
    /// Load file is logically deleted.
    /// </summary>
    LogicallyDeleted = 0x80
}