using System;
using System.Collections.Immutable;
using CSharpFunctionalExtensions;

namespace Gp4Net.Domain;

/// <summary>
/// Immutable record representing information about an application on a smart card.
/// </summary>
public record ApplicationInfo(
    byte[] Aid,
    LifecycleState LifecycleState,
    ImmutableList<Privilege> Privileges,
    ApplicationType Type,
    Maybe<string> Version = default,
    Maybe<byte[]> AssociatedSecurityDomain = default)
{
    /// <summary>
    /// Gets the application AID as a hexadecimal string.
    /// </summary>
    public string AidHex
    {
        get
        {
            return Convert.ToHexString(Aid);
        }
    }

    /// <summary>
    /// Gets the lifecycle state as a string.
    /// </summary>
    public string LifecycleStateString
    {
        get
        {
            return LifecycleState.ToString();
        }
    }

    /// <summary>
    /// Gets the application type as a string.
    /// </summary>
    public string TypeString
    {
        get
        {
            return Type.ToString();
        }
    }

    /// <summary>
    /// Checks if the application has a specific privilege.
    /// </summary>
    public bool HasPrivilege(Privilege privilege) => Privileges.Contains(privilege);

    /// <summary>
    /// Checks if the application is selectable.
    /// </summary>
    public bool IsSelectable
    {
        get
        {
            return LifecycleState == LifecycleState.Selectable;
        }
    }

    /// <summary>
    /// Checks if the application is an Issuer Security Domain.
    /// </summary>
    public bool IsIssuerSecurityDomain
    {
        get
        {
            return Type == ApplicationType.IssuerSecurityDomain;
        }
    }
}

/// <summary>
/// Application types in the GlobalPlatform specification.
/// </summary>
public enum ApplicationType : byte
{
    /// <summary>
    /// Issuer Security Domain.
    /// </summary>
    IssuerSecurityDomain = 0x80,

    /// <summary>
    /// Supplementary Security Domain.
    /// </summary>
    SupplementarySecurityDomain = 0x40,

    /// <summary>
    /// Application (Applet).
    /// </summary>
    Application = 0x00,

    /// <summary>
    /// Load file (package).
    /// </summary>
    LoadFile = 0x01,
        
    /// <summary>
    /// Executable load file.
    /// </summary>
    ExecutableLoadFile = 0x02
}