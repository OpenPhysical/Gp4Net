using System;
using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using static Gp4Net.Constants.Constants.GlobalPlatform;

namespace Gp4Net.Domain;

/// <summary>
/// Immutable record representing information about an application on a smart card.
/// </summary>
public record ApplicationInfo(
    byte[] Aid,
    byte RawLifecycleState,
    ImmutableList<Privilege> Privileges,
    ApplicationType Type,
    Maybe<string> Version = default,
    Maybe<byte[]> AssociatedSecurityDomain = default,
    Maybe<byte[]> ExecutableLoadFileAid = default
)
{
    /// <summary>
    /// Gets the application AID as a hexadecimal string.
    /// </summary>
    public string AidHex
    {
        get { return Convert.ToHexString(Aid); }
    }

    /// <summary>
    /// Gets the lifecycle state as a string.
    /// </summary>
    public string LifecycleStateString
    {
        get
        {
            return Type switch
            {
                ApplicationType.IssuerSecurityDomain
                    => GlobalPlatformLifecycle.DescribeCardState(RawLifecycleState),
                ApplicationType.SupplementarySecurityDomain
                    => GlobalPlatformLifecycle.DescribeSecurityDomainState(RawLifecycleState),
                _ => GlobalPlatformLifecycle.DescribeApplicationState(RawLifecycleState),
            };
        }
    }

    /// <summary>
    /// Gets the application type as a string.
    /// </summary>
    public string TypeString
    {
        get { return Type.ToString(); }
    }

    /// <summary>
    /// Checks if the application has a specific privilege.
    /// </summary>
    public bool HasPrivilege(Privilege privilege)
    {
        return Privileges.Contains(privilege);
    }

    /// <summary>
    /// Checks if the application is selectable.
    /// </summary>
    public bool IsSelectable
    {
        get
        {
            return Type switch
            {
                ApplicationType.IssuerSecurityDomain
                    => RawLifecycleState
                        is (byte)CardLifecycleState.Initialized
                            or (byte)CardLifecycleState.Secured,
                ApplicationType.SupplementarySecurityDomain
                    => RawLifecycleState
                        is (byte)SecurityDomainLifecycleState.Selectable
                            or (byte)SecurityDomainLifecycleState.Personalized,
                _ => (RawLifecycleState & 0x87) == 0x07,
            };
        }
    }

    /// <summary>
    /// Checks if the application is an Issuer Security Domain.
    /// </summary>
    public bool IsIssuerSecurityDomain
    {
        get { return Type == ApplicationType.IssuerSecurityDomain; }
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
    ExecutableLoadFile = 0x02,
}
