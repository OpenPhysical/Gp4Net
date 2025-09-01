using JetBrains.Annotations;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Represents the type of operation being checked for compatibility.
/// </summary>
[PublicAPI]
public enum CardOperation
{
    /// <summary>
    /// Authentication operation (secure channel establishment).
    /// </summary>
    Authentication,

    /// <summary>
    /// Key installation or replacement.
    /// </summary>
    KeyInstallation,

    /// <summary>
    /// Application installation.
    /// </summary>
    ApplicationInstallation,

    /// <summary>
    /// Application deletion.
    /// </summary>
    ApplicationDeletion,

    /// <summary>
    /// Card personalization.
    /// </summary>
    Personalization,

    /// <summary>
    /// Read-only operations (safe).
    /// </summary>
    ReadOnly,
}
