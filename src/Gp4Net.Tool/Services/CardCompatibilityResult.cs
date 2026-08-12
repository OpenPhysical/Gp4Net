using JetBrains.Annotations;

namespace Gp4Net.Tool.Services;

/// <summary>
/// The safety assessment for an operation against a detected card type.
/// </summary>
[PublicAPI]
public sealed record CardCompatibilityResult(
    bool IsCompatible,
    bool IsSafe,
    CardTypeInfo CardType,
    string Message,
    string[] Warnings,
    string[] Recommendations
);
