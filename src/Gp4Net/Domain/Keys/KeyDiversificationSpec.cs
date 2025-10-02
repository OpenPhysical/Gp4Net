using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Keys;

/// <summary>
/// Represents a key diversification scheme identifier.
/// Stores the normalized scheme name so host and card pipelines can apply the same
/// diversification templates consistently.
/// </summary>
[PublicAPI]
public sealed record KeyDiversificationSpec
{
    private KeyDiversificationSpec(string scheme)
    {
        Scheme = scheme;
    }

    /// <summary>
    /// Gets the normalized (lowercase) diversification scheme name.
    /// </summary>
    public string Scheme { get; }

    /// <summary>
    /// Attempts to create a diversification spec from a raw scheme string.
    /// </summary>
    /// <param name="scheme">The user-provided diversification scheme identifier.</param>
    /// <returns>A result containing the normalized spec or an error.</returns>
    public static Result<KeyDiversificationSpec, SmartCardError> Create(string scheme)
    {
        if (string.IsNullOrWhiteSpace(scheme))
        {
            return Result.Failure<KeyDiversificationSpec, SmartCardError>(
                SmartCardError.InvalidArgument("Diversification scheme cannot be empty")
            );
        }

        var normalized = scheme.Trim().ToLowerInvariant();
        return Result.Success<KeyDiversificationSpec, SmartCardError>(
            new KeyDiversificationSpec(normalized)
        );
    }

    /// <summary>
    /// Convenience helper for Maybe conversions.
    /// </summary>
    public static Maybe<KeyDiversificationSpec> From(string scheme) =>
        string.IsNullOrWhiteSpace(scheme)
            ? Maybe<KeyDiversificationSpec>.None
            : Create(scheme)
                .Match(
                    spec => Maybe<KeyDiversificationSpec>.From(spec),
                    _ => Maybe<KeyDiversificationSpec>.None
                );
}
