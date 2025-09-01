using CSharpFunctionalExtensions;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Represents detected card type information.
/// </summary>
[PublicAPI]
public class CardTypeInfo
{
    /// <summary>
    /// Gets the card manufacturer.
    /// </summary>
    public string Manufacturer { get; }

    /// <summary>
    /// Gets the card family or series.
    /// </summary>
    public string Family { get; }

    /// <summary>
    /// Gets the specific card model if detected.
    /// </summary>
    public string Model { get; }

    /// <summary>
    /// Gets whether this is a production card.
    /// </summary>
    public bool IsProduction { get; }

    /// <summary>
    /// Gets the maximum authentication attempts before lockout if known.
    /// </summary>
    public Maybe<int> MaxAuthenticationAttempts { get; }

    /// <summary>
    /// Gets supported secure channel protocols.
    /// </summary>
    public string[] SupportedProtocols { get; }

    /// <summary>
    /// Gets known limitations or risks for this card type.
    /// </summary>
    public string[] KnownLimitations { get; }

    /// <summary>
    /// Initializes a new instance of CardTypeInfo.
    /// </summary>
    public CardTypeInfo(
        string manufacturer,
        string family,
        string model,
        bool isProduction,
        Maybe<int> maxAuthenticationAttempts,
        string[] supportedProtocols,
        string[] knownLimitations
    )
    {
        Manufacturer = manufacturer;
        Family = family;
        Model = model;
        IsProduction = isProduction;
        MaxAuthenticationAttempts = maxAuthenticationAttempts;
        SupportedProtocols = supportedProtocols;
        KnownLimitations = knownLimitations;
    }

    /// <summary>
    /// Gets a descriptive name for this card type.
    /// </summary>
    public override string ToString()
    {
        return string.IsNullOrEmpty(Model) 
            ? $"{Manufacturer} {Family}"
            : $"{Manufacturer} {Family} {Model}";
    }
}
