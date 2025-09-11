using System.IO;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.CardEmulator.Profiles;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Core;

/// <summary>
/// P71D321 SmartMX3 virtual card implementation.
/// Supports loading from JSON profiles for accurate hardware emulation.
/// </summary>
[PublicAPI]
public class P71VirtualCard
{
    /// <summary>
    /// Gets the card profile name.
    /// </summary>
    public string ProfileName { get; }

    /// <summary>
    /// Initializes a new P71 virtual card with the specified configuration.
    /// </summary>
    private P71VirtualCard(string profileName, VirtualCard baseCard)
    {
        ProfileName = profileName;
        _baseCard = baseCard;
    }

    private readonly VirtualCard _baseCard;

    /// <summary>
    /// Creates a P71 virtual card from a JSON profile file.
    /// </summary>
    /// <param name="jsonPath">Path to the JSON profile file.</param>
    /// <param name="rngContext">Random number generator context for card operations.</param>
    /// <param name="loggingService">Logging service for debugging.</param>
    /// <returns>Result containing the virtual card or error.</returns>
    public static Result<P71VirtualCard, SmartCardError> FromJsonProfile(
        string jsonPath,
        IRngContext rngContext,
        LoggingService loggingService
    )
    {
        return CardProfileLoader
            .LoadFromFile(jsonPath)
            .Bind(config =>
            {
                string profileName = Path.GetFileNameWithoutExtension(jsonPath);
                return CardState
                    .Create()
                    .Bind(_ => VirtualCard.Create(config, rngContext))
                    .Map(baseCard => new P71VirtualCard(profileName, baseCard));
            });
    }

    /// <summary>
    /// Creates a P71 virtual card from JSON content.
    /// </summary>
    /// <param name="json">JSON content.</param>
    /// <param name="profileName">Name for this profile.</param>
    /// <param name="rngContext">Random number generator context for card operations.</param>
    /// <param name="loggingService">Logging service for debugging.</param>
    /// <returns>Result containing the virtual card or error.</returns>
    public static Result<P71VirtualCard, SmartCardError> FromJson(
        string json,
        string profileName,
        IRngContext rngContext,
        LoggingService loggingService
    )
    {
        return CardProfileLoader
            .LoadFromJson(json)
            .Bind(config =>
            {
                return CardState
                    .Create()
                    .Bind(_ => VirtualCard.Create(config, rngContext))
                    .Map(baseCard => new P71VirtualCard(profileName, baseCard));
            });
    }

    /// <summary>
    /// Creates a P71 virtual card using the default SCP02 test profile.
    /// </summary>
    /// <param name="rngContext">Random number generator context for card operations.</param>
    /// <param name="loggingService">Logging service for debugging.</param>
    /// <returns>Result containing P71 virtual card with SCP02 support.</returns>
    public static Result<P71VirtualCard, SmartCardError> CreateScp02Card(
        IRngContext rngContext,
        LoggingService loggingService
    )
    {
        return CardConfiguration
            .P71()
            .Bind(config => CardState
                .Create()
                .Bind(_ => VirtualCard.Create(config, rngContext)))
            .Map(baseCard => new P71VirtualCard("P71_SCP02_Default", baseCard));
    }

    /// <summary>
    /// Creates a P71 virtual card using the default SCP03 test profile.
    /// </summary>
    /// <param name="rngContext">Random number generator context for card operations.</param>
    /// <param name="loggingService">Logging service for debugging.</param>
    /// <returns>Result containing P71 virtual card with SCP03 support.</returns>
    public static Result<P71VirtualCard, SmartCardError> CreateScp03Card(
        IRngContext rngContext,
        LoggingService loggingService
    )
    {
        // Use dual protocol config but default to SCP03
        return CardConfiguration
            .DualProtocol()
            .Map(config => config.WithScpDefaults(0x03, ScpImplementation.Scp03I70))
            .Bind(config => CardState
                .Create()
                .Bind(_ => VirtualCard.Create(config, rngContext)))
            .Map(baseCard => new P71VirtualCard("P71_SCP03_Default", baseCard));
    }
}
