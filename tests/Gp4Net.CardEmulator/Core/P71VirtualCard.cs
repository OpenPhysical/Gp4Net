using System;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.CardEmulator.Profiles;
using Gp4Net.Core;
using Gp4Net.Domain.Security;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Gp4Net.CardEmulator.Core;

/// <summary>
/// P71D321 SmartMX3 virtual card implementation.
/// Supports loading from JSON profiles for accurate hardware emulation.
/// </summary>
[PublicAPI]
public class P71VirtualCard : VirtualCard
{
    /// <summary>
    /// Gets the card profile name.
    /// </summary>
    public string ProfileName { get; }
    
    /// <summary>
    /// Initializes a new P71 virtual card with the specified configuration.
    /// </summary>
    private P71VirtualCard(
        string profileName,
        CardConfiguration config, 
        ICryptographicService cryptoService, 
        ILogger<P71VirtualCard>? logger = null)
        : base(config, cryptoService, logger ?? NullLogger<P71VirtualCard>.Instance)
    {
        ProfileName = profileName;
    }
    
    /// <summary>
    /// Creates a P71 virtual card from a JSON profile file.
    /// </summary>
    /// <param name="jsonPath">Path to the JSON profile file.</param>
    /// <param name="cryptoService">Optional cryptographic service. If not provided, a default will be created.</param>
    /// <param name="logger">Optional logger for debugging.</param>
    /// <returns>Result containing the virtual card or error.</returns>
    public static Result<P71VirtualCard, SmartCardError> FromJsonProfile(
        string jsonPath,
        ICryptographicService? cryptoService = null,
        ILogger<P71VirtualCard>? logger = null)
    {
        return CardProfileLoader.LoadFromFile(jsonPath)
            .Map(config =>
            {
                var crypto = cryptoService ?? new CryptographicService();
                var profileName = System.IO.Path.GetFileNameWithoutExtension(jsonPath);
                return new P71VirtualCard(profileName, config, crypto, logger);
            });
    }
    
    /// <summary>
    /// Creates a P71 virtual card from JSON content.
    /// </summary>
    /// <param name="json">JSON content.</param>
    /// <param name="profileName">Name for this profile.</param>
    /// <param name="cryptoService">Optional cryptographic service. If not provided, a default will be created.</param>
    /// <param name="logger">Optional logger for debugging.</param>
    /// <returns>Result containing the virtual card or error.</returns>
    public static Result<P71VirtualCard, SmartCardError> FromJson(
        string json,
        string profileName,
        ICryptographicService? cryptoService = null,
        ILogger<P71VirtualCard>? logger = null)
    {
        return CardProfileLoader.LoadFromJson(json)
            .Map(config =>
            {
                var crypto = cryptoService ?? new CryptographicService();
                return new P71VirtualCard(profileName, config, crypto, logger);
            });
    }
    
    /// <summary>
    /// Creates a P71 virtual card using the default SCP02 test profile.
    /// </summary>
    /// <param name="cryptoService">Optional cryptographic service.</param>
    /// <param name="logger">Optional logger for debugging.</param>
    /// <returns>P71 virtual card with SCP02 support.</returns>
    public static P71VirtualCard CreateScp02Card(
        ICryptographicService? cryptoService = null,
        ILogger<P71VirtualCard>? logger = null)
    {
        var config = CardConfiguration.P71();
        var crypto = cryptoService ?? new CryptographicService();
        return new P71VirtualCard("P71_SCP02_Default", config, crypto, logger);
    }
    
    /// <summary>
    /// Creates a P71 virtual card using the default SCP03 test profile.
    /// </summary>
    /// <param name="cryptoService">Optional cryptographic service.</param>
    /// <param name="logger">Optional logger for debugging.</param>
    /// <returns>P71 virtual card with SCP03 support.</returns>
    public static P71VirtualCard CreateScp03Card(
        ICryptographicService? cryptoService = null,
        ILogger<P71VirtualCard>? logger = null)
    {
        // Use dual protocol config but default to SCP03
        var config = CardConfiguration.DualProtocol()
            .WithScpDefaults(0x03, Gp4Net.Domain.Protocol.ScpImplementation.Scp03I70);
        var crypto = cryptoService ?? new CryptographicService();
        return new P71VirtualCard("P71_SCP03_Default", config, crypto, logger);
    }
}