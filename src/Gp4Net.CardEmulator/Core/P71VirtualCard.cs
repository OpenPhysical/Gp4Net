using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.CardEmulator.Profiles;
using Gp4Net.Core;
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
        CryptographicService cryptoService, 
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
        CryptographicService? cryptoService = null,
        ILogger<P71VirtualCard>? logger = null)
    {
        return CardProfileLoader.LoadFromFile(jsonPath)
            .Map(config =>
            {
                CryptographicService crypto = cryptoService ?? new CryptographicService();
                string profileName = System.IO.Path.GetFileNameWithoutExtension(jsonPath);
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
        CryptographicService? cryptoService = null,
        ILogger<P71VirtualCard>? logger = null)
    {
        return CardProfileLoader.LoadFromJson(json)
            .Map(config =>
            {
                CryptographicService crypto = cryptoService ?? new CryptographicService();
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
        CryptographicService? cryptoService = null,
        ILogger<P71VirtualCard>? logger = null)
    {
        CardConfiguration config = CardConfiguration.P71();
        CryptographicService crypto = cryptoService ?? new CryptographicService();
        return new P71VirtualCard("P71_SCP02_Default", config, crypto, logger);
    }
    
    /// <summary>
    /// Creates a P71 virtual card using the default SCP03 test profile.
    /// </summary>
    /// <param name="cryptoService">Optional cryptographic service.</param>
    /// <param name="logger">Optional logger for debugging.</param>
    /// <returns>P71 virtual card with SCP03 support.</returns>
    public static P71VirtualCard CreateScp03Card(
        CryptographicService? cryptoService = null,
        ILogger<P71VirtualCard>? logger = null)
    {
        // Use dual protocol config but default to SCP03
        CardConfiguration config = CardConfiguration.DualProtocol()
            .WithScpDefaults(0x03, Domain.Protocol.ScpImplementation.Scp03I70);
        CryptographicService crypto = cryptoService ?? new CryptographicService();
        return new P71VirtualCard("P71_SCP03_Default", config, crypto, logger);
    }
}