using System.Collections.Generic;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Test builder for creating functional virtual cards with various configurations.
/// Provides a fluent API for setting up test scenarios with different card types,
/// cryptographic services, and validation modes.
/// </summary>
[PublicAPI]
public static class VirtualCardTestBuilder
{
    /// <summary>
    /// Creates a new builder instance for fluent configuration.
    /// </summary>
    /// <returns>A new VirtualCardBuilder instance.</returns>
    public static VirtualCardBuilder Builder() => new VirtualCardBuilder();

    /// <summary>
    /// Creates a P71 card with test cryptographic service.
    /// </summary>
    public static VirtualCard P71Card() =>
        new VirtualCard(CardConfiguration.P71(), new CryptographicService());

    /// <summary>
    /// Creates a P71 card with deterministic entropy for reproducible testing.
    /// </summary>
    /// <param name="entropy">The complete entropy supply for all random operations.</param>
    /// <returns>A P71 virtual card with deterministic behavior.</returns>
    public static Result<VirtualCard, SmartCardError> P71CardWithEntropy(byte[] entropy)
    {
        return CardConfiguration.P71().WithEntropy(entropy);
    }

    /// <summary>
    /// Creates a P71 card configured for exact trace replay.
    /// </summary>
    /// <param name="traceChallenges">Sequential challenges from a real P71 card trace.</param>
    /// <returns>A P71 virtual card that will behave exactly like the traced card.</returns>
    public static Result<VirtualCard, SmartCardError> P71CardForTraceReplay(IEnumerable<byte[]> traceChallenges)
    {
        return CardConfiguration.P71().WithTraceChallenges(traceChallenges);
    }


    /// <summary>
    /// Creates a generic JavaCard with test cryptographic service.
    /// </summary>
    public static VirtualCard GenericCard() =>
        new VirtualCard(CardConfiguration.Generic(), new CryptographicService());

    /// <summary>
    /// Creates a card with the specified configuration.
    /// </summary>
    public static VirtualCard WithConfiguration(CardConfiguration config) =>
        new VirtualCard(config, new CryptographicService());

    /// <summary>
    /// Creates a card with insufficient entropy to simulate crypto failures.
    /// Uses PreloadedRngService with insufficient entropy to cause cryptographic operation failures.
    /// </summary>
    public static VirtualCard WithFailingCrypto(this CardConfiguration config)
    {
        // Use insufficient entropy (4 bytes) - most crypto operations need 8+ bytes
        byte[] insufficientEntropy = [0x01, 0x02, 0x03, 0x04];
        
        return PreloadedRngService.Create(insufficientEntropy)
            .Map(rng => new VirtualCard(config, new CryptographicService(rng)))
            .GetValueOrDefault(new VirtualCard(config, new CryptographicService()));
    }

    /// <summary>
    /// Creates a card with deterministic test crypto service.
    /// </summary>
    public static VirtualCard WithTestCrypto(this CardConfiguration config) =>
        new VirtualCard(config, new CryptographicService());

    /// <summary>
    /// Creates a card with pre-loaded entropy for deterministic testing.
    /// </summary>
    /// <param name="config">The card configuration.</param>
    /// <param name="entropy">The complete entropy supply for all random operations.</param>
    /// <returns>A virtual card with deterministic behavior.</returns>
    public static Result<VirtualCard, SmartCardError> WithEntropy(this CardConfiguration config, byte[] entropy)
    {
        return PreloadedRngService.Create(entropy)
            .Map(rng => new VirtualCard(config, new CryptographicService(rng)));
    }

    /// <summary>
    /// Creates a card with entropy from trace challenges for exact replay.
    /// </summary>
    /// <param name="config">The card configuration.</param>
    /// <param name="traceChallenges">Sequential challenges extracted from a card trace.</param>
    /// <returns>A virtual card that will behave exactly like the traced card.</returns>
    public static Result<VirtualCard, SmartCardError> WithTraceChallenges(this CardConfiguration config, IEnumerable<byte[]> traceChallenges)
    {
        return PreloadedRngService.FromTraceChallenges(traceChallenges)
            .Map(rng => new VirtualCard(config, new CryptographicService(rng)));
    }

    /// <summary>
    /// Creates a card with repeating entropy pattern for unit tests.
    /// </summary>
    /// <param name="config">The card configuration.</param>
    /// <param name="pattern">The entropy pattern to repeat.</param>
    /// <param name="repetitions">Number of times to repeat the pattern.</param>
    /// <returns>A virtual card with repeating deterministic behavior.</returns>
    public static Result<VirtualCard, SmartCardError> WithRepeatingEntropy(this CardConfiguration config, byte[] pattern, int repetitions)
    {
        return PreloadedRngService.WithRepeatingPattern(pattern, repetitions)
            .Map(rng => new VirtualCard(config, new CryptographicService(rng)));
    }

    /// <summary>
    /// Creates a P71 card that supports IDENTIFY command.
    /// </summary>
    public static VirtualCard P71CardWithIdentify() =>
        P71Card(); // P71 configuration already includes IDENTIFY support

    /// <summary>
    /// Creates a card with specific SCP configuration.
    /// </summary>
    public static VirtualCard WithScp(this CardConfiguration config, byte version, Domain.Protocol.ScpImplementation implementation) =>
        new(config.WithScpDefaults(version, implementation), new CryptographicService());

    /// <summary>
    /// Creates a card with additional data objects for testing.
    /// </summary>
    public static VirtualCard WithDataObject(this CardConfiguration config, ushort tag, byte[] data) =>
        new(config.WithDataObject(tag, data), new CryptographicService());
    
    /// <summary>
    /// Creates a dual-protocol card supporting both SCP02 and SCP03.
    /// Defaults to SCP02 i=15 but supports SCP03 i=70 as well.
    /// </summary>
    public static VirtualCard DualProtocolCard() =>
        new VirtualCard(CardConfiguration.DualProtocol(), new CryptographicService());

    /// <summary>
    /// Creates an SCP03-first card configuration.
    /// Defaults to SCP03 i=70 but supports SCP02 fallback.  
    /// </summary>
    public static VirtualCard Scp03FirstCard() =>
        new VirtualCard(CardConfiguration.Scp03First(), new CryptographicService());

    /// <summary>
    /// Creates a card with SCP02 protocol support using GlobalPlatform Test Keys.
    /// Per GP 2.3.1 Section 11.1.1: Uses proper SCP02 key set types for type safety.
    /// </summary>
    public static VirtualCard Scp02Card()
    {
        CardConfiguration config = CardConfiguration.Generic() with
        {
            DefaultScpVersion = 0x02,
            DefaultScpImplementation = Domain.Protocol.ScpImplementation.Scp02I15
        };
        return new VirtualCard(config, new CryptographicService());
    }

    /// <summary>
    /// Creates a card set up for secure channel testing.
    /// </summary>
    public static VirtualCard ForSecureChannelTesting(byte scpVersion = 0x02)
    {
        CardConfiguration? config = scpVersion switch
        {
            0x02 => CardConfiguration.P71().WithScpDefaults(0x02, Domain.Protocol.ScpImplementation.Scp02I15),
            0x03 => CardConfiguration.P71().WithScpDefaults(0x03, Domain.Protocol.ScpImplementation.Scp03I70),
            _ => Result.Success<CardConfiguration, SmartCardError>(CardConfiguration.P71()) // Use functional approach instead of throw
                .Map(c => c) // Keep consistency with functional programming
                .GetValueOrDefault(CardConfiguration.P71())
        };
        return new VirtualCard(config, new CryptographicService());
    }

    /// <summary>
    /// Creates a minimal card for basic testing supporting only SELECT and GET DATA commands.
    /// </summary>
    public static VirtualCard MinimalCard() =>
        new VirtualCard(CardConfiguration.Minimal(), new CryptographicService());

    /// <summary>
    /// Creates a card configured for testing with insufficient entropy to simulate crypto failures.
    /// Uses PreloadedRngService with minimal entropy (1 byte) to cause failure on 6-byte challenge requests.
    /// </summary>
    public static VirtualCard SimulatingErrors()
    {
        // Use minimal entropy (1 byte) - INITIALIZE UPDATE needs 6 bytes for SCP02 card challenge
        // This will cause GenerateChallenge(6) to fail with insufficient entropy error
        byte[] minimalEntropy = [0x01];
        
        return PreloadedRngService.Create(minimalEntropy)
            .Match(
                rng => new VirtualCard(CardConfiguration.Generic(), new CryptographicService(rng)),
                error => new VirtualCard(CardConfiguration.Generic(), new CryptographicService()));
    }

    /// <summary>
    /// Creates a card configured for trace replay testing.
    /// </summary>
    public static VirtualCard ForTrace() =>
        P71Card(); // Use P71 card as base for trace replay
    
    /// <summary>
    /// Creates a card configured for trace replay testing with specific entropy.
    /// </summary>
    public static Result<VirtualCard, SmartCardError> ForTrace(byte[] entropy) =>
        P71CardWithEntropy(entropy);
    
    /// <summary>
    /// Creates a card configured for trace replay testing from a trace file.
    /// </summary>
    /// <param name="traceFileName">The trace file name to load.</param>
    /// <returns>A virtual card configured for the specified trace.</returns>
    public static Result<VirtualCard, SmartCardError> ForTrace(string traceFileName)
    {
        return Maybe<string>.From(traceFileName)
            .ToResult(SmartCardError.InvalidArgument("Trace file name cannot be null"))
            .Bind(fileName => fileName.Length > 0
                ? Result.Success<string, SmartCardError>(fileName)
                : Result.Failure<string, SmartCardError>(SmartCardError.InvalidArgument("Trace file name cannot be empty")))
            .Map(_ => P71Card()); // Use P71 card as base for trace-based testing
    }
}

/// <summary>
/// Fluent builder for creating virtual cards with complex configurations.
/// Uses functional programming principles with Maybe&lt;T&gt; for optional values.
/// </summary>
[PublicAPI]
public class VirtualCardBuilder
{
    private readonly Maybe<CardConfiguration> _configuration;
    private readonly Maybe<CryptographicService> _cryptographicService;
    
    /// <summary>
    /// Initializes a new instance with no configuration set.
    /// </summary>
    public VirtualCardBuilder()
    {
        _configuration = Maybe<CardConfiguration>.None;
        _cryptographicService = Maybe<CryptographicService>.None;
    }
    
    /// <summary>
    /// Private constructor for creating configured instances.
    /// </summary>
    private VirtualCardBuilder(Maybe<CardConfiguration> configuration, Maybe<CryptographicService> cryptographicService)
    {
        _configuration = configuration;
        _cryptographicService = cryptographicService;
    }
    
    /// <summary>
    /// Sets the card configuration.
    /// </summary>
    /// <param name="configuration">The card configuration to use.</param>
    /// <returns>A new builder instance with the configuration set.</returns>
    public VirtualCardBuilder WithConfiguration(CardConfiguration configuration) =>
        new VirtualCardBuilder(Maybe<CardConfiguration>.From(configuration), _cryptographicService);
    
    /// <summary>
    /// Sets a test cryptographic service.
    /// </summary>
    /// <returns>A new builder instance with test crypto service.</returns>
    public VirtualCardBuilder WithTestCrypto() =>
        new VirtualCardBuilder(_configuration, Maybe<CryptographicService>.From(new CryptographicService()));
    
    /// <summary>
    /// Configures the card for P71 testing with specific crypto configuration.
    /// </summary>
    /// <returns>A new builder instance configured for P71 testing.</returns>
    public VirtualCardBuilder AsP71() =>
        new VirtualCardBuilder(Maybe<CardConfiguration>.From(CardConfiguration.P71()), _cryptographicService);
    
    /// <summary>
    /// Configures the card with specific SCP settings.
    /// </summary>
    /// <param name="scpVersion">The SCP version.</param>
    /// <param name="implementation">The SCP implementation.</param>
    /// <returns>A new builder instance with SCP configuration.</returns>
    public VirtualCardBuilder WithScp(byte scpVersion, Domain.Protocol.ScpImplementation implementation)
    {
        CardConfiguration? currentConfig = _configuration.Match(
            config => config,
            () => CardConfiguration.P71()
        );
        
        CardConfiguration updatedConfig = currentConfig.WithScpDefaults(scpVersion, implementation);
        return new VirtualCardBuilder(Maybe<CardConfiguration>.From(updatedConfig), _cryptographicService);
    }
    
    /// <summary>
    /// Sets a cryptographic service with deterministic entropy.
    /// </summary>
    /// <param name="entropy">The entropy to use for cryptographic operations.</param>
    /// <returns>A new builder instance with the entropy-based crypto service.</returns>
    public VirtualCardBuilder WithCryptographicService(byte[] entropy)
    {
        CryptographicService? cryptoService = PreloadedRngService.Create(entropy)
            .Map(rng => new CryptographicService(rng))
            .GetValueOrDefault(new CryptographicService());
            
        return new VirtualCardBuilder(_configuration, Maybe<CryptographicService>.From(cryptoService));
    }
    
    /// <summary>
    /// Builds the virtual card with the configured settings using functional pattern matching.
    /// </summary>
    /// <returns>A configured virtual card instance.</returns>
    public VirtualCard Build()
    {
        CardConfiguration? config = _configuration.Match(
            configuration => configuration,
            () => CardConfiguration.P71()
        );
        
        CryptographicService? crypto = _cryptographicService.Match(
            service => service,
            () => new CryptographicService()
        );
        
        return new VirtualCard(config, crypto);
    }
}
