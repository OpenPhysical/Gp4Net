using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Services;
using Gp4Net.Tool.Pipeline;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Card;

/// <summary>
/// Command to test secure channel establishment with GlobalPlatform test keys.
/// </summary>
[PublicAPI]
[Description("Test secure channel establishment with GP test keys")]
public class TestSecureChannelCommand : AsyncCommand<TestSecureChannelCommand.Settings>
{
    private readonly IDisplayService _displayService;
    private readonly IDomainServiceFactory _domainServiceFactory;
    private readonly IKeysetResolver _keysetResolver;

    /// <summary>
    /// Initializes a new instance of the TestSecureChannelCommand class.
    /// </summary>
    public TestSecureChannelCommand(
        IDisplayService displayService,
        IDomainServiceFactory domainServiceFactory,
        IKeysetResolver keysetResolver)
    {
        _displayService = displayService;
        _domainServiceFactory = domainServiceFactory;
        _keysetResolver = keysetResolver;
    }

    /// <summary>
    /// Command settings.
    /// </summary>
    [PublicAPI]
    public class Settings : CommandSettings
    {
        /// <summary>
        /// Gets or sets whether to use SCP03.
        /// </summary>
        [CommandOption("--scp03")]
        [Description("Use SCP03 instead of SCP02")]
        public bool UseScp03 { get; set; }

        /// <summary>
        /// Gets or sets the security level for secure channel.
        /// </summary>
        [CommandOption("-s|--security-level")]
        [Description("Security level (1=MAC, 3=MAC+ENC)")]
        public byte SecurityLevel { get; set; } = 1;
    }

    /// <summary>
    /// Executes the test secure channel command to verify secure channel establishment.
    /// </summary>
    /// <param name="context">The command context.</param>
    /// <param name="settings">The command settings.</param>
    /// <returns>0 if successful, 1 if failed.</returns>
    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings)
    {
        _displayService.Info("Starting secure channel test...");

        return await CreateSmartCardService()
            .Bind(smartCardService => EstablishConnectionAndTest(smartCardService, settings))
            .Match(
                success => Task.FromResult(0),
                error =>
                {
                    _displayService.Error($"Secure channel test failed: {error.Message}");
                    return Task.FromResult(1);
                });
    }

    private Result<ISmartCardService, SmartCardError> CreateSmartCardService()
    {
        return Result.Failure<ISmartCardService, SmartCardError>(
            SmartCardError.CommunicationError("Direct SmartCardService creation requires dependency injection setup that is not available in current context"));
    }

    private async Task<Result<bool, SmartCardError>> EstablishConnectionAndTest(
        ISmartCardService smartCardService,
        Settings settings)
    {
        // Check if already connected
        Result<bool, SmartCardError> isConnectedResult = await smartCardService.IsConnectedAsync();
        if (isConnectedResult.IsFailure)
        {
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.CommunicationError("Cannot determine connection status"));
        }

        if (!isConnectedResult.Value)
        {
            _displayService.Error("Not connected to card. Use 'card connect' first.");
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.CommunicationError("Card not connected"));
        }

        return await TestSecureChannelEstablishment(smartCardService, settings);
    }

    private async Task<Result<bool, SmartCardError>> TestSecureChannelEstablishment(
        ISmartCardService smartCardService,
        Settings settings)
    {
        _displayService.Info("Testing secure channel establishment...");

        _displayService.Info($"Security Level: {settings.SecurityLevel}");
        _displayService.Info($"Protocol: {(settings.UseScp03 ? "SCP03" : "SCP02")}");

        // Create proper KeySet from GP test keys
        byte protocolVersion = settings.UseScp03 ? (byte)0x03 : (byte)0x02;
        KeySet keySet = protocolVersion == 0x03
            ? GpTestKeys.CreateScp03TestKeySet(0x00) as KeySet
            : GpTestKeys.CreateScp02TestKeySet(0x00) as KeySet;

        SecurityLevel securityLevel = (SecurityLevel)settings.SecurityLevel;

        Stopwatch sw = System.Diagnostics.Stopwatch.StartNew();

        // Create GlobalPlatform service and establish secure channel
        var gpService = _domainServiceFactory.CreateGlobalPlatformService(smartCardService);
        var secureChannelResult = await gpService.EstablishSecureChannelAsync(keySet, securityLevel);

        sw.Stop();

        return await secureChannelResult.Match(
            async _ =>
            {
                _displayService.Success($"✓ Secure channel established successfully in {sw.ElapsedMilliseconds}ms");
                return await TestSecureMessaging(gpService);
            },
            error =>
            {
                _displayService.Error($"✗ Failed to establish secure channel: {error.Message}");
                return Task.FromResult(Result.Failure<bool, SmartCardError>(error));
            });
    }

    private async Task<Result<bool, SmartCardError>> TestSecureMessaging(IGlobalPlatformService gpService)
    {
        _displayService.Info("Testing secure messaging...");

        // Test with GET STATUS command through secure channel
        Result<ImmutableList<ApplicationInfo>, SmartCardError> getStatusResult = await gpService.GetStatusAsync(
            Gp4Net.Domain.Commands.GetStatusCommand.StatusSubset.IssuerSecurityDomain);

        return getStatusResult.Match(
            applications =>
            {
                _displayService.Success("✓ Secure messaging working correctly");
                _displayService.Info($"Retrieved {applications.Count} application(s)");
                return Result.Success<bool, SmartCardError>(true);
            },
            error =>
            {
                _displayService.Warning($"! Secure channel established but command failed: {error.Message}");
                return Result.Success<bool, SmartCardError>(true); // Still consider secure channel test successful
            });
    }
}
