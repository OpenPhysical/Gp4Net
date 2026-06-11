using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Services;
using Gp4Net.Services.GlobalPlatform;
using Gp4Net.Tool.Commands;
using Gp4Net.Tool.Extensions;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Pipeline;
using Gp4Net.Tool.Services;
using Gp4Net.Transport;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Card;

/// <summary>
/// Command to test secure channel establishment with GlobalPlatform test keys.
/// </summary>
[PublicAPI]
[Description("Test secure channel establishment with GP test keys")]
[CliCommand("test-sc", "Test secure channel establishment with GP test keys", "card")]
public class TestSecureChannelCommand : AsyncCommand<TestSecureChannelCommand.Settings>
{
    private readonly IDisplayService _displayService;
    private readonly IKeysetResolver _keysetResolver;
    private readonly IApduTransportFactory _transportFactory;
    private readonly ILogger<TestSecureChannelCommand> _logger;

    /// <summary>
    /// Initializes a new instance of the TestSecureChannelCommand class.
    /// </summary>
    public TestSecureChannelCommand(
        IDisplayService displayService,
        IKeysetResolver keysetResolver,
        IApduTransportFactory transportFactory,
        ILogger<TestSecureChannelCommand> logger
    )
    {
        _displayService = displayService;
        _keysetResolver = keysetResolver;
        _transportFactory = transportFactory;
        _logger = logger;
    }

    /// <summary>
    /// Command settings.
    /// </summary>
    [PublicAPI]
    public class Settings : SecureCommandSettings
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

        return await GetAvailableReaders(settings)
            .Bind(readerName => ConnectSmartCardService(readerName))
            .Bind(service => TestSecureChannelEstablishment(service, settings))
            .Match(
                success => Task.FromResult(0),
                error =>
                {
                    _displayService.Error($"Secure channel test failed: {error}");
                    return Task.FromResult(1);
                }
            );
    }

    private Result<string, SmartCardError> GetAvailableReaders(Settings settings)
    {
        _displayService.Info("Enumerating available card readers...");

        if (
            !string.IsNullOrWhiteSpace(settings.ReaderName)
            && ReaderEnumerationService.IsVirtualReader(settings.ReaderName)
        )
        {
            _displayService.Info($"Using virtual reader: {settings.ReaderName}");
            return Result.Success<string, SmartCardError>(settings.ReaderName);
        }

        return Result
            .Try(() =>
            {
                // Use ReaderEnumerationService instead of direct WSCT
                var readersResult = ReaderEnumerationService
                    .EnumeratePhysicalReadersAsync()
                    .GetAwaiter()
                    .GetResult();

                if (readersResult.IsFailure)
                {
                    return Result.Failure<string, SmartCardError>(readersResult.Error);
                }

                var readers = readersResult.Value.ToList();
                if (readers.Count == 0)
                {
                    return Result.Failure<string, SmartCardError>(
                        SmartCardError.CommunicationError("No card readers found")
                    );
                }

                _displayService.Info($"Found {readers.Count} reader(s):");
                var readerMessages = readers.Select(reader => $"  - {reader}");
                var displayResults = readerMessages.Select(message =>
                {
                    _displayService.Info(message);
                    return message;
                });
                var _ = displayResults.ToList(); // Force evaluation

                if (!string.IsNullOrWhiteSpace(settings.ReaderName))
                {
                    if (!readers.Contains(settings.ReaderName))
                    {
                        return Result.Failure<string, SmartCardError>(
                            SmartCardError.InvalidArgument(
                                $"Reader '{settings.ReaderName}' not found"
                            )
                        );
                    }
                    return Result.Success<string, SmartCardError>(settings.ReaderName);
                }

                // Use first available reader
                string selectedReader = readers[0];
                _displayService.Info($"Using reader: {selectedReader}");
                return Result.Success<string, SmartCardError>(selectedReader);
            })
            .MapError(ex => SmartCardError.CommunicationError($"Failed to enumerate readers: {ex}"))
            .Bind(result => result);
    }

    private async Task<Result<ISmartCardService, SmartCardError>> ConnectSmartCardService(
        string readerName
    )
    {
        _displayService.Info($"Connecting to reader: {readerName}");
        var result = await PhysicalCardConnectionService.CreateServiceAsync(
            readerName,
            NullLogger<SmartCardService>.Instance,
            CancellationToken.None
        );

        if (result.IsSuccess)
        {
            _displayService.Success("Connected to card");
        }

        return result;
    }

    private async Task<Result<bool, SmartCardError>> TestSecureChannelEstablishment(
        ISmartCardService smartCardService,
        Settings settings
    )
    {
        _displayService.Info("Testing secure channel establishment...");

        _displayService.Info($"Security Level: {settings.SecurityLevel}");
        _displayService.Info($"Protocol: {(settings.UseScp03 ? "SCP03" : "SCP02")}");

        string keysetName = settings.GetKeyset().GetValueOrDefault("gp_test_keys");
        if (keysetName is not "gp_test_keys" and not "gp_test")
        {
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument(
                    $"Unsupported test keyset '{keysetName}'. Only gp_test_keys is supported."
                )
            );
        }

        var explicitKeyVersion = settings.ToSecureChannelRequest().ExplicitKeyVersion;
        var rawKeysetResult = GpTestKeys.CreateRawTestKeyset(
            explicitKeyVersion.GetValueOrDefault(0x00)
        );

        return await rawKeysetResult.Match(
            async rawKeyset => await ExecuteTestWithKeySet(smartCardService, rawKeyset, settings),
            error =>
            {
                _displayService.Error($"Failed to create test keyset: {error.Message}");
                return Task.FromResult(Result.Failure<bool, SmartCardError>(error));
            }
        );
    }

    /// <summary>
    /// Executes the secure channel test with the resolved keyset.
    /// </summary>
    private async Task<Result<bool, SmartCardError>> ExecuteTestWithKeySet(
        ISmartCardService smartCardService,
        RawKeyset rawKeyset,
        Settings settings
    )
    {
        var securityLevel = (SecurityLevel)settings.SecurityLevel;

        var sw = Stopwatch.StartNew();

        // Establish secure channel using static ScpService
        var secureChannelResult = await ScpService.Establishment.EstablishAsync(
            smartCardService,
            rawKeyset,
            securityLevel,
            settings.ToSecureChannelRequest().ExplicitKeyVersion,
            CancellationToken.None
        );

        sw.Stop();

        return await secureChannelResult.Match(
            async secureChannelSession =>
            {
                if (
                    settings.UseScp03
                    && secureChannelSession.ScpOption.Protocol != CryptoService.ScpVersion.Scp03
                )
                {
                    return Result.Failure<bool, SmartCardError>(
                        SmartCardError.SecurityError(
                            $"Expected SCP03, but card negotiated {secureChannelSession.ScpOption.Protocol}"
                        )
                    );
                }

                _displayService.Success(
                    $"✓ Secure channel established successfully in {sw.ElapsedMilliseconds}ms"
                );
                if (settings.Debug)
                {
                    DisplayVectors(secureChannelSession);
                }

                return await TestSecureMessaging(smartCardService, secureChannelSession);
            },
            error =>
            {
                _displayService.Error($"✗ Failed to establish secure channel: {error.Message}");
                return Task.FromResult(Result.Failure<bool, SmartCardError>(error));
            }
        );
    }

    private async Task<Result<bool, SmartCardError>> TestSecureMessaging(
        ISmartCardService smartCardService,
        ScpService.Types.SecureChannelSession secureChannelSession
    )
    {
        _displayService.Info("Testing secure messaging...");

        var securedServiceResult = smartCardService.WithContextValue(
            "SecureChannelSession",
            secureChannelSession.State
        );
        if (securedServiceResult.IsFailure)
        {
            return Result.Failure<bool, SmartCardError>(securedServiceResult.Error);
        }

        var securedService = securedServiceResult.Value;

        // Test with GET STATUS command through secure channel
        var getStatusResult = await Applications.GetApplicationsAndSecurityDomainsAsync(
            (command, ct) => securedService.ExecuteCommandAsync(command, true, ct),
            CancellationToken.None
        );

        return getStatusResult.Match(
            applications =>
            {
                _displayService.Success("✓ Secure messaging working correctly");
                _displayService.Info($"Retrieved {applications.Count} application(s)");
                return Result.Success<bool, SmartCardError>(true);
            },
            error =>
            {
                _displayService.Warning(
                    $"! Secure channel established but command failed: {error.Message}"
                );
                return Result.Failure<bool, SmartCardError>(error);
            }
        );
    }

    private void DisplayVectors(ScpService.Types.SecureChannelSession secureChannelSession)
    {
        var vectors = secureChannelSession.Vectors;
        if (vectors is null)
        {
            return;
        }

        _displayService.Info("Secure channel vectors:");
        _displayService.Info($"  Protocol: {secureChannelSession.ScpOption.Protocol}");
        _displayService.Info($"  Implementation: 0x{vectors.ImplementationParameter:X2}");
        _displayService.Info($"  Key version: 0x{vectors.KeyVersion:X2}");
        _displayService.Info($"  Host challenge: {ToHex(vectors.HostChallenge)}");
        _displayService.Info(
            $"  Initialize Update response: {ToHex(vectors.InitializeUpdateResponse)}"
        );
        _displayService.Info($"  KDD: {ToHex(vectors.KeyDiversificationData)}");
        _displayService.Info($"  SSC: {ToHex(vectors.SequenceCounter)}");
        _displayService.Info($"  Card challenge: {ToHex(vectors.CardChallenge)}");
        _displayService.Info($"  Card cryptogram: {ToHex(vectors.CardCryptogram)}");
        _displayService.Info($"  S-ENC: {ToHex(vectors.SEnc)}");
        _displayService.Info($"  S-MAC: {ToHex(vectors.SMac)}");
        _displayService.Info($"  S-RMAC: {ToHex(vectors.SRMac)}");
        _displayService.Info($"  Host cryptogram: {ToHex(vectors.HostCryptogram)}");
        _displayService.Info(
            $"  External Authenticate MAC: {ToHex(vectors.ExternalAuthenticateMac)}"
        );
        _displayService.Info(
            $"  External Authenticate chaining MAC: {ToHex(vectors.ExternalAuthenticateChainingMac)}"
        );
        _displayService.Info(
            $"  External Authenticate APDU: {ToHex(vectors.ExternalAuthenticateCommand)}"
        );

        var firstStatusCommand = Gp4Net
            .Services.GlobalPlatform.Commands.CreateGetStatusCommand(
                Gp4Net
                    .Domain
                    .Commands
                    .GetStatusCommand
                    .StatusSubset
                    .ApplicationsAndSupplementaryDomains,
                new byte[] { 0x4F, 0x00 }
            )
            .Bind(command => command.ToCommandApdu());

        if (firstStatusCommand.IsSuccess)
        {
            var secured = ScpService.Security.ApplyCommandSecurity(
                firstStatusCommand.Value,
                secureChannelSession.State
            );

            if (secured.IsSuccess)
            {
                var (securedCommand, nextState) = secured.Value;
                _displayService.Info(
                    $"  First secured GET STATUS APDU: {ToHex(securedCommand.ToBytes())}"
                );
                _displayService.Info(
                    $"  First secured GET STATUS chaining: {ToHex(nextState.MacChainingValue)}"
                );
            }
        }
    }

    private static string ToHex(byte[] data) => Convert.ToHexString(data);
}
