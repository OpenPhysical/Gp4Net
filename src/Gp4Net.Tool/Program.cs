using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Services;
using Gp4Net.Tool.Commands.Card;
using Gp4Net.Tool.Commands.Packages;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Pipeline;
using Gp4Net.Tool.Services;
using Gp4Net.Tool.Services.CardCommunication;
using Gp4Net.Transport;
using log4net;
using log4net.Config;
using log4net.Repository;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool;

/// <summary>
/// Main program class for the GP4Net tool.
/// </summary>
public class Program
{
    private static readonly ILog Logger = LogManager.GetLogger(typeof(Program));

    /// <summary>
    /// Main entry point for the application.
    /// </summary>
    /// <param name="args">Command line arguments.</param>
    /// <returns>Exit code.</returns>
    public static async Task<int> Main(string[] args)
    {
        try
        {
            // Configure log4net (file logging only)
            ILoggerRepository logRepository = LogManager.GetRepository(
                Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly()
            );
            FileInfo configFile = new FileInfo("log4net.config");
            if (configFile.Exists)
            {
                _ = XmlConfigurator.Configure(logRepository, configFile);
            }
            // Note: Intentionally not calling BasicConfigurator to avoid console output

            // Create service collection and configure DI
            ServiceCollection services = new ServiceCollection();
            ConfigureServices(services);

            // Build service provider to initialize CardServiceProvider
            ServiceProvider serviceProvider = services.BuildServiceProvider();

            // Validate critical service registrations
            Result<bool> validationResult = ValidateServiceRegistrations(serviceProvider);
            if (validationResult.IsFailure)
            {
                AnsiConsole.MarkupLine($"[red]Startup Error: {validationResult.Error}[/]");
                return 1;
            }

            // CardServiceProvider is no longer needed - functional context handles service provision

            // Create command app with DI
            CommandApp app = new CommandApp(new TypeRegistrar(services));
            app.Configure(config =>
            {
                _ = config.SetApplicationName("gp4net");
                _ = config.SetApplicationVersion("1.0.0");

                // Auto-register commands with CliCommandAttribute
                config.RegisterCliCommands(services);

                // Add global options
                _ = config.AddExample(new[] { "card", "list-readers" });
                _ = config.AddExample(new[] { "card", "connect", "-r", "ACS ACR122U 00 00" });
                _ = config.AddExample(
                    new[] { "card", "test-sc", "-k", "visa2:00000000000000000000000000000000" }
                );
                _ = config.AddExample(new[] { "applet", "status", "--detailed" });
                _ = config.AddExample(new[] { "applet", "install", "myapp.cap" });
                _ = config.AddExample(new[] { "applet", "delete", "A000000001020304" });
                _ = config.AddExample(new[] { "applet", "uninstall", "myapp.cap" });

                // Card management commands
                _ = config.AddBranch(
                    "card",
                    card =>
                    {
                        card.SetDescription("Smart card operations");
                        // Use new pipeline commands where available
                        _ = card.AddCommand<
                                PipelineCommand<ListReadersCommand.Settings>
                            >("list-readers")
                            .WithDescription("List available card readers");
                        _ = card.AddCommand<
                                PipelineCommand<ConnectCommand.Settings>
                            >("connect")
                            .WithDescription("Connect to a smart card");
                        _ = card.AddCommand<
                                PipelineCommand<InfoCommand.Settings>
                            >("info")
                            .WithDescription("Display detailed card information");
                        _ = card.AddCommand<TestSecureChannelCommand>("test-sc")
                            .WithDescription("Test secure channel establishment");
                        _ = card.AddCommand<
                                PipelineCommand<KeysChangeCommand.Settings>
                            >("change-keys")
                            .WithDescription("Change cryptographic keys on the card (WARNING: This permanently modifies card keys)");
                        _ = card.AddCommand<
                                PipelineCommand<GetIsdDataCommand.Settings>
                            >("get-data")
                            .WithDescription(
                                "Retrieve data objects from the card (IIN, CIN, OPID, etc.)"
                            );
                        _ = card.AddCommand<
                                PipelineCommand<PutIsdDataCommand.Settings>
                            >("put-data")
                            .WithDescription(
                                "Write data objects to the card (IIN, CIN, OPID, etc.)"
                            );
                    }
                );

                // Applet management commands are now auto-registered via CliCommandAttribute


                // Package management commands
                _ = config.AddBranch(
                    "packages",
                    packages =>
                    {
                        packages.SetDescription("Java Card package operations");
                        _ = packages
                            .AddCommand<ScanSdkCommand>("scan-sdk")
                            .WithDescription(
                                "Scan Oracle Java Card SDKs for package AID mappings"
                            );
                        _ = packages
                            .AddCommand<AnalyzeExpCommand>("analyze-exp")
                            .WithDescription(
                                "Analyze individual .exp files for package information"
                            );
                    }
                );

                // Trace management commands
                _ = config.AddBranch(
                    "trace",
                    trace =>
                    {
                        trace.SetDescription("Trace file operations");
                        _ = trace
                            .AddCommand<Commands.Trace.ConvertCommand>("convert")
                            .WithDescription(
                                "Convert trace files to structured JSON format with rich metadata"
                            );
                    }
                );

                // Set default command
                _ = config.SetExceptionHandler(
                    (ex, resolver) =>
                    {
                        Logger.Error("Unhandled exception", ex);
                        AnsiConsole.WriteException(ex);
                        return 1;
                    }
                );
            });

            return await app.RunAsync(args);
        }
        catch (Exception ex)
        {
            Logger?.Fatal("Fatal error during startup", ex);
            AnsiConsole.WriteException(ex);
            return 1;
        }
    }

    /// <summary>
    /// Configures dependency injection services.
    /// </summary>
    /// <param name="services">The service collection.</param>
    private static void ConfigureServices(IServiceCollection services)
    {
        // Register logging without console appender
        // Console logging is handled by command-level verbose flags
        _ = services.AddLogging(builder =>
        {
            _ = builder.SetMinimumLevel(LogLevel.Debug);
            // No console logger - commands handle their own output
        });

        // Register WSCT dependencies
        _ = services.AddSingleton<IWsctFactory, WsctFactory>();
        _ = services.AddSingleton<ICardContextWrapper>(provider => provider.GetRequiredService<IWsctFactory>().CreateCardContext());

        // Register cryptography services
        _ = services.AddSingleton<IKeyDerivationService, KeyDerivationService>();

        // Register transport services
        _ = services.AddSingleton<IApduTransportFactory, ApduTransportFactory>();

        // Register secure channel services
        _ = services.AddSingleton<IChallengeGenerator, DefaultChallengeGenerator>();
        _ = services.AddSingleton<
            ISecureChannelProtocolFactory,
            SecureChannelProtocolFactory
        >();
        _ = services.AddSingleton<ISecureChannelManager, SecureChannelManager>();

        // Register keyset resolver (functional implementation)
        _ = services.AddSingleton<IKeysetResolver, FunctionalKeysetResolverAdapter>();

        // Register functional smart card service
        _ = services.AddSingleton<ISmartCardService, SmartCardService>();

        // Register domain service factory
        _ = services.AddSingleton<IDomainServiceFactory, DomainServiceFactory>();
        _ = services.AddSingleton<PackageRegistry>();

        // SmartCardService is now created by DomainServiceFactory with functional composition

        // GlobalPlatformService is now created by DomainServiceFactory with functional composition
        // No need to register it in DI since it's created per-connection

        // Register pipeline services
        _ = services.AddSingleton<IDisplayService>(provider => new DisplayService(false));
        _ = services.AddScoped<ICliExecutionContext>(provider =>
        {
            IDisplayService display = provider.GetRequiredService<IDisplayService>();
            ISmartCardService smartCardService = provider.GetRequiredService<ISmartCardService>();
            var domainServiceFactory = provider.GetRequiredService<IDomainServiceFactory>();
            IKeysetResolver keysetResolver = provider.GetRequiredService<IKeysetResolver>();

            ILogger<CliContext> logger = provider.GetService<ILogger<CliContext>>();
            return new CliContext(display, smartCardService, domainServiceFactory, keysetResolver, logger);
        });

        // Command pipeline is now implemented as pure function composition

        // Register new pipeline commands automatically
        services.RegisterCommandHandlers(Assembly.GetExecutingAssembly());

        // Use Scrutor for automatic service registration
        _ = services.Scan(scan => scan
            .FromAssemblyOf<Program>()
            .FromAssemblyOf<Gp4Net.Core.ServiceLifetime.ISingletonService>()
            .AddClasses(classes => classes.AssignableTo<Gp4Net.Core.ServiceLifetime.ISingletonService>())
            .AsImplementedInterfaces()
            .WithSingletonLifetime()
            .AddClasses(classes => classes.AssignableTo<Gp4Net.Core.ServiceLifetime.IScopedService>())
            .AsImplementedInterfaces()
            .WithScopedLifetime()
            .AddClasses(classes => classes.AssignableTo<Gp4Net.Core.ServiceLifetime.ITransientService>())
            .AsImplementedInterfaces()
            .WithTransientLifetime());

        Logger.Debug("Services configured");
    }

    /// <summary>
    /// Validates that all critical services are properly registered in the DI container.
    /// </summary>
    /// <param name="provider">The service provider to validate.</param>
    /// <returns>Success if all services are registered, or an error message.</returns>
    private static CSharpFunctionalExtensions.Result<bool> ValidateServiceRegistrations(ServiceProvider provider)
    {
        Type[] criticalServices =
        [

            // IGlobalPlatformService is created by DomainServiceFactory, not DI
            typeof(ISmartCardService),
            typeof(IKeysetResolver),
            typeof(ISecureChannelManager),
            typeof(IApduTransportFactory),
            typeof(ISecureChannelProtocolFactory),
            typeof(IDomainServiceFactory)
        ];

        List<string> missingServices = [];

        foreach (Type serviceType in criticalServices)
        {
            try
            {
                object service = provider.GetService(serviceType);
                if (service == null)
                {
                    missingServices.Add(serviceType.Name);
                }
            }
            catch (Exception ex)
            {
                missingServices.Add($"{serviceType.Name} (Error: {ex.Message})");
            }
        }

        if (missingServices.Count > 0)
        {
            string errorMessage = $"Missing critical service registrations: {string.Join(", ", missingServices)}. " +
                                  "Check Program.cs ConfigureServices method.";
            Logger.Error(errorMessage);
            return CSharpFunctionalExtensions.Result.Failure<bool>(errorMessage);
        }

        Logger.Debug("All critical services validated successfully");
        return CSharpFunctionalExtensions.Result.Success(true);
    }
}
