using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Core.ServiceLifetime;
using Gp4Net.Pipeline;
using Gp4Net.Services;
using Gp4Net.Tool.Commands.Card;
using Gp4Net.Tool.Commands.Packages;
using Gp4Net.Tool.Commands.Trace;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Pipeline;
using Gp4Net.Tool.Services;
using Gp4Net.Tool.Services.CardCommunication;
using Gp4Net.Transport;
using log4net;
using log4net.Config;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Spectre.Console;
using Spectre.Console.Cli;
using WSCT.ISO7816;

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
            var logRepository = LogManager.GetRepository(
                Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly()
            );
            var configFile = new FileInfo("log4net.config");
            if (configFile.Exists)
            {
                _ = XmlConfigurator.Configure(logRepository, configFile);
            }
            // Note: Intentionally not calling BasicConfigurator to avoid console output

            // Create service collection and configure DI
            var services = new ServiceCollection();
            ConfigureServices(services);

            // Build service provider to initialize CardServiceProvider
            var serviceProvider = services.BuildServiceProvider();

            // Validate critical service registrations
            var validationResult = ValidateServiceRegistrations(serviceProvider);
            if (validationResult.IsFailure)
            {
                AnsiConsole.WriteLine($"Startup Error: {validationResult.Error}");
                return 1;
            }

            // CardServiceProvider is no longer needed - functional context handles service provision

            // Create command app with DI
            var app = new CommandApp(new TypeRegistrar(services));
            app.Configure(config =>
            {
                _ = config.SetApplicationName("gp4net");
                _ = config.SetApplicationVersion("1.0.0");

                // Auto-register commands with CliCommandAttribute
                config.RegisterCliCommands(services);

                // Add global options
                _ = config.AddExample("card", "list-readers");
                _ = config.AddExample("card", "connect", "-r", "ACS ACR122U 00 00");
                _ = config.AddExample(
                    "card",
                    "test-sc",
                    "-k",
                    "visa2:00000000000000000000000000000000"
                );
                _ = config.AddExample("applet", "status", "--detailed");
                _ = config.AddExample("applet", "install", "myapp.cap");
                _ = config.AddExample("applet", "delete", "A000000001020304");
                _ = config.AddExample("applet", "uninstall", "myapp.cap");

                // All card and applet commands are now auto-registered via CliCommandAttribute

                // Package management commands
                _ = config.AddBranch(
                    "packages",
                    packages =>
                    {
                        packages.SetDescription("Java Card package operations");
                        _ = packages
                            .AddCommand<ScanSdkCommand>("scan-sdk")
                            .WithDescription("Scan Oracle Java Card SDKs for package AID mappings");
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
                            .AddCommand<ConvertCommand>("convert")
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
        // Register logging with console output
        _ = services.AddLogging(builder =>
        {
            _ = builder.SetMinimumLevel(LogLevel.Debug);
            _ = builder.AddConsole();
        });

        // Register WSCT dependencies
        _ = services.AddSingleton<IWsctFactory, WsctFactory>();
        _ = services.AddSingleton(provider =>
            provider.GetRequiredService<IWsctFactory>().CreateCardContext()
        );

        // Register cryptography services
        // UnifiedCryptoService is static and doesn't need registration

        // Register transport services
        _ = services.AddSingleton<IApduTransportFactory, ApduTransportFactory>();

        // Register secure channel services
        // IChallengeGenerator removed - use CryptoService.Rng.GenerateBytes directly
        // ISecureChannelProtocolFactory deleted - using ScpService directly

        // SecureChannelManager is now created per-connection since it requires ISmartCardService
        // Removed singleton registration - will be created by commands that need it

        // Register keyset resolver (functional implementation)
        _ = services.AddSingleton<IKeysetResolver, KeysetResolver>();

        // SmartCardService is now created per-connection via PcscSmartCardService.CreateAsync
        // No singleton registration needed as it's created dynamically with specific readers

        // DomainServiceFactory deleted - services are now static
        // No factory registration needed
        _ = services.AddSingleton<PackageRegistry>();

        // SmartCardService is now created per-connection
        // GlobalPlatformService is static - no DI registration needed

        // Register pipeline services
        _ = services.AddSingleton<IDisplayService>(provider => new DisplayService());
        _ = services.AddSingleton<ISmartCardServiceFactory, SmartCardServiceFactory>();
        
        // Register reader resolution services
        _ = services.AddSingleton<IEnvironmentService, EnvironmentService>();
        _ = services.AddSingleton<IReaderResolutionService, ReaderResolutionService>();
        
        // CliExecutionContext is now created per-command with proper service factory
        _ = services.AddScoped<ICliExecutionContext>(provider =>
        {
            var display = provider.GetRequiredService<IDisplayService>();
            var keysetResolver = provider.GetRequiredService<IKeysetResolver>();
            var serviceFactory = provider.GetRequiredService<ISmartCardServiceFactory>();
            var logger = provider.GetService<ILogger<CliContext>>();

            // Create enumeration service for commands that don't need a connection
            var enumerationService = serviceFactory.CreateForEnumeration();

            return new CliContext(display, enumerationService, keysetResolver, logger);
        });

        // Command pipeline is now implemented as pure function composition

        // Register new pipeline commands automatically
        services.RegisterCommandHandlers(Assembly.GetExecutingAssembly());

        // Use Scrutor for automatic service registration
        _ = services.Scan(scan =>
            scan.FromAssemblyOf<Program>()
                .FromAssemblyOf<ISingletonService>()
                .AddClasses(classes => classes.AssignableTo<ISingletonService>())
                .AsImplementedInterfaces()
                .WithSingletonLifetime()
                .AddClasses(classes => classes.AssignableTo<IScopedService>())
                .AsImplementedInterfaces()
                .WithScopedLifetime()
                .AddClasses(classes => classes.AssignableTo<ITransientService>())
                .AsImplementedInterfaces()
                .WithTransientLifetime()
        );

        Logger.Debug("Services configured");
    }

    /// <summary>
    /// Validates that all critical services are properly registered in the DI container.
    /// </summary>
    /// <param name="provider">The service provider to validate.</param>
    /// <returns>Success if all services are registered, or an error message.</returns>
    private static Result<bool> ValidateServiceRegistrations(ServiceProvider provider)
    {
        Type[] criticalServices =
        [
            // GlobalPlatformService is static - no DI registration
            // ISmartCardService is created per-connection, not from DI
            // ISecureChannelManager is deleted - using ScpService directly
            typeof(IKeysetResolver),
            typeof(IApduTransportFactory),
            // ISecureChannelProtocolFactory and IDomainServiceFactory are deleted
        ];

        var missingServices = criticalServices
            .Select(serviceType => TryGetService(provider, serviceType))
            .Where(result => result.IsFailure)
            .Select(result => result.Error)
            .ToList();

        if (missingServices.Count > 0)
        {
            string errorMessage =
                $"Missing critical service registrations: {string.Join(", ", missingServices)}. "
                + "Check Program.cs ConfigureServices method.";
            Logger.Error(errorMessage);
            return Result.Failure<bool>(errorMessage);
        }

        Logger.Debug("All critical services validated successfully");
        return Result.Success(true);
    }

    /// <summary>
    /// Functional helper to safely get a service from the container.
    /// Returns Result with success/failure instead of using exceptions or null checks.
    /// </summary>
    private static Result<object, string> TryGetService(IServiceProvider provider, Type serviceType)
    {
        return Result
            .Try(() => provider.GetService(serviceType))
            .MapError(ex => $"{serviceType.Name} (Error: {ex})")
            .Bind(service => Maybe.From(service).ToResult($"{serviceType.Name}").Map(s => s));
    }
}

