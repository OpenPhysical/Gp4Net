using System;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Services;
using Gp4Net.Tool.Commands.Card;
using Gp4Net.Tool.Commands.Packages;
using Gp4Net.Tool.Commands.Script;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Pipeline;
using Gp4Net.Tool.Scripting;
using Gp4Net.Tool.Services;
using Gp4Net.Tool.Services.CardCommunication;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Pipeline;
using Gp4Net.Transport;
using log4net;
using log4net.Config;
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
            var cardService = serviceProvider.GetRequiredService<Tool.Services.ICardService>();
            CardServiceProvider.SetCardService(cardService);

            // Create command app with DI
            var app = new CommandApp(new TypeRegistrar(services));
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
                _ = config.AddExample(new[] { "script", "run", "install.lua" });
                _ = config.AddExample(
                    new[] { "script", "eval", "connect(); get_status(); disconnect()" }
                );

                // Card management commands
                _ = config.AddBranch(
                    "card",
                    card =>
                    {
                        card.SetDescription("Smart card operations");
                        // Use new pipeline commands where available
                        _ = card.AddCommand<
                                PipelineCommand<Commands.Card.ListReadersCommand.Settings>
                            >("list-readers")
                            .WithDescription("List available card readers");
                        _ = card.AddCommand<
                                PipelineCommand<Commands.Card.ConnectCommand.Settings>
                            >("connect")
                            .WithDescription("Connect to a smart card");
                        _ = card.AddCommand<
                                PipelineCommand<Commands.Card.InfoCommand.Settings>
                            >("info")
                            .WithDescription("Display detailed card information");
                        _ = card.AddCommand<TestSecureChannelCommand>("test-sc")
                            .WithDescription("Test secure channel establishment");
                        _ = card.AddCommand<KeysChangeCommand>("change-keys")
                            .WithDescription("Change cryptographic keys on the card (WARNING: This permanently modifies card keys)");
                        _ = card.AddCommand<
                                PipelineCommand<Commands.Card.GetIsdDataCommand.Settings>
                            >("get-data")
                            .WithDescription(
                                "Retrieve data objects from the card (IIN, CIN, OPID, etc.)"
                            );
                        _ = card.AddCommand<
                                PipelineCommand<Commands.Card.PutIsdDataCommand.Settings>
                            >("put-data")
                            .WithDescription(
                                "Write data objects to the card (IIN, CIN, OPID, etc.)"
                            );
                    }
                );

                // Applet management commands are now auto-registered via CliCommandAttribute

                // Script commands
                _ = config.AddBranch(
                    "script",
                    script =>
                    {
                        script.SetDescription("Lua scripting operations");
                        _ = script
                            .AddCommand<ScriptCommand>("run")
                            .WithDescription("Execute a Lua script file");
                        _ = script
                            .AddCommand<ReplCommand>("repl")
                            .WithDescription("Start interactive Lua REPL");
                        _ = script
                            .AddCommand<EvalCommand>("eval")
                            .WithDescription("Evaluate a Lua expression");
                    }
                );

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

        // Register scripting services
        _ = services.AddSingleton<ScriptDirectoryResolver>();
        _ = services.AddSingleton<IScriptManager, ScriptManager>();
        _ = services.AddSingleton<IKeysetResolver, KeysetResolver>();

        // Register real card service
        _ = services.AddSingleton<WsctCardService>();
            
        // Register virtual card services
        _ = services.AddSingleton<VirtualCardService>(provider => 
        {
            var virtualService = new VirtualCardService();
            virtualService.SetupComprehensiveTestEnvironment(); // Setup all card types
            return virtualService;
        });
        _ = services.AddSingleton<VirtualCardServiceAdapter>();
            
        // Register hybrid card service as the main ICardService
        _ = services.AddSingleton<Tool.Services.ICardService, HybridCardService>(provider =>
        {
            var realCardService = provider.GetRequiredService<WsctCardService>();
            var virtualCardService = provider.GetRequiredService<VirtualCardServiceAdapter>();
            var logger = provider.GetRequiredService<ILogger<HybridCardService>>();
            return new HybridCardService(realCardService, virtualCardService, logger);
        });
            
        // Register domain service factory
        _ = services.AddSingleton<IDomainServiceFactory, DomainServiceFactory>();
        _ = services.AddSingleton<PackageRegistry>();

        // Register pipeline services
        _ = services.AddSingleton<IDisplayService>(provider => new DisplayService(false));
        _ = services.AddScoped<Gp4Net.Tool.Pipeline.ICliExecutionContext>(provider => 
        {
            var display = provider.GetRequiredService<IDisplayService>();
            var cardService = provider.GetRequiredService<Tool.Services.ICardService>();
            var domainServiceFactory = provider.GetRequiredService<IDomainServiceFactory>();
            var keysetResolver = provider.GetRequiredService<IKeysetResolver>();
                
            var logger = provider.GetService<ILogger<Pipeline.CliContext>>();
            return new Pipeline.CliContext(display, cardService, domainServiceFactory, keysetResolver, logger);
        });
            
        // Build the command pipeline
        _ = services.AddSingleton<ICommandPipeline>(provider =>
        {
            var transportFactory = provider.GetRequiredService<IApduTransportFactory>();
            var transport = transportFactory.CreateTransport(TransportProtocol.T0);
            var transportLogger = provider.GetService<ILogger<Gp4Net.Pipeline.Middleware.TransportMiddleware>>();
            var secureChannelLogger = provider.GetService<ILogger<Gp4Net.Pipeline.Middleware.SecureChannelMiddleware>>();
            var loggingLogger = provider.GetService<ILogger<Gp4Net.Pipeline.Middleware.LoggingMiddleware>>();
                
            return new CommandPipelineBuilder()
                .Use(new Gp4Net.Pipeline.Middleware.TransportMiddleware(transport, transportLogger))
                .Use(new Gp4Net.Pipeline.Middleware.SecureChannelMiddleware(secureChannelLogger))
                .Use(new Gp4Net.Pipeline.Middleware.LoggingMiddleware(loggingLogger!))
                .Build();
        });

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
}