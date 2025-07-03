using System;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using Gp4Net.Cryptography;
using Gp4Net.Cryptography.Implementation;
using Gp4Net.Cryptography.Strategies;
using Gp4Net.Domain.Protocol;
using Gp4Net.Services;
using Gp4Net.Tool.Commands.Applet;
using Gp4Net.Tool.Commands.Card;
using Gp4Net.Tool.Commands.Packages;
using Gp4Net.Tool.Commands.Script;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Pipeline;
using Gp4Net.Tool.Scripting;
using Gp4Net.Tool.Services;
using Gp4Net.Tool.Services.CardCommunication;
using Gp4Net.Transport;
using log4net;
using log4net.Config;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool
{
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
                var cardService = serviceProvider.GetRequiredService<ICardService>();
                CardServiceProvider.SetCardService(cardService);

                // Create command app with DI
                var app = new CommandApp(new TypeRegistrar(services));
                app.Configure(config =>
                {
                    _ = config.SetApplicationName("gp4net");
                    _ = config.SetApplicationVersion("1.0.0");

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
                            _ = card.AddCommand<ConvertScpCommand>("convert-scp")
                                .WithDescription("Convert card from SCP02 to SCP03");
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

                    // Applet management commands
                    _ = config.AddBranch(
                        "applet",
                        applet =>
                        {
                            applet.SetDescription("Applet management operations");
                            _ = applet
                                .AddCommand<ListCommand>("list")
                                .WithDescription("List applications on the card");
                            _ = applet
                                .AddCommand<StatusCommand>("status")
                                .WithDescription(
                                    "Get applet status from card (deprecated, use 'list')"
                                );
                            _ = applet
                                .AddCommand<InstallCommand>("install")
                                .WithDescription("Install a CAP file on the card");
                            _ = applet
                                .AddCommand<LoadCommand>("load")
                                .WithDescription(
                                    "Load a CAP file package (without installing applets)"
                                );
                            _ = applet
                                .AddCommand<InstantiateCommand>("instantiate")
                                .WithDescription("Instantiate an applet from a loaded package");
                            _ = applet
                                .AddCommand<DeleteCommand>("delete")
                                .WithDescription("Delete an applet from the card");
                            _ = applet
                                .AddCommand<DeleteCommand>("uninstall")
                                .WithDescription("Uninstall an applet from the card (alias for delete)");
                            _ = applet
                                .AddCommand<LifecycleCommand>("lifecycle")
                                .WithDescription("Manage applet lifecycle states");
                            _ = applet
                                .AddCommand<ValidateCommand>("validate")
                                .WithDescription("Validate a CAP file without installing");
                        }
                    );

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

            // Register cryptography services
            _ = services.AddSingleton<IKeyDerivationService, KeyDerivationService>();
            _ = services.AddSingleton<ICryptogramStrategy, Scp02CryptogramStrategy>();
            _ = services.AddSingleton<ICryptogramStrategy, Scp03CryptogramStrategy>();
            _ = services.AddSingleton<IKeyDerivationStrategy, Scp02KeyDerivationStrategy>();
            _ = services.AddSingleton<IKeyDerivationStrategy, Scp03KeyDerivationStrategy>();

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

            // Register card services with factory pattern for reader type selection
            _ = services.AddSingleton<EnhancedWsctCardService>();
            _ = services.AddSingleton<LuaVirtualCardService>();
            _ = services.AddSingleton<JsonLuaCardService>();
            _ = services.AddSingleton<SimpleJsonCardService>();
            _ = services.AddSingleton<ICardService>(provider =>
            {
                // Create a factory that selects the appropriate service based on reader name
                return new SimpleCardServiceFactory(
                    provider.GetRequiredService<EnhancedWsctCardService>(),
                    provider.GetRequiredService<SimpleJsonCardService>()
                );
            });
            _ = services.AddSingleton<IGlobalPlatformService, GlobalPlatformService>();
            _ = services.AddSingleton<PackageRegistry>();

            // Register pipeline services
            _ = services.AddSingleton<IDisplayService>(provider => new DisplayService(false));
            _ = services.AddSingleton<ICommandContext, Pipeline.CommandContext>();

            // Register new pipeline commands automatically
            services.RegisterCommandHandlers(Assembly.GetExecutingAssembly());

            // Register legacy commands (not yet refactored)
            _ = services.AddTransient<TestSecureChannelCommand>();
            _ = services.AddTransient<KeysChangeCommand>();
            _ = services.AddTransient<ConvertScpCommand>();
            _ = services.AddTransient<ListCommand>();
            _ = services.AddTransient<StatusCommand>();
            _ = services.AddTransient<InstallCommand>();
            _ = services.AddTransient<LoadCommand>();
            _ = services.AddTransient<InstantiateCommand>();
            _ = services.AddTransient<DeleteCommand>();
            _ = services.AddTransient<LifecycleCommand>();
            _ = services.AddTransient<ValidateCommand>();
            _ = services.AddTransient<ScanSdkCommand>();
            _ = services.AddTransient<AnalyzeExpCommand>();
            _ = services.AddTransient<ScriptCommand>();
            _ = services.AddTransient<ReplCommand>();
            _ = services.AddTransient<EvalCommand>();
            _ = services.AddTransient<Commands.Trace.ConvertCommand>();

            Logger.Debug("Services configured");
        }
    }
}
