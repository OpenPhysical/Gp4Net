using System;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using Gp4Net.Services;
using Gp4Net.Tool.Commands.Applet;
using Gp4Net.Tool.Commands.Card;
using Gp4Net.Tool.Commands.Packages;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Services;
using Gp4Net.Tool.Services.CardCommunication;
using log4net;
using log4net.Config;
using Microsoft.Extensions.DependencyInjection;
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
                // Configure log4net
                var logRepository = LogManager.GetRepository(Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly());
                var configFile = new FileInfo("log4net.config");
                if (configFile.Exists)
                {
                    XmlConfigurator.Configure(logRepository, configFile);
                }
                else
                {
                    BasicConfigurator.Configure(logRepository);
                }

                Logger.Info("GP4Net tool starting");

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
                    config.SetApplicationName("gp4net");
                    config.SetApplicationVersion("1.0.0");

                    // Add global options
                    config.AddExample(new[] { "card", "list-readers" });
                    config.AddExample(new[] { "card", "connect", "-r", "ACS ACR122U 00 00" });
                    config.AddExample(new[] { "applet", "status", "--detailed" });
                    config.AddExample(new[] { "applet", "install", "myapp.cap" });
                    config.AddExample(new[] { "applet", "delete", "A000000001020304" });

                    // Card management commands
                    config.AddBranch("card", card =>
                    {
                        card.SetDescription("Smart card operations");
                        card.AddCommand<ListReadersCommand>("list-readers")
                            .WithDescription("List available card readers");
                        card.AddCommand<ConnectCommand>("connect")
                            .WithDescription("Connect to a smart card");
                        card.AddCommand<InfoCommand>("info")
                            .WithDescription("Display detailed card information");
                    });

                    // Applet management commands  
                    config.AddBranch("applet", applet =>
                    {
                        applet.SetDescription("Applet management operations");
                        applet.AddCommand<StatusCommand>("status")
                            .WithDescription("Get applet status from card");
                        applet.AddCommand<InstallCommand>("install")
                            .WithDescription("Install a CAP file on the card");
                        applet.AddCommand<DeleteCommand>("delete")
                            .WithDescription("Delete an applet from the card");
                        applet.AddCommand<LifecycleCommand>("lifecycle")
                            .WithDescription("Manage applet lifecycle states");
                        applet.AddCommand<ValidateCommand>("validate")
                            .WithDescription("Validate a CAP file without installing");
                    });

                    // Package management commands
                    config.AddBranch("packages", packages =>
                    {
                        packages.SetDescription("Java Card package operations");
                        packages.AddCommand<ScanSdkCommand>("scan-sdk")
                            .WithDescription("Scan Oracle Java Card SDKs for package AID mappings");
                        packages.AddCommand<AnalyzeExpCommand>("analyze-exp")
                            .WithDescription("Analyze individual .exp files for package information");
                    });

                    // Set default command
                    config.SetExceptionHandler((ex, resolver) =>
                    {
                        Logger.Error("Unhandled exception", ex);
                        AnsiConsole.WriteException(ex);
                        return 1;
                    });
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
            // Register WSCT dependencies
            services.AddSingleton<IWsctFactory, WsctFactory>();
            
            // Register services
            services.AddSingleton<ICardService, WsctCardService>();
            services.AddSingleton<IGlobalPlatformService, GlobalPlatformService>();
            services.AddSingleton<PackageRegistry>();

            // Register commands
            services.AddTransient<ListReadersCommand>();
            services.AddTransient<ConnectCommand>();
            services.AddTransient<InfoCommand>();
            services.AddTransient<StatusCommand>();
            services.AddTransient<InstallCommand>();
            services.AddTransient<DeleteCommand>();
            services.AddTransient<LifecycleCommand>();
            services.AddTransient<ValidateCommand>();
            services.AddTransient<ScanSdkCommand>();
            services.AddTransient<AnalyzeExpCommand>();

            Logger.Debug("Services configured");
        }
    }
}
