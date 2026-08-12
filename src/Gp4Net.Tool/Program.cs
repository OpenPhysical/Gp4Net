using System;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using Gp4Net.Services;
using Gp4Net.Tool.Commands.Packages;
using Gp4Net.Tool.Commands.Trace;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Pipeline;
using Gp4Net.Tool.Services;
using Gp4Net.Transport;
using log4net;
using log4net.Config;
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

            using var loggerFactory = Microsoft.Extensions.Logging.LoggerFactory.Create(builder =>
            {
                _ = builder.SetMinimumLevel(LogLevel.Debug);
                _ = builder.AddConsole();
            });
            var display = new ConsoleDisplay();
            var keysets = new KeysetResolution();
            var transports = new ApduTransports(loggerFactory);
            var cardSessions = new CardSessionConnections(loggerFactory);
            var readers = new ReaderSelectionOperations(ProcessEnvironment.GetGp4NetReaderVariable);
            var context = new CliContext(
                display,
                cardSessions.CreateForEnumeration(),
                keysets,
                loggerFactory.CreateLogger<CliContext>(),
                cardSessions,
                readers
            );

            var registrar = new TypeRegistrar();
            registrar.RegisterInstance(typeof(ILoggerFactory), loggerFactory);
            registrar.RegisterInstance(typeof(IDisplay), display);
            registrar.RegisterInstance(typeof(KeysetResolution), keysets);
            registrar.RegisterInstance(typeof(ApduTransports), transports);
            registrar.RegisterInstance(typeof(CardSessionConnections), cardSessions);
            registrar.RegisterInstance(typeof(ReaderSelectionOperations), readers);
            registrar.RegisterInstance(typeof(ICliExecutionContext), context);
            registrar.RegisterInstance(typeof(PackageCatalog), new PackageCatalog());

            var app = new CommandApp(registrar);
            app.Configure(config =>
            {
                _ = config.SetApplicationName("gp4net");
                _ = config.SetApplicationVersion("1.0.0");

                // Auto-register commands with CliCommandAttribute
                config.RegisterCliCommands(registrar);

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
}
