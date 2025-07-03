using System;
using System.ComponentModel;
using System.IO;
using System.Threading.Tasks;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Applet
{
    /// <summary>
    /// Command to load a CAP file package onto the card without installing applets.
    /// </summary>
    [PublicAPI]
    /// <summary>
    /// Command to load a CAP file package onto a GlobalPlatform card without installing applets.
    /// </summary>
    [Description("Load a CAP file package onto the card (without installing applets)")]
    public class LoadCommand : BaseCommand<LoadCommand.Settings>
    {
        /// <summary>
        /// Initializes a new instance of the LoadCommand class.
        /// </summary>
        public LoadCommand(
            ICardService cardService,
            IGlobalPlatformService globalPlatformService,
            IKeysetResolver keysetResolver
        )
            : base(cardService, globalPlatformService, keysetResolver) { }

        /// <summary>
        /// Executes the load command to upload a CAP file package to the card.
        /// </summary>
        /// <param name="context">The command context.</param>
        /// <param name="settings">The command settings.</param>
        /// <returns>0 if successful, 1 if failed.</returns>
        protected override async Task<int> ExecuteCommandAsync(
            CommandContext context,
            Settings settings
        )
        {
            if (!EnsureCardConnection(settings))
            {
                return 1;
            }

            // Establish secure channel for loading
            if (!EnsureSecureChannel(settings))
            {
                return 1;
            }

            if (!File.Exists(settings.CapFile))
            {
                AnsiConsole.MarkupLine($"[red]CAP file not found: {settings.CapFile}[/]");
                return 1;
            }

            try
            {
                AnsiConsole.MarkupLine($"[cyan]Reading CAP file: {settings.CapFile}[/]");
                var capFileData = await File.ReadAllBytesAsync(settings.CapFile);

                AnsiConsole.MarkupLine($"[dim]CAP file size: {capFileData.Length} bytes[/]");

                if (!settings.NoCardInfo)
                {
                    DisplayCardInfo();
                }

                AnsiConsole.WriteLine();

                _ = await AnsiConsole
                    .Progress()
                    .StartAsync(async ctx =>
                    {
                        var task = ctx.AddTask("[green]Loading CAP file[/]");
                        task.MaxValue = 100;

                        // TODO: Call GlobalPlatformService.LoadCapFile when implemented
                        // For now, use InstallCapFile with installApplets=false
                        task.Value = 10;
                        await Task.Delay(100);

                        var result = GlobalPlatformService.InstallCapFile(
                            capFileData,
                            installApplets: false,
                            makeSelectable: false
                        );

                        task.Value = 100;

                        if (result.IsSuccessful)
                        {
                            AnsiConsole.MarkupLine("[green]✓ CAP file loaded successfully[/]");

                            if (result.PackageAid != null)
                            {
                                AnsiConsole.MarkupLine(
                                    $"[green]Package AID:[/] {Convert.ToHexString(result.PackageAid)}"
                                );

                                if (settings.ShowDetails)
                                {
                                    // TODO: Show package details when available
                                    AnsiConsole.MarkupLine(
                                        "[dim]Use 'applet list --filter packages' to see loaded packages[/]"
                                    );
                                }
                            }
                        }
                        else
                        {
                            AnsiConsole.MarkupLine($"[red]✗ Load failed: {result.ErrorMessage}[/]");
                            return 1;
                        }

                        return 0;
                    });

                return 0;
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Error loading CAP file: {ex.Message}[/]");
                if (settings.Verbose)
                {
                    AnsiConsole.WriteException(ex);
                }
                return 1;
            }
        }

        /// <summary>
        /// Settings for the load command.
        /// </summary>
        public class Settings : BaseCommandSettings
        {
            /// <summary>
            /// Gets or sets the CAP file path.
            /// </summary>
            [CommandArgument(0, "<CAP_FILE>")]
            [Description("Path to the CAP file to load")]
            public string CapFile { get; set; } = string.Empty;

            /// <summary>
            /// Gets or sets the package AID override.
            /// </summary>
            [CommandOption("--package-aid")]
            [Description("Override the package AID (hex string)")]
            [TypeConverter(typeof(HexStringTypeConverter))]
            public byte[]? PackageAid { get; set; }

            /// <summary>
            /// Gets or sets the security domain AID.
            /// </summary>
            [CommandOption("--security-domain")]
            [Description("Security domain AID for delegated management (hex string)")]
            [TypeConverter(typeof(HexStringTypeConverter))]
            public byte[]? SecurityDomain { get; set; }

            /// <summary>
            /// Gets or sets the maximum block size.
            /// </summary>
            [CommandOption("--max-block-size")]
            [Description("Maximum APDU data block size (default: 255)")]
            [DefaultValue(255)]
            public int MaxBlockSize { get; set; } = 255;

            /// <summary>
            /// Gets or sets whether to show package details.
            /// </summary>
            [CommandOption("-d|--details")]
            [Description("Show package details after loading")]
            public bool ShowDetails { get; set; }

            /// <inheritdoc />
            public override bool RequiresSecureChannel => true;

            /// <summary>
            /// Validates the command settings.
            /// </summary>
            /// <returns>Success if valid, or an error message if validation fails.</returns>
            public override ValidationResult Validate()
            {
                if (string.IsNullOrWhiteSpace(CapFile))
                {
                    return ValidationResult.Error("CAP file path is required");
                }

                if (MaxBlockSize < 1 || MaxBlockSize > 255)
                {
                    return ValidationResult.Error("Max block size must be between 1 and 255");
                }

                return ValidationResult.Success();
            }
        }
    }
}
