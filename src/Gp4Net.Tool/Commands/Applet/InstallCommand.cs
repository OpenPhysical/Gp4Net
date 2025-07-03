using System;
using System.ComponentModel;
using System.IO;
using System.Threading.Tasks;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Applet
{
    /// <summary>
    /// Command to install a CAP file on the card.
    /// </summary>
    [PublicAPI]
    public class InstallCommand : BaseCommand<InstallCommand.Settings>
    {
        /// <summary>
        /// Initializes a new instance of the InstallCommand class.
        /// </summary>
        public InstallCommand(
            ICardService cardService,
            IGlobalPlatformService globalPlatformService,
            IKeysetResolver keysetResolver
        )
            : base(cardService, globalPlatformService, keysetResolver) { }

        /// <summary>
        /// Executes the install command to load and install a CAP file on the card.
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

            // Establish secure channel for installation
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
                        var task = ctx.AddTask("[green]Installing CAP file[/]");
                        task.MaxValue = 100;

                        // Simulate progress during installation
                        task.Value = 10;
                        await Task.Delay(100);

                        var result = GlobalPlatformService.InstallCapFile(
                            capFileData,
                            settings.InstallApplets,
                            settings.MakeSelectable
                        );

                        task.Value = 100;

                        if (result.IsSuccessful)
                        {
                            AnsiConsole.MarkupLine("[green]✓ CAP file installed successfully[/]");

                            if (result.PackageAid != null)
                            {
                                AnsiConsole.MarkupLine(
                                    $"[dim]Package AID: {Convert.ToHexString(result.PackageAid)}[/]"
                                );
                            }

                            if (result.InstalledApplets.Count > 0)
                            {
                                AnsiConsole.MarkupLine(
                                    $"[green]Installed {result.InstalledApplets.Count} applet(s):[/]"
                                );
                                foreach (var appletAid in result.InstalledApplets)
                                {
                                    AnsiConsole.MarkupLine(
                                        $"  [dim]• {Convert.ToHexString(appletAid)}[/]"
                                    );
                                }
                            }
                        }
                        else
                        {
                            AnsiConsole.MarkupLine(
                                $"[red]✗ Installation failed: {result.ErrorMessage}[/]"
                            );
                            return 1;
                        }

                        return 0;
                    });

                return 0;
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Error installing CAP file: {ex.Message}[/]");
                if (settings.Verbose)
                {
                    AnsiConsole.WriteException(ex);
                }
                return 1;
            }
        }

        /// <summary>
        /// Settings for the install command.
        /// </summary>
        public class Settings : BaseCommandSettings
        {
            /// <summary>
            /// Gets or sets the CAP file path.
            /// </summary>
            [CommandArgument(0, "<CAP_FILE>")]
            [Description("Path to the CAP file to install")]
            public string CapFile { get; set; } = string.Empty;

            /// <summary>
            /// Gets or sets a value indicating whether to install applets.
            /// </summary>
            [CommandOption("--no-install-applets")]
            [Description("Don't install applets after loading the package")]
            public bool NoInstallApplets { get; set; }

            /// <summary>
            /// Gets a value indicating whether to install applets.
            /// </summary>
            public bool InstallApplets => !NoInstallApplets;

            /// <summary>
            /// Gets or sets a value indicating whether to make applets selectable.
            /// </summary>
            [CommandOption("--no-make-selectable")]
            [Description("Don't make applets selectable after installation")]
            public bool NoMakeSelectable { get; set; }

            /// <summary>
            /// Gets a value indicating whether to make applets selectable.
            /// </summary>
            public bool MakeSelectable => !NoMakeSelectable;

            /// <inheritdoc />
            public override bool RequiresSecureChannel => true; // Installation always requires secure channel

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

                return ValidationResult.Success();
            }
        }
    }
}
