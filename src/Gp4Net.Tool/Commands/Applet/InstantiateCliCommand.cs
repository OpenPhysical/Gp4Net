using System;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Tool.Extensions;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Pipeline;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Applet;

/// <summary>
/// Command to instantiate an applet from a loaded package on a GlobalPlatform card.
/// </summary>
[PublicAPI]
[CliCommand("instantiate", "Instantiate an applet from a loaded package", "applet")]
[Description("Instantiate an applet from a loaded package")]
public class InstantiateCliCommand : IPipelineCommand<InstantiateCliCommand.Settings>
{
    /// <summary>
    /// Executes the instantiate command to create an applet instance from a loaded package.
    /// </summary>
    /// <param name="context">The CLI execution context.</param>
    /// <param name="settings">The command settings.</param>
    /// <returns>0 if successful, 1 if failed.</returns>
    public async Task<int> ExecuteAsync(ICliExecutionContext context, Settings settings)
    {
        return await context.ExecuteAsync(async ctx =>
        {
            var connectionResult = await ctx.RequireCardConnection(settings.GetReaderName());
            return await connectionResult.Match(
                async connectedCtx =>
                {
                    var secureChannelResult = await connectedCtx.RequireSecureChannel(
                        settings.ToSecureChannelRequest()
                    );
                    return await secureChannelResult.Match(
                        async secureCtx =>
                        {
                            AnsiConsole.MarkupLine("[cyan]Instantiating applet[/]");
                            AnsiConsole.MarkupLine($"[dim]Package AID: {settings.PackageAid}[/]");
                            AnsiConsole.MarkupLine($"[dim]Applet AID: {settings.AppletAid}[/]");

                            if (!string.IsNullOrEmpty(settings.InstanceAid))
                            {
                                AnsiConsole.MarkupLine(
                                    $"[dim]Instance AID: {settings.InstanceAid}[/]"
                                );
                            }

                            if (!settings.NoCardInfo)
                            {
                                await DisplayCardInfoAsync(secureCtx);
                            }

                            AnsiConsole.MarkupLine(
                                "[yellow]Warning:[/] Applet instantiation is not yet implemented"
                            );
                            AnsiConsole.MarkupLine(
                                "[dim]This feature will be available in a future release[/]"
                            );

                            if (settings.ShowSteps)
                            {
                                AnsiConsole.WriteLine();
                                AnsiConsole.MarkupLine("[blue]Installation steps:[/]");
                                AnsiConsole.MarkupLine("1. Select Security Domain");
                                AnsiConsole.MarkupLine("2. INSTALL [for install] command");
                                AnsiConsole.MarkupLine($"   - Package AID: {settings.PackageAid}");
                                AnsiConsole.MarkupLine($"   - Applet AID: {settings.AppletAid}");
                                AnsiConsole.MarkupLine(
                                    $"   - Instance AID: {settings.InstanceAid ?? settings.AppletAid}"
                                );

                                if (settings.Privileges.Any())
                                {
                                    AnsiConsole.MarkupLine(
                                        $"   - Privileges: {string.Join(", ", settings.Privileges)}"
                                    );
                                }

                                if (!string.IsNullOrEmpty(settings.InstallParams))
                                {
                                    AnsiConsole.MarkupLine(
                                        $"   - Parameters: {settings.InstallParams}"
                                    );
                                }

                                if (settings.MakeSelectable)
                                {
                                    AnsiConsole.WriteLine();
                                    AnsiConsole.MarkupLine(
                                        "3. INSTALL [for make selectable] command"
                                    );
                                    AnsiConsole.MarkupLine(
                                        $"   - Instance AID: {settings.InstanceAid ?? settings.AppletAid}"
                                    );
                                }
                            }

                            return await Task.FromResult(0);
                        },
                        async secureChannelError =>
                        {
                            AnsiConsole.MarkupLine(
                                $"[red]Secure channel error: {secureChannelError.Message}[/]"
                            );
                            return await Task.FromResult(1);
                        }
                    );
                },
                async connectionError =>
                {
                    AnsiConsole.MarkupLine($"[red]Connection error: {connectionError.Message}[/]");
                    return await Task.FromResult(1);
                }
            );
        });
    }

    private static Task DisplayCardInfoAsync(ICliExecutionContext context)
    {
        context.Display.Info("Card information display would go here");
        return Task.CompletedTask;
    }

    /// <summary>
    /// Settings for the instantiate command.
    /// </summary>
    public class Settings : BaseCommandSettings
    {
        /// <summary>
        /// Gets or sets the package AID.
        /// </summary>
        [CommandArgument(0, "<PACKAGE_AID>")]
        [Description("AID of the loaded package (hex string)")]
        public string PackageAid { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the applet AID.
        /// </summary>
        [CommandArgument(1, "<APPLET_AID>")]
        [Description("AID of the applet class in the package (hex string)")]
        public string AppletAid { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the instance AID.
        /// </summary>
        [CommandOption("--instance-aid")]
        [Description("Instance AID (defaults to applet AID)")]
        public string? InstanceAid { get; set; }

        /// <summary>
        /// Gets or sets the privileges.
        /// </summary>
        [CommandOption("--privileges")]
        [Description("Comma-separated list of privileges")]
        public string[] Privileges { get; set; } = Array.Empty<string>();

        /// <summary>
        /// Gets or sets the installation parameters.
        /// </summary>
        [CommandOption("--install-params")]
        [Description("Installation parameters (hex string)")]
        public string? InstallParams { get; set; }

        /// <summary>
        /// Gets or sets whether to make the applet selectable.
        /// </summary>
        [CommandOption("--make-selectable")]
        [Description("Make the applet selectable after installation")]
        [DefaultValue(true)]
        public bool MakeSelectable { get; set; } = true;

        /// <summary>
        /// Gets or sets whether to show installation steps.
        /// </summary>
        [CommandOption("--show-steps")]
        [Description("Show detailed installation steps")]
        public bool ShowSteps { get; set; }

        /// <summary>
        /// Gets or sets whether to skip card info display.
        /// </summary>
        [CommandOption("--no-card-info")]
        [Description("Skip card information display")]
        public bool NoCardInfo { get; set; }

        /// <inheritdoc />
        public override bool RequiresSecureChannel => true;

        /// <summary>
        /// Validates the command settings.
        /// </summary>
        /// <returns>Success if valid, or an error message if validation fails.</returns>
        public override ValidationResult Validate()
        {
            if (string.IsNullOrWhiteSpace(PackageAid))
            {
                return ValidationResult.Error("Package AID is required");
            }

            if (string.IsNullOrWhiteSpace(AppletAid))
            {
                return ValidationResult.Error("Applet AID is required");
            }

            try
            {
                _ = Convert.FromHexString(PackageAid.Replace(" ", ""));
            }
            catch
            {
                return ValidationResult.Error("Package AID must be a valid hex string");
            }

            try
            {
                _ = Convert.FromHexString(AppletAid.Replace(" ", ""));
            }
            catch
            {
                return ValidationResult.Error("Applet AID must be a valid hex string");
            }

            if (!string.IsNullOrEmpty(InstanceAid))
            {
                try
                {
                    _ = Convert.FromHexString(InstanceAid.Replace(" ", ""));
                }
                catch
                {
                    return ValidationResult.Error("Instance AID must be a valid hex string");
                }
            }

            if (!string.IsNullOrEmpty(InstallParams))
            {
                try
                {
                    _ = Convert.FromHexString(InstallParams.Replace(" ", ""));
                }
                catch
                {
                    return ValidationResult.Error("Install parameters must be a valid hex string");
                }
            }

            var validPrivileges = new[]
            {
                "security-domain",
                "dap-verification",
                "delegated-management",
                "card-lock",
                "card-terminate",
                "card-reset",
                "cvm-management",
                "mandated-dap",
                "trusted-path",
                "authorized-management",
                "token-verification",
                "global-delete",
                "global-lock",
                "global-registry",
                "final-application",
                "global-service",
                "receipt-generation",
                "ciphered-load-file",
            };

            foreach (var privilege in Privileges)
            {
                if (!validPrivileges.Contains(privilege.ToLowerInvariant()))
                {
                    return ValidationResult.Error($"Invalid privilege: {privilege}");
                }
            }

            return ValidationResult.Success();
        }
    }
}
