using System;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Services.Helpers;
using Gp4Net.Tool.Extensions;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Pipeline;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;
using GlobalPlatformConstants = Gp4Net.Constants.Constants.GlobalPlatform;

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

                            if (settings.ShowSteps)
                            {
                                AnsiConsole.WriteLine();
                                AnsiConsole.MarkupLine("[blue]Installation steps:[/]");
                                AnsiConsole.MarkupLine("1. Select Security Domain");
                                AnsiConsole.WriteLine("2. INSTALL [for install] command");
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
                                    AnsiConsole.WriteLine(
                                        "3. INSTALL [for make selectable] command"
                                    );
                                    AnsiConsole.MarkupLine(
                                        $"   - Instance AID: {settings.InstanceAid ?? settings.AppletAid}"
                                    );
                                }
                            }

                            var commandResult = CreateInstallCommand(settings);
                            if (commandResult.IsFailure)
                            {
                                secureCtx.Display.Error(commandResult.Error.Message);
                                return 1;
                            }

                            var apduResult = commandResult.Value.ToCommandApdu();
                            if (apduResult.IsFailure)
                            {
                                secureCtx.Display.Error(apduResult.Error.Message);
                                return 1;
                            }

                            var responseResult = await secureCtx.CardService.ExecuteCommandAsync(
                                apduResult.Value,
                                useSecureChannel: true
                            );
                            return responseResult.Match(
                                response =>
                                {
                                    if (!response.IsSuccess)
                                    {
                                        secureCtx.Display.Error(
                                            $"INSTALL [for install] failed with SW: {response.StatusWord:X4}"
                                        );
                                        return 1;
                                    }

                                    secureCtx.Display.Success("Applet instantiated successfully");
                                    return 0;
                                },
                                error =>
                                {
                                    secureCtx.Display.Error(error.Message);
                                    return 1;
                                }
                            );
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

    internal static Result<
        InstallCommand.InstallForInstallCommand,
        SmartCardError
    > CreateInstallCommand(Settings settings)
    {
        byte[] packageAid = Convert.FromHexString(settings.PackageAid.Replace(" ", ""));
        byte[] moduleAid = Convert.FromHexString(settings.AppletAid.Replace(" ", ""));
        byte[] instanceAid = Convert.FromHexString(
            (settings.InstanceAid ?? settings.AppletAid).Replace(" ", "")
        );
        byte[] privilegeBytes = ParsePrivileges(settings.Privileges).ToBytesCompact();
        Maybe<byte[]> installParameters = string.IsNullOrWhiteSpace(settings.InstallParams)
            ? Maybe<byte[]>.None
            : Maybe<byte[]>.From(WrapApplicationParameters(settings.InstallParams));

        return settings.MakeSelectable
            ? InstallCommand.InstallForInstallCommand.CreateAndMakeSelectable(
                packageAid,
                moduleAid,
                instanceAid,
                privilegeBytes,
                installParameters
            )
            : InstallCommand.InstallForInstallCommand.Create(
                packageAid,
                moduleAid,
                instanceAid,
                privilegeBytes,
                installParameters
            );
    }

    private static GlobalPlatformConstants.Privilege ParsePrivileges(string[] names)
    {
        GlobalPlatformConstants.Privilege value = GlobalPlatformConstants.Privilege.None;
        foreach (string name in ExpandPrivileges(names))
        {
            string enumName = name.ToLowerInvariant() switch
            {
                "mandated-dap" => nameof(GlobalPlatformConstants.Privilege.MandatedDapVerification),
                "ciphered-load-file" => nameof(GlobalPlatformConstants.Privilege.CipheredLoadFileDataBlock),
                _ => name.Replace("-", ""),
            };
            if (Enum.TryParse(enumName, ignoreCase: true, out GlobalPlatformConstants.Privilege parsed))
                value |= parsed;
        }
        return value;
    }

    private static string[] ExpandPrivileges(string[] names) =>
        names.SelectMany(name =>
                name.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            )
            .ToArray();

    private static byte[] WrapApplicationParameters(string parameters)
    {
        byte[] value = Convert.FromHexString(parameters.Replace(" ", ""));
        return
        [
            0xC9,
            .. EncodeBerLength(value.Length),
            .. value,
        ];
    }

    private static byte[] EncodeBerLength(int length) =>
        length switch
        {
            < 0x80 => [(byte)length],
            <= 0xFF => [0x81, (byte)length],
            <= 0xFFFF => [0x82, (byte)(length >> 8), (byte)length],
            _ => throw new ArgumentOutOfRangeException(
                nameof(length),
                "Install parameters exceed the supported BER length"
            ),
        };

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

            foreach (var privilege in ExpandPrivileges(Privileges))
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
