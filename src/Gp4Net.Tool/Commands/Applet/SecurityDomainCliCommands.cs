using System;
using System.ComponentModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Services.GlobalPlatform;
using Gp4Net.Tool.Extensions;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Pipeline;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Applet;

/// <summary>
/// Creates a supplementary Security Domain through INSTALL [for install and make selectable].
/// See GlobalPlatform Card Specification v2.3.1, sections 6.6.3 and 11.5.2.3.2.
/// </summary>
[CliCommand("create-ssd", "Create a supplementary Security Domain", "applet")]
public sealed class CreateSsdCliCommand : IPipelineCommand<CreateSsdCliCommand.Settings>
{
    /// <inheritdoc />
    public async Task<int> ExecuteAsync(ICliExecutionContext context, Settings settings)
    {
        var connection = await context.RequireCardConnection(settings.GetReaderName());
        if (connection.IsFailure)
        {
            context.Display.Error(connection.Error.Message);
            return 1;
        }

        var secure = await connection.Value.RequireSecureChannel(settings.ToSecureChannelRequest());
        if (secure.IsFailure)
        {
            context.Display.Error(secure.Error.Message);
            return 1;
        }

        // Section 6.6.3 requires every supplementary Security Domain registry
        // entry to carry the Security Domain privilege.
        var install = InstantiateCliCommand.CreateInstallCommand(
            new InstantiateCliCommand.Settings
            {
                PackageAid = settings.PackageAid,
                AppletAid = settings.ModuleAid,
                InstanceAid = settings.SecurityDomainAid,
                Privileges = ["security-domain", .. settings.Privileges],
                InstallParams = settings.InstallParameters,
                MakeSelectable = true,
            }
        );
        if (install.IsFailure)
        {
            context.Display.Error(install.Error.Message);
            return 1;
        }

        byte[] privilegeBytes = install.Value.Privileges.ToArray();
        Maybe<byte[]> parameters = string.IsNullOrWhiteSpace(settings.InstallParameters)
            ? Maybe<byte[]>.None
            : Maybe<byte[]>.From(WrapParameters(settings.InstallParameters));
        var result = await CardManagement.CreateSupplementarySecurityDomainAsync(
            ParseHex(settings.PackageAid),
            ParseHex(settings.ModuleAid),
            ParseHex(settings.SecurityDomainAid),
            privilegeBytes,
            parameters,
            (command, cancellationToken) =>
                secure.Value.CardService.ExecuteCommandAsync(command, true, cancellationToken),
            CancellationToken.None
        );
        return result.Match(
            _ =>
            {
                context.Display.Success($"Created Security Domain {settings.SecurityDomainAid}");
                return 0;
            },
            error =>
            {
                context.Display.Error(error.Message);
                return 1;
            }
        );
    }

    private static byte[] ParseHex(string value) => Convert.FromHexString(value.Replace(" ", ""));
    private static byte[] WrapParameters(string value)
    {
        byte[] bytes = ParseHex(value);

        // Table 11-43 carries system-specific installation parameters in C9.
        return bytes.Length < 0x80
            ? [0xC9, (byte)bytes.Length, .. bytes]
            : [0xC9, 0x81, (byte)bytes.Length, .. bytes];
    }

    public sealed class Settings : BaseCommandSettings
    {
        [CommandArgument(0, "<SECURITY_DOMAIN_AID>")]
        public string SecurityDomainAid { get; set; } = string.Empty;
        [CommandOption("--package-aid")]
        [DefaultValue("A0000001515350")]
        public string PackageAid { get; set; } = "A0000001515350";
        [CommandOption("--module-aid")]
        [DefaultValue("A000000151535041")]
        public string ModuleAid { get; set; } = "A000000151535041";
        [CommandOption("--privileges")]
        public string[] Privileges { get; set; } = [];
        [CommandOption("--install-parameters")]
        public string? InstallParameters { get; set; }
        public override bool RequiresSecureChannel => true;
        public override ValidationResult Validate()
        {
            try
            {
                foreach (string value in new[] { SecurityDomainAid, PackageAid, ModuleAid })
                    if (ParseHex(value).Length is < 5 or > 16)
                        return ValidationResult.Error("AIDs must contain 5 to 16 bytes");
                if (!string.IsNullOrWhiteSpace(InstallParameters) && ParseHex(InstallParameters).Length > 255)
                    return ValidationResult.Error("Install parameters must not exceed 255 bytes");
            }
            catch (FormatException)
            {
                return ValidationResult.Error("AIDs and parameters must be hexadecimal");
            }

            return base.Validate();
        }
    }
}

/// <summary>
/// Changes an application's associated Security Domain through INSTALL [for extradition].
/// See GlobalPlatform Card Specification v2.3.1, section 11.5.2.3.4 and Table 11-45.
/// </summary>
[CliCommand("extradite", "Move an application to another Security Domain", "applet")]
public sealed class ExtraditeCliCommand : IPipelineCommand<ExtraditeCliCommand.Settings>
{
    /// <inheritdoc />
    public async Task<int> ExecuteAsync(ICliExecutionContext context, Settings settings)
    {
        var connection = await context.RequireCardConnection(settings.GetReaderName());
        if (connection.IsFailure)
        {
            context.Display.Error(connection.Error.Message);
            return 1;
        }

        var secure = await connection.Value.RequireSecureChannel(settings.ToSecureChannelRequest());
        if (secure.IsFailure)
        {
            context.Display.Error(secure.Error.Message);
            return 1;
        }

        var result = await CardManagement.ExtraditeApplicationAsync(
            Convert.FromHexString(settings.ApplicationAid),
            Convert.FromHexString(settings.TargetSecurityDomainAid),
            Maybe<byte[]>.None,
            Maybe<byte[]>.None,
            (command, cancellationToken) =>
                secure.Value.CardService.ExecuteCommandAsync(command, true, cancellationToken),
            CancellationToken.None
        );
        return result.Match(
            _ =>
            {
                context.Display.Success($"Extradited {settings.ApplicationAid}");
                return 0;
            },
            error =>
            {
                context.Display.Error(error.Message);
                return 1;
            }
        );
    }

    public sealed class Settings : BaseCommandSettings
    {
        [CommandArgument(0, "<APPLICATION_AID>")]
        public string ApplicationAid { get; set; } = string.Empty;
        [CommandOption("--to <SECURITY_DOMAIN_AID>")]
        public string TargetSecurityDomainAid { get; set; } = string.Empty;
        public override bool RequiresSecureChannel => true;
        public override ValidationResult Validate()
        {
            try
            {
                if (Convert.FromHexString(ApplicationAid).Length is < 5 or > 16
                    || Convert.FromHexString(TargetSecurityDomainAid).Length is < 5 or > 16)
                    return ValidationResult.Error("AIDs must contain 5 to 16 bytes");
            }
            catch (FormatException)
            {
                return ValidationResult.Error("AIDs must be hexadecimal");
            }

            return base.Validate();
        }
    }
}
