using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.CapFile;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Pipeline;
using Gp4Net.Tool.Extensions;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Applet;

[PublicAPI]
[CliCommand("load", "Load a CAP file package without installing applets", "applet")]
public sealed class LoadCommand : IPipelineCommand<LoadCommand.Settings>
{
    public Task<int> ExecuteAsync(ICliExecutionContext context, Settings settings) =>
        context.ExecuteAsync(ctx => ExecuteCoreAsync(ctx, settings));

    private static async Task<int> ExecuteCoreAsync(ICliExecutionContext context, Settings settings)
    {
        byte[] capData;
        try { capData = await File.ReadAllBytesAsync(settings.CapFile); }
        catch (Exception exception)
        {
            context.Display.Error($"Unable to read CAP file: {exception.Message}");
            return 1;
        }
        var parsed = CapFileStructure.Parse(capData);
        if (parsed.IsFailure)
        {
            context.Display.Error($"Invalid CAP file: {parsed.Error.Message}");
            return 1;
        }
        if (settings.PackageAid is { Length: > 0 }
            && !settings.PackageAid.AsSpan().SequenceEqual(parsed.Value.PackageAid))
        {
            context.Display.Error("--package-aid must match the package AID encoded in the CAP file.");
            return 1;
        }
        bool delegated = settings.LoadToken is { Length: > 0 } || settings.LoadTokenKey is { Length: > 0 };
        bool dap = settings.DapSecurityDomain is { Length: > 0 } && settings.DapKey is { Length: > 0 };
        Result<DelegatedLoadOptions, SmartCardError> options = delegated ? CreateOptions(settings) : default;
        if (delegated && options.IsFailure)
        {
            context.Display.Error(options.Error.Message);
            return 1;
        }
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
        if (!delegated && dap)
        {
            var dapResult = await Gp4Net.Services.GlobalPlatform.CardManagement.LoadCapFileWithDapAsync(
                capData, settings.DapSecurityDomain!, settings.DapKey!,
                settings.SecurityDomain is { Length: > 0 } ? Maybe<byte[]>.From(settings.SecurityDomain) : Maybe<byte[]>.None,
                settings.LoadParameters is { Length: > 0 } ? Maybe<byte[]>.From(settings.LoadParameters) : Maybe<byte[]>.None,
                settings.MaxBlockSize,
                (command, cancellationToken) => secure.Value.CardService.ExecuteCommandAsync(command, true, cancellationToken),
                CancellationToken.None);
            return dapResult.Match(success =>
            {
                context.Display.Success($"Loaded package {Convert.ToHexString(success.PackageAid)} with AES DAP");
                if (settings.ShowDetails)
                    context.Display.Info($"LFDBH: {Convert.ToHexString(success.LoadFileDataBlockHash)}");
                return 0;
            }, (SmartCardError error) => { context.Display.Error($"Load failed: {error.Message}"); return 1; });
        }
        if (!delegated)
        {
            var ordinary = await Gp4Net.Services.GlobalPlatform.CardManagement.InstallCapFileAsync(
                capData,
                settings.SecurityDomain is { Length: > 0 }
                    ? Maybe<byte[]>.From(settings.SecurityDomain)
                    : Maybe<byte[]>.None,
                false,
                false,
                (command, cancellationToken) => secure.Value.CardService.ExecuteCommandAsync(command, true, cancellationToken),
                CancellationToken.None);
            return ordinary.Match(success =>
            {
                context.Display.Success($"Loaded package {Convert.ToHexString(success.PackageAid)}");
                return 0;
            }, (SmartCardError error) =>
            {
                context.Display.Error($"Load failed: {error.Message}");
                return 1;
            });
        }
        var result = await Gp4Net.Services.GlobalPlatform.CardManagement.LoadCapFileAsync(
            capData, options.Value, settings.MaxBlockSize,
            (command, cancellationToken) => secure.Value.CardService.ExecuteCommandAsync(command, true, cancellationToken),
            CancellationToken.None);
        return result.Match(success =>
        {
            context.Display.Success($"Loaded package {Convert.ToHexString(success.PackageAid)}");
            if (settings.ShowDetails)
            {
                context.Display.Info($"LFDBH: {Convert.ToHexString(success.LoadFileDataBlockHash)}");
                context.Display.Info($"Load Token: {Convert.ToHexString(success.LoadToken)}");
            }
            success.Confirmation.Execute(confirmation =>
            {
                context.Display.Info($"Receipt: {Convert.ToHexString(confirmation.Receipt)}");
                context.Display.Info($"Confirmation Counter: {confirmation.ConfirmationCounter}");
                context.Display.Info($"SD Unique Data: {Convert.ToHexString(confirmation.SecurityDomainUniqueData)}");
                confirmation.TokenDataDigest.Execute(digest =>
                    context.Display.Info($"Token Data Digest: {Convert.ToHexString(digest)}"));
            });
            return 0;
        }, (SmartCardError error) =>
        {
            context.Display.Error($"Load failed: {error.Message}");
            return 1;
        });
    }

    internal static Result<DelegatedLoadOptions, SmartCardError> CreateOptions(Settings settings)
    {
        DelegatedLoadTokenSource source = settings.LoadToken is { Length: > 0 }
            ? new DelegatedLoadTokenSource.Precomputed(settings.LoadToken)
            : new DelegatedLoadTokenSource.AesKey(settings.LoadTokenKey ?? []);
        return DelegatedLoadOptions.Create(settings.SecurityDomain ?? [], source,
            settings.LoadParameters, settings.DapSecurityDomain, settings.DapKey);
    }

    public sealed class Settings : SecureCommandSettings
    {
        [CommandArgument(0, "<CAP_FILE>")]
        public string CapFile { get; set; } = string.Empty;
        [CommandOption("--package-aid")]
        [TypeConverter(typeof(HexStringTypeConverter))]
        public byte[]? PackageAid { get; set; }
        [CommandOption("--security-domain")]
        [TypeConverter(typeof(HexStringTypeConverter))]
        public byte[]? SecurityDomain { get; set; }
        [CommandOption("--load-token")]
        [TypeConverter(typeof(HexStringTypeConverter))]
        public byte[]? LoadToken { get; set; }
        [CommandOption("--load-token-key")]
        [TypeConverter(typeof(HexStringTypeConverter))]
        public byte[]? LoadTokenKey { get; set; }
        [CommandOption("--load-parameters")]
        [TypeConverter(typeof(HexStringTypeConverter))]
        public byte[]? LoadParameters { get; set; }
        [CommandOption("--dap-security-domain")]
        [TypeConverter(typeof(HexStringTypeConverter))]
        public byte[]? DapSecurityDomain { get; set; }
        [CommandOption("--dap-key")]
        [TypeConverter(typeof(HexStringTypeConverter))]
        public byte[]? DapKey { get; set; }
        [CommandOption("--max-block-size")]
        [DefaultValue(Constants.Constants.GlobalPlatform.ApduLimits.DEFAULT_LOAD_BLOCK_SIZE)]
        public int MaxBlockSize { get; set; } =
            Constants.Constants.GlobalPlatform.ApduLimits.DEFAULT_LOAD_BLOCK_SIZE;
        [CommandOption("--details")]
        public bool ShowDetails { get; set; }
        [CommandOption("--no-card-info")]
        public bool NoCardInfo { get; set; }

        public override ValidationResult Validate()
        {
            if (string.IsNullOrWhiteSpace(CapFile))
                return ValidationResult.Error("CAP file path is required.");
            if (MaxBlockSize is < 1 or > 255)
                return ValidationResult.Error("Max block size must be between 1 and 255.");
            bool hasToken = LoadToken is { Length: > 0 };
            bool hasKey = LoadTokenKey is { Length: > 0 };
            if (hasToken && hasKey)
                return ValidationResult.Error("--load-token and --load-token-key are mutually exclusive.");
            if ((hasToken || hasKey) && SecurityDomain is not { Length: > 0 })
                return ValidationResult.Error("--security-domain is required for delegated loading.");
            if ((DapSecurityDomain is { Length: > 0 }) != (DapKey is { Length: > 0 }))
                return ValidationResult.Error("--dap-security-domain and --dap-key must be supplied together.");
            return base.Validate();
        }
    }
}
