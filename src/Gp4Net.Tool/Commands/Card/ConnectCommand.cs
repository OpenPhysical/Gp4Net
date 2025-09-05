using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Services;
using Gp4Net.Services.GlobalPlatform;
using Gp4Net.Tool.Pipeline;
using JetBrains.Annotations;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Card;

/// <summary>
/// Command to connect to a smart card.
/// </summary>
[PublicAPI]
[CommandHandler(Description = "Connect to a smart card")]
public class ConnectCommand : IPipelineCommand<ConnectCommand.Settings>
{
    /// <summary>
    /// Executes the connect command to establish a connection to a smart card.
    /// </summary>
    public async Task<int> ExecuteAsync(ICliExecutionContext context, Settings settings)
    {
        return await context.ExecuteCardCommandFunctional(
            settings,
            async ctx => await ConnectAndGetCardInfoAsync(ctx)
        );
    }

    /// <summary>
    /// Connects to card and retrieves basic information.
    /// </summary>
    private static async Task<Result<bool, string>> ConnectAndGetCardInfoAsync(
        ICliExecutionContext context
    )
    {
        context.Display.Success("Successfully connected to card");

        // Try to select ISD and get basic card information
        Result<SelectResponse, SmartCardError> selectResult = await Discovery.DetectAndSelectIsdAsync(
            (command, ct) => context.CardService.ExecuteCommandAsync(command, ct),
            CancellationToken.None
        );

        if (selectResult.IsSuccess)
        {
            SelectResponse response = selectResult.Value;
            context.Display.Success("✓ ISD successfully selected");

            // Display FCI information using functional pattern
            _ = response.Fci.Match(
                fci =>
                {
                    if (fci.ApplicationAid.Length > 0)
                    {
                        context.Display.Info($"ISD AID: {Convert.ToHexString(fci.ApplicationAid)}");
                    }

                    if (fci.CardData.Length > 0)
                    {
                        context.Display.Verbose($"Card data: {Convert.ToHexString(fci.CardData)}");
                    }
                    return true;
                },
                () => false
            );

            // Display raw response data in verbose mode
            if (response.RawData.Length > 0)
            {
                context.Display.Verbose($"Response data: {Convert.ToHexString(response.RawData)}");
            }
        }
        else
        {
            context.Display.Warning($"Could not select ISD: {selectResult.Error.Message}");
        }

        // Connection is still considered successful even if ISD selection fails
        return Result.Success<bool, string>(true);
    }

    /// <summary>
    /// Settings for the connect command.
    /// </summary>
    public class Settings : CommandSettings
    {
        // Connect command doesn't require secure channel by default
    }
}
