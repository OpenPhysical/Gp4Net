using System;
using System.Threading.Tasks;
using Gp4Net.Tool.Pipeline;
using JetBrains.Annotations;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Card
{
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
        public async Task<int> ExecuteAsync(ICommandContext context, Settings settings)
        {
            return await context.ExecuteCardCommand(
                settings,
                async ctx =>
                {
                    ctx.Display.Success("Successfully connected to card");

                    // Try to select ISD and get basic card information
                    try
                    {
                        var selectResult = await ctx.GlobalPlatformService.SelectIsdAsync();
                        
                        await selectResult.MatchAsync<object>(
                            selectResponse =>
                            {
                                ctx.Display.Success("✓ ISD successfully selected");

                                if (selectResponse.RawData != null && selectResponse.RawData.Length > 0)
                                {
                                    ctx.Display.Verbose(
                                        $"Response data: {Convert.ToHexString(selectResponse.RawData)}"
                                    );
                                }

                                if (
                                    selectResponse.Fci?.CardData != null
                                    && selectResponse.Fci.CardData.Length > 0
                                )
                                {
                                    ctx.Display.Verbose(
                                        $"Card data: {Convert.ToHexString(selectResponse.Fci.CardData)}"
                                    );
                                }
                                return Task.FromResult<object>(null!);
                            },
                            error =>
                            {
                                ctx.Display.Warning($"Could not select ISD: {error.Message}");
                                return Task.FromResult<object>(null!);
                            });
                    }
                    catch (Exception ex)
                    {
                        ctx.Display.Warning($"Error selecting ISD: {ex.Message}");
                    }

                    return 0;
                }
            );
        }

        /// <summary>
        /// Settings for the connect command.
        /// </summary>
        public class Settings : CardCommandSettings { }
    }
}
