using System;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Tool.Pipeline;
using JetBrains.Annotations;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Card
{
    /// <summary>
    /// Functional implementation of the connect command demonstrating pure error handling.
    /// </summary>
    [PublicAPI]
    [CommandHandler(Description = "Connect to a smart card (functional version)")]
    public class FunctionalConnectCommand : IPipelineCommand<FunctionalConnectCommand.Settings>
    {
        /// <summary>
        /// Executes the connect command using functional patterns without exceptions.
        /// </summary>
        public async Task<int> ExecuteAsync(ICliExecutionContext context, Settings settings)
        {
            return await context.ExecuteCardCommandFunctional(
                settings,
                async ctx => await ConnectAndGetCardInfoAsync(ctx));
        }

        private static async Task<Result<bool, string>> ConnectAndGetCardInfoAsync(
            ICliExecutionContext context)
        {
            context.Display.Success("Successfully connected to card");

            // Try to select ISD and get basic card information
            var gpService = context.GetGlobalPlatformService();
            var selectResult = await gpService.SelectIsdAsync();

            if (selectResult.IsSuccess)
            {
                var response = selectResult.Value;
                if (response.Fci?.ApplicationAid != null)
                {
                    context.Display.Info($"ISD AID: {Convert.ToHexString(response.Fci.ApplicationAid)}");
                }
                if (response.RawData != null && response.RawData.Length > 0)
                {
                    context.Display.Info($"Response Data: {Convert.ToHexString(response.RawData)}");
                }
                return Result.Success<bool, string>(true);
            }
            else
            {
                context.Display.Warning($"Could not select ISD: {selectResult.Error.Message}");
                // Still consider connection successful even if ISD selection fails
                return Result.Success<bool, string>(true);
            }
        }

        /// <summary>
        /// Settings for the functional connect command.
        /// </summary>
        public class Settings : BaseCommandSettings
        {
            // Connect command doesn't require secure channel by default
        }
    }
}