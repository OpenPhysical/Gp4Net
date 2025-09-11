using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Pipeline;
using JetBrains.Annotations;
using WSCT.ISO7816;

namespace Gp4Net.Services.GlobalPlatform;

/// <summary>
/// Card lifecycle and management operations.
/// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.4, 11.8
/// </summary>
[PublicAPI]
public static class CardManagement
{
    /// <summary>
    /// Deletes an application from the card.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.8
    /// </summary>
    public static async Task<Result<bool, SmartCardError>> DeleteApplicationAsync(
        byte[] aid,
        bool deleteRelated,
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken = default
    )
    {
        var cmdResult = Commands.CreateDeleteCommand(aid, deleteRelated);

        if (cmdResult.IsFailure)
        {
            return Result.Failure<bool, SmartCardError>(cmdResult.Error);
        }

        return await cmdResult
            .Bind(cmd => cmd.ToCommandApdu())
            .Bind(async commandApdu => await executeCommand(commandApdu, cancellationToken))
            .Bind(response => Responses.ParseDeleteResponse(response));
    }

    /// <summary>
    /// Sets the lifecycle state of a card or application.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.4
    /// </summary>
    public static async Task<Result<bool, SmartCardError>> SetLifecycleStateAsync(
        byte[] aid,
        byte p1,
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken = default
    )
    {
        var cmdResult = Commands.CreateSetStatusCommand(aid, p1);

        if (cmdResult.IsFailure)
        {
            return Result.Failure<bool, SmartCardError>(cmdResult.Error);
        }

        return await cmdResult
            .Bind(cmd => cmd.ToCommandApdu())
            .Bind(async commandApdu => await executeCommand(commandApdu, cancellationToken))
            .Map(response =>
                response.IsSuccess
                    ? Result.Success<bool, SmartCardError>(true)
                    : Result.Failure<bool, SmartCardError>(
                        SmartCardError.CardError(
                            $"SET STATUS failed with SW: {response.StatusWord:X4}"
                        )
                    )
            )
            .Bind(result => result);
    }
}
