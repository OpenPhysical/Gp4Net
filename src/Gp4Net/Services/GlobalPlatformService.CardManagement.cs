// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Pipeline;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Services;

public static partial class GlobalPlatformService
{
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
            Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
            CancellationToken cancellationToken = default
        )
        {
            var cmdResult = Commands.CreateDeleteCommand(aid, deleteRelated);
            
            if (cmdResult.IsFailure)
            {
                return Result.Failure<bool, SmartCardError>(cmdResult.Error);
            }

            var cmd = cmdResult.Value;
            var response = await executeCommand(cmd, cancellationToken);
            
            if (response.IsFailure)
            {
                return Result.Failure<bool, SmartCardError>(response.Error);
            }
            
            return Responses.ParseDeleteResponse(response.Value);
        }

        /// <summary>
        /// Sets the lifecycle state of a card or application.
        /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.4
        /// </summary>
        public static async Task<Result<bool, SmartCardError>> SetLifecycleStateAsync(
            byte[] aid,
            byte p1,
            Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
            CancellationToken cancellationToken = default
        )
        {
            var cmdResult = Commands.CreateSetStatusCommand(aid, p1);
            
            if (cmdResult.IsFailure)
            {
                return Result.Failure<bool, SmartCardError>(cmdResult.Error);
            }

            var cmd = cmdResult.Value;
            var response = await executeCommand(cmd, cancellationToken);
            
            if (response.IsFailure)
            {
                return Result.Failure<bool, SmartCardError>(response.Error);
            }
            
            var responseValue = response.Value;
            return responseValue.IsSuccess
                ? Result.Success<bool, SmartCardError>(true)
                : Result.Failure<bool, SmartCardError>(
                    SmartCardError.CardError($"SET STATUS failed with SW: {responseValue.StatusWord:X4}")
                );
        }
    }
}