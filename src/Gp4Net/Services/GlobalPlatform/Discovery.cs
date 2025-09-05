using System;
using System.Collections.Immutable;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Pipeline;
using JetBrains.Annotations;
using WSCT.ISO7816;

namespace Gp4Net.Services.GlobalPlatform;

/// <summary>
/// Card discovery and selection operations.
/// Handles ISD detection, application selection, and key discovery.
/// Reference: GlobalPlatform Card Specification v2.3.1 Section 9.2
/// </summary>
[PublicAPI]
public static class Discovery
{
    /// <summary>
    /// Well-known Issuer Security Domain AIDs per GlobalPlatform specification.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 5.1
    /// </summary>
    private static readonly ImmutableList<byte[]> WellKnownIsdAids = ImmutableList.Create(
        Convert.FromHexString("A000000003000000"), // Standard GP ISD
        Convert.FromHexString("A000000151000000"), // Common alternative ISD
        Convert.FromHexString("A000000018434D00"), // Another common ISD variant
        [0xA0, 0x00, 0x00, 0x00, 0x03] // Shorter form sometimes used
    );

    /// <summary>
    /// Attempts to detect and select the Issuer Security Domain.
    /// First tries a direct SELECT with empty AID, then tries known ISD AIDs.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 9.2.2
    /// </summary>
    /// <param name="executeCommand">Function to execute APDU commands.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The SelectResponse from the ISD or an error.</returns>
    public static async Task<Result<SelectResponse, SmartCardError>> DetectAndSelectIsdAsync(
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken = default
    )
    {
        // First try SELECT with empty AID (standard method)
        Result<SelectCommand, SmartCardError> selectIsdResult = Commands.CreateSelectIsdCommand();
        if (selectIsdResult.IsFailure)
        {
            return Result.Failure<SelectResponse, SmartCardError>(selectIsdResult.Error);
        }

        Result<CommandResponse, SmartCardError> response = await selectIsdResult
            .Bind(selectCommand => selectCommand.ToCommandApdu())
            .Bind(async commandApdu => await executeCommand(commandApdu, cancellationToken));

        // If the transport/card returned an error, don't keep probing; propagate the failure
        if (response.IsFailure)
        {
            return Result.Failure<SelectResponse, SmartCardError>(response.Error);
        }

        if (response.IsSuccess)
        {
            Result<SelectResponse, SmartCardError> parseResult = Responses.ParseSelectResponse(
                response.Value
            );
            if (parseResult.IsSuccess)
            {
                return parseResult;
            }
        }

        // If direct ISD selection fails, try known ISD AIDs
        return await TryKnownIsdAidsAsync(executeCommand, cancellationToken);
    }

    /// <summary>
    /// Selects a specific application by AID.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.9
    /// </summary>
    /// <param name="aid">The application identifier.</param>
    /// <param name="executeCommand">Function to execute APDU commands.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The SelectResponse or an error.</returns>
    public static async Task<Result<SelectResponse, SmartCardError>> SelectApplicationAsync(
        byte[] aid,
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken = default
    )
    {
        Result<SelectCommand, SmartCardError> selectResult = Commands.CreateSelectCommand(
            aid
        );
        return await selectResult
            .Bind(selectCommand => selectCommand.ToCommandApdu())
            .Bind(async commandApdu => await executeCommand(commandApdu, cancellationToken))
            .Bind(response => Responses.ParseSelectResponse(response));
    }

    /// <summary>
    /// Discovers a working key set by trying multiple key sets.
    /// Useful when the exact key set is unknown.
    /// </summary>
    /// <param name="keySets">List of key sets to try.</param>
    /// <param name="hostChallenge">Host challenge for INITIALIZE UPDATE.</param>
    /// <param name="executeCommand">Function to execute APDU commands.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The working key set and protocol version, or an error.</returns>
    public static async Task<
        Result<(IKeySet KeySet, CryptoService.ScpVersion ProtocolVersion), SmartCardError>
    > DiscoverKeySetAsync(
        ImmutableList<IKeySet> keySets,
        byte[] hostChallenge,
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken = default
    )
    {
        return await TryKeySetsRecursively(
            keySets,
            0,
            hostChallenge,
            executeCommand,
            cancellationToken
        );
    }

    #region Private Helper Methods

    /// <summary>
    /// Tries to select ISD using known AID values.
    /// </summary>
    private static async Task<Result<SelectResponse, SmartCardError>> TryKnownIsdAidsAsync(
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken
    )
    {
        // Functional approach: try AIDs recursively
        return await TryAidsRecursively(WellKnownIsdAids, 0, executeCommand, cancellationToken);
    }

    /// <summary>
    /// Recursively tries AIDs until one succeeds.
    /// </summary>
    private static async Task<Result<SelectResponse, SmartCardError>> TryAidsRecursively(
        ImmutableList<byte[]> aids,
        int index,
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken
    )
    {
        if (index >= aids.Count)
        {
            return Result.Failure<SelectResponse, SmartCardError>(
                SmartCardError.CardError("Failed to detect Issuer Security Domain")
            );
        }

        Result<SelectCommand, SmartCardError> selectResult = Commands.CreateSelectCommand(
            aids[index]
        );
        if (selectResult.IsFailure)
        {
            return await TryAidsRecursively(aids, index + 1, executeCommand, cancellationToken);
        }

        var parseResult = await selectResult
            .Bind(selectCommand => selectCommand.ToCommandApdu())
            .Bind(async commandApdu => await executeCommand(commandApdu, cancellationToken))
            .Bind(response => Responses.ParseSelectResponse(response));

        if (parseResult.IsSuccess)
        {
            return parseResult;
        }

        return await TryAidsRecursively(aids, index + 1, executeCommand, cancellationToken);
    }

    /// <summary>
    /// Recursively tries key sets until one succeeds.
    /// </summary>
    private static async Task<
        Result<(IKeySet KeySet, CryptoService.ScpVersion ProtocolVersion), SmartCardError>
    > TryKeySetsRecursively(
        ImmutableList<IKeySet> keySets,
        int index,
        byte[] hostChallenge,
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken
    )
    {
        if (index >= keySets.Count)
        {
            return Result.Failure<(IKeySet, CryptoService.ScpVersion), SmartCardError>(
                SmartCardError.SecurityError("Failed to discover working key set")
            );
        }

        IKeySet keySet = keySets[index];
        Result<InitializeUpdateCommand, SmartCardError> cmdResult = Commands.CreateInitializeUpdateCommand(
            keySet.KeyVersion,
            keySet.KeyId,
            hostChallenge
        );

        if (cmdResult.IsFailure)
        {
            return await TryKeySetsRecursively(
                keySets,
                index + 1,
                hostChallenge,
                executeCommand,
                cancellationToken
            );
        }

        Result<CommandResponse, SmartCardError> response = await cmdResult
            .Bind(command => command.ToCommandApdu())
            .Bind(async commandApdu => await executeCommand(commandApdu, cancellationToken));

        if (response.IsSuccess)
        {
            var responseValue = response.Value;
            if (!responseValue.IsSuccess)
            {
                return await TryKeySetsRecursively(
                    keySets,
                    index + 1,
                    hostChallenge,
                    executeCommand,
                    cancellationToken
                );
            }

            Result<InitializeUpdateResponse, SmartCardError> parseResult = Responses.ParseInitializeUpdateResponse(responseValue);

            if (parseResult.IsSuccess)
            {
                Maybe<CryptoService.ScpVersion> protocolVersion = parseResult.Value.ScpId;
                return protocolVersion
                    .ToResult(
                        SmartCardError.InvalidArgument("Could not determine SCP protocol version")
                    )
                    .Map(version => (keySet, version));
            }
        }

        return await TryKeySetsRecursively(
            keySets,
            index + 1,
            hostChallenge,
            executeCommand,
            cancellationToken
        );
    }

    #endregion
}