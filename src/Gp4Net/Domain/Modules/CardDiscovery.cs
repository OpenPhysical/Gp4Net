using System;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Transport;
using Gp4Net.Pipeline;

namespace Gp4Net.Domain.Modules;

/// <summary>
/// Pure functional module for card discovery operations.
/// Handles ISD detection and application selection.
/// </summary>
public static class CardDiscovery
{
    /// <summary>
    /// Well-known Issuer Security Domain AIDs per GlobalPlatform specification.
    /// </summary>
    private static readonly ImmutableList<byte[]> WellKnownIsdAids = ImmutableList.Create(
        Convert.FromHexString("A000000003000000"),  // Standard GP ISD
        Convert.FromHexString("A000000151000000"),  // Common alternative ISD
        Convert.FromHexString("A000000018434D00"),  // Another common ISD variant
        new byte[] { 0xA0, 0x00, 0x00, 0x00, 0x03 }  // Shorter form sometimes used
    );

    /// <summary>
    /// Attempts to detect and select the Issuer Security Domain.
    /// First tries a direct SELECT with empty AID, then tries known ISD AIDs.
    /// </summary>
    /// <param name="executeCommand">Function to execute APDU commands.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The SelectResponse from the ISD or an error.</returns>
    public static async Task<Result<SelectResponse, SmartCardError>> DetectAndSelectIsdAsync(
        Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken = default)
    {
        // First try SELECT with empty AID (standard method)
        Result<SelectCommand, SmartCardError> selectIsdResult = CommandFactory.CreateSelectIsdCommand();
        if (selectIsdResult.IsFailure)
        {
            return Result.Failure<SelectResponse, SmartCardError>(selectIsdResult.Error);
        }

        Result<CommandResponse, SmartCardError> response = await executeCommand(selectIsdResult.Value, cancellationToken);
        
        if (response.IsSuccess)
        {
            Result<SelectResponse, SmartCardError> parseResult = ResponseParser.ParseSelectResponse(response.Value);
            if (parseResult.IsSuccess)
            {
                return parseResult;
            }
        }

        // If direct ISD selection fails, try known ISD AIDs
        return await TryKnownIsdAidsAsync(executeCommand, cancellationToken);
    }

    /// <summary>
    /// Tries to select ISD using known AID values.
    /// </summary>
    private static async Task<Result<SelectResponse, SmartCardError>> TryKnownIsdAidsAsync(
        Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken)
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
        Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken)
    {
        if (index >= aids.Count)
        {
            return Result.Failure<SelectResponse, SmartCardError>(
                SmartCardError.CardError("Failed to detect Issuer Security Domain"));
        }

        Result<SelectCommand, SmartCardError> selectResult = CommandFactory.CreateSelectCommand(aids[index]);
        if (selectResult.IsFailure)
        {
            return await TryAidsRecursively(aids, index + 1, executeCommand, cancellationToken);
        }

        Result<CommandResponse, SmartCardError> response = await executeCommand(selectResult.Value, cancellationToken);
        
        if (response.IsSuccess)
        {
            Result<SelectResponse, SmartCardError> parseResult = ResponseParser.ParseSelectResponse(response.Value);
            if (parseResult.IsSuccess)
            {
                return parseResult;
            }
        }

        return await TryAidsRecursively(aids, index + 1, executeCommand, cancellationToken);
    }

    /// <summary>
    /// Selects a specific application by AID.
    /// </summary>
    /// <param name="aid">The application identifier.</param>
    /// <param name="executeCommand">Function to execute APDU commands.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The SelectResponse or an error.</returns>
    public static async Task<Result<SelectResponse, SmartCardError>> SelectApplicationAsync(
        byte[] aid,
        Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken = default)
    {
        Result<SelectCommand, SmartCardError> selectResult = CommandFactory.CreateSelectCommand(aid);
        if (selectResult.IsFailure)
        {
            return Result.Failure<SelectResponse, SmartCardError>(selectResult.Error);
        }

        Result<CommandResponse, SmartCardError> response = await executeCommand(selectResult.Value, cancellationToken);
        
        return response.IsSuccess
            ? ResponseParser.ParseSelectResponse(response.Value)
            : Result.Failure<SelectResponse, SmartCardError>(response.Error);
    }

    /// <summary>
    /// Attempts to determine the correct key set for a card through trial.
    /// Useful for cards where the key set is unknown.
    /// </summary>
    /// <param name="executeCommand">Function to execute APDU commands.</param>
    /// <param name="possibleKeySets">List of key sets to try.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The first working key set and protocol version, or an error.</returns>
    public static async Task<Result<(IKeySet KeySet, byte ProtocolVersion), SmartCardError>> DiscoverKeySetAsync(
        Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        ImmutableList<IKeySet> possibleKeySets,
        CancellationToken cancellationToken = default)
    {
        ImmutableList<IKeySet> keySetsToTry = possibleKeySets == null || possibleKeySets.Count == 0
            ? ImmutableList.Create<IKeySet>(
                GpTestKeys.CreateScp02TestKeySet(),
                GpTestKeys.CreateScp03TestKeySet())
            : possibleKeySets;

        // Generate host challenge for testing
        byte[] hostChallenge = CryptographyHelpers.GenerateHostChallenge();

        return await TryKeySetsRecursively(keySetsToTry, 0, hostChallenge, executeCommand, cancellationToken);
    }

    /// <summary>
    /// Recursively tries key sets until one succeeds.
    /// </summary>
    private static async Task<Result<(IKeySet KeySet, byte ProtocolVersion), SmartCardError>> TryKeySetsRecursively(
        ImmutableList<IKeySet> keySets,
        int index,
        byte[] hostChallenge,
        Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken)
    {
        if (index >= keySets.Count)
        {
            return Result.Failure<(IKeySet, byte), SmartCardError>(
                SmartCardError.SecurityError("Failed to discover working key set"));
        }

        IKeySet keySet = keySets[index];
        Result<InitializeUpdateCommand, SmartCardError> cmdResult = 
            CommandFactory.CreateInitializeUpdateCommand(keySet.KeyVersion, keySet.KeyId, hostChallenge);
        
        if (cmdResult.IsFailure)
        {
            return await TryKeySetsRecursively(keySets, index + 1, hostChallenge, executeCommand, cancellationToken);
        }

        Result<CommandResponse, SmartCardError> response = 
            await executeCommand(cmdResult.Value, cancellationToken);
        
        if (response.IsSuccess && response.Value.IsSuccess)
        {
            Result<InitializeUpdateResponse, SmartCardError> parseResult = 
                ResponseParser.ParseInitializeUpdateResponse(response.Value);
            
            if (parseResult.IsSuccess)
            {
                byte protocolVersion = parseResult.Value.ScpId;
                return Result.Success<(IKeySet, byte), SmartCardError>((keySet, protocolVersion));
            }
        }

        return await TryKeySetsRecursively(keySets, index + 1, hostChallenge, executeCommand, cancellationToken);
    }
}