// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Domain;
using Gp4Net.Core;
using Gp4Net.Domain.CapFile;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Pure functional processor for GlobalPlatform LOAD commands.
/// Handles CAP file loading with proper state management and DAP verification.
/// </summary>
[PublicAPI]
public static class LoadProcessor
{
    /// <summary>
    /// Processes a LOAD command according to GlobalPlatform specification.
    /// </summary>
    /// <param name="command">Parsed LOAD command.</param>
    /// <param name="state">Current card state.</param>
    /// <param name="config">Card configuration.</param>
    /// <returns>Response and updated state, or error.</returns>
    public static Result<(ApduResponse, CardState), SmartCardError> Process(
        ParsedCommand command,
        CardState state,
        CardConfiguration config
    )
    {
        return command.P1 switch
        {
            0x00 => ProcessFirstLoad(command, state, config),
            0x01 => ProcessSubsequentLoad(command, state, config),
            0x80 => ProcessLastLoad(command, state, config),
            _
                => Result.Failure<(ApduResponse, CardState), SmartCardError>(
                    SmartCardError.IncorrectP1P2($"Invalid P1 parameter: {command.P1:X2}")
                ),
        };
    }

    /// <summary>
    /// Processes the first LOAD command (P1=0x00) which starts CAP file loading.
    /// </summary>
    private static Result<(ApduResponse, CardState), SmartCardError> ProcessFirstLoad(
        ParsedCommand command,
        CardState state,
        CardConfiguration config
    )
    {
        return GetOrCreateLoadContext(state, command.P2)
            .Bind(loadContext => ValidateFirstLoadData(command.Data))
            .Bind(validData => InitializeLoadContext(validData, state, command.P2))
            .Map(newState => (ApduResponse.Success([]), newState));
    }

    /// <summary>
    /// Processes subsequent LOAD commands (P1=0x01) which continue CAP file loading.
    /// </summary>
    private static Result<(ApduResponse, CardState), SmartCardError> ProcessSubsequentLoad(
        ParsedCommand command,
        CardState state,
        CardConfiguration config
    )
    {
        return GetLoadContext(state, command.P2)
            .Bind(loadContext => AccumulateLoadData(loadContext, command.Data))
            .Bind(updatedContext => UpdateLoadContext(state, updatedContext, command.P2))
            .Map(newState => (ApduResponse.Success([]), newState));
    }

    /// <summary>
    /// Processes the last LOAD command (P1=0x80) which completes CAP file loading.
    /// </summary>
    private static Result<(ApduResponse, CardState), SmartCardError> ProcessLastLoad(
        ParsedCommand command,
        CardState state,
        CardConfiguration config
    )
    {
        return GetLoadContext(state, command.P2)
            .Bind(loadContext => AccumulateLoadData(loadContext, command.Data))
            .Bind(finalContext => ProcessCompleteCapFile(finalContext, state, config))
            .Map(newState => (ApduResponse.Success([]), newState));
    }

    /// <summary>
    /// Gets or creates a load context for the specified block number.
    /// </summary>
    private static Result<LoadContext, SmartCardError> GetOrCreateLoadContext(
        CardState state,
        byte blockNumber
    )
    {
        string contextKey = $"LOAD_{blockNumber:X2}";

        return state.LoadContexts.ContainsKey(contextKey)
            ? Result.Success<LoadContext, SmartCardError>(state.LoadContexts[contextKey])
            : Result.Success<LoadContext, SmartCardError>(
                new LoadContext(
                    blockNumber,
                    ImmutableList<byte[]>.Empty,
                    Maybe<ImmutableArray<byte>>.None,
                    0
                )
            );
    }

    /// <summary>
    /// Gets an existing load context for the specified block number.
    /// </summary>
    private static Result<LoadContext, SmartCardError> GetLoadContext(
        CardState state,
        byte blockNumber
    )
    {
        string contextKey = $"LOAD_{blockNumber:X2}";

        return state.LoadContexts.ContainsKey(contextKey)
            ? Result.Success<LoadContext, SmartCardError>(state.LoadContexts[contextKey])
            : Result.Failure<LoadContext, SmartCardError>(
                SmartCardError.ConditionsOfUseNotSatisfied()
            );
    }

    /// <summary>
    /// Validates the data in the first LOAD command.
    /// </summary>
    private static Result<byte[], SmartCardError> ValidateFirstLoadData(byte[] data)
    {
        return data.Length > 0
            ? Result.Success<byte[], SmartCardError>(data)
            : Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidData("First LOAD command must contain data")
            );
    }

    /// <summary>
    /// Initializes a new load context with the first block of data.
    /// </summary>
    private static Result<CardState, SmartCardError> InitializeLoadContext(
        byte[] firstData,
        CardState state,
        byte blockNumber
    )
    {
        var loadContext = new LoadContext(
            blockNumber,
            ImmutableList.Create<byte[]>(firstData),
            Maybe<ImmutableArray<byte>>.None,
            firstData.Length
        );

        string contextKey = $"LOAD_{blockNumber:X2}";
        var newContexts = state.LoadContexts.SetItem(contextKey, loadContext);

        return Result.Success<CardState, SmartCardError>(state.WithLoadContexts(newContexts));
    }

    /// <summary>
    /// Accumulates load data into an existing load context using functional composition.
    /// </summary>
    private static Result<LoadContext, SmartCardError> AccumulateLoadData(
        LoadContext loadContext,
        byte[] newData
    )
    {
        var builder = loadContext.AccumulatedData.ToBuilder();
        builder.Add(newData);
        var updatedData = builder.ToImmutable();

        var updatedContext = loadContext with
        {
            AccumulatedData = updatedData,
            TotalSize = loadContext.TotalSize + newData.Length,
        };

        return Result.Success<LoadContext, SmartCardError>(updatedContext);
    }

    /// <summary>
    /// Updates the card state with the modified load context.
    /// </summary>
    private static Result<CardState, SmartCardError> UpdateLoadContext(
        CardState state,
        LoadContext loadContext,
        byte blockNumber
    )
    {
        string contextKey = $"LOAD_{blockNumber:X2}";
        var newContexts = state.LoadContexts.SetItem(contextKey, loadContext);

        return Result.Success<CardState, SmartCardError>(state.WithLoadContexts(newContexts));
    }

    /// <summary>
    /// Processes the complete CAP file when loading is finished.
    /// </summary>
    private static Result<CardState, SmartCardError> ProcessCompleteCapFile(
        LoadContext loadContext,
        CardState state,
        CardConfiguration config
    )
    {
        return CombineLoadData(loadContext)
            .Bind(capFileData =>
                ParseCapFileStructure(capFileData)
                    .Bind(capInfo =>
                        VerifyLfdbhHash(capFileData, state)
                            .Bind(_ => VerifyDapSignature(capFileData))
                            .Bind(_ => CreateLoadFileFromCapInfo(capInfo, state))
                    )
                    .Bind(loadFile => InstallLoadFile(loadFile, state))
            )
            .Map(newState => ClearLoadContext(newState, loadContext.BlockNumber));
    }

    /// <summary>
    /// Combines all accumulated load data into a single byte array using functional composition.
    /// </summary>
    private static Result<byte[], SmartCardError> CombineLoadData(LoadContext loadContext)
    {
        try
        {
            var combinedData = loadContext.AccumulatedData.SelectMany(chunk => chunk).ToArray();

            return Result.Success<byte[], SmartCardError>(combinedData);
        }
        catch (Exception ex)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.UnexpectedError($"Failed to combine load data: {ex.Message}")
            );
        }
    }

    /// <summary>
    /// Parses the CAP file structure to extract package information.
    /// </summary>
    private static Result<CapFileInfo, SmartCardError> ParseCapFileStructure(byte[] capData)
    {
        return CapFileStructure
            .Parse(capData)
            .Map(structure => new CapFileInfo(
                structure.PackageAid,
                structure.PackageVersion.ToString(),
                structure.Applets.Select(a => a.Aid).ToArray()
            ))
            .MapError(error =>
                SmartCardError.InvalidData($"Invalid CAP file structure: {error.Message}")
            );
    }

    /// <summary>
    /// Verifies the Load File Data Block Hash (LFDBH) against the expected value.
    /// Per GlobalPlatform Card Specification v2.3.1 Section 11.5.2.1.
    /// </summary>
    private static Result<bool, SmartCardError> VerifyLfdbhHash(byte[] capFileData, CardState state)
    {
        return ExtractExpectedLfdbhFromState(state)
            .Bind(expectedLfdbh =>
                LoadFileDataBlockHash
                    .ComputeFromCapFile(capFileData, expectedLfdbh.Value.Length)
                    .Bind(actualLfdbh => expectedLfdbh.VerifyMatch(actualLfdbh))
            );
    }

    /// <summary>
    /// Extracts the expected LFDBH from the card state (from Install for Load response).
    /// </summary>
    private static Result<LoadFileDataBlockHash, SmartCardError> ExtractExpectedLfdbhFromState(
        CardState state
    )
    {
        // In a real implementation, this would extract the LFDBH from Install for Load response
        // For emulation, create a default expected hash
        return state.DataObjects.TryGetValue(0xC001, out var hashValue)
            ? LoadFileDataBlockHash.Create(hashValue)
            : Result.Failure<LoadFileDataBlockHash, SmartCardError>(
                SmartCardError.SecurityStatusNotSatisfied(
                    "Expected LFDBH not found in card state - INSTALL [for load] required first"
                )
            );
    }

    /// <summary>
    /// Verifies the DAP (Data Authentication Pattern) signature if present.
    /// </summary>
    private static Result<bool, SmartCardError> VerifyDapSignature(byte[] capFileData)
    {
        return DapProcessor.VerifyDapSignature(capFileData);
    }

    /// <summary>
    /// Creates a LoadFile instance from the parsed CAP file information.
    /// </summary>
    private static Result<LoadFile, SmartCardError> CreateLoadFileFromCapInfo(
        CapFileInfo capInfo,
        CardState state
    )
    {
        return Result.Success<LoadFile, SmartCardError>(
            new LoadFile(
                capInfo.PackageAid,
                [0xA0, 0x00, 0x00, 0x01, 0x51], // Default ISD AID
                0x01, // LOADED state
                ImmutableList<ExecutableModule>.Empty
            )
        );
    }

    /// <summary>
    /// Installs the load file into the card state.
    /// </summary>
    private static Result<CardState, SmartCardError> InstallLoadFile(
        LoadFile loadFile,
        CardState state
    )
    {
        return Result.Success<CardState, SmartCardError>(state.WithLoadFile(loadFile));
    }

    /// <summary>
    /// Clears the load context after successful completion.
    /// </summary>
    private static CardState ClearLoadContext(CardState state, byte blockNumber)
    {
        string contextKey = $"LOAD_{blockNumber:X2}";
        var newContexts = state.LoadContexts.Remove(contextKey);
        return state.WithLoadContexts(newContexts);
    }

    /// <summary>
    /// Load context for tracking multi-block LOAD operations.
    /// </summary>
    public record LoadContext(
        byte BlockNumber,
        ImmutableList<byte[]> AccumulatedData,
        Maybe<ImmutableArray<byte>> ExpectedLfdbh,
        int TotalSize
    );

    /// <summary>
    /// CAP file information extracted from parsed structure.
    /// </summary>
    private record CapFileInfo(byte[] PackageAid, string PackageName, byte[][] AppletAids);
}
