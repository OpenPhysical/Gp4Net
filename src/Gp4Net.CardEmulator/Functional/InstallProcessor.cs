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
using Gp4Net.Cryptography;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Pure functional processor for GlobalPlatform INSTALL commands.
/// Handles Install for Load, Install for Install, and Install for Make Selectable.
/// </summary>
[PublicAPI]
public static class InstallProcessor
{
    /// <summary>
    /// Processes an INSTALL command according to GlobalPlatform specification.
    /// </summary>
    /// <param name="command">Parsed INSTALL command.</param>
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
            0x02 => ProcessInstallForLoad(command, state, config),
            0x04 => ProcessInstallForInstall(command, state, config),
            0x08 => ProcessInstallForMakeSelectable(command, state, config),
            0x0C => ProcessInstallForInstallAndMakeSelectable(command, state, config),
            _
                => Result.Failure<(ApduResponse, CardState), SmartCardError>(
                    SmartCardError.IncorrectP1P2($"Invalid P1 parameter: {command.P1:X2}")
                ),
        };
    }

    /// <summary>
    /// Processes Install for Load (P1=0x02) which prepares the card for loading a new package.
    /// </summary>
    private static Result<(ApduResponse, CardState), SmartCardError> ProcessInstallForLoad(
        ParsedCommand command,
        CardState state,
        CardConfiguration config
    )
    {
        return ParseInstallForLoadData(command.Data)
            .Bind(installData =>
                ValidateInstallToken(installData.InstallToken, state, config)
                    .Bind(isValidToken => CreateInstallForLoadResponse(installData, state))
                    .Map(response =>
                        (response, state.WithLoadFileAid(installData.LoadFileAid.ToArray()))
                    )
            );
    }

    /// <summary>
    /// Processes Install for Install (P1=0x04) which creates an application instance.
    /// </summary>
    private static Result<(ApduResponse, CardState), SmartCardError> ProcessInstallForInstall(
        ParsedCommand command,
        CardState state,
        CardConfiguration config
    )
    {
        return ParseInstallForInstallData(command.Data)
            .Bind(installData => ValidateApplicationInstall(installData, state, config))
            .Bind(validData => CreateApplicationInstance(validData, state))
            .Map(result => (CreateSuccessResponse(), result));
    }

    /// <summary>
    /// Processes Install for Make Selectable (P1=0x08) which makes an application selectable.
    /// </summary>
    private static Result<
        (ApduResponse, CardState),
        SmartCardError
    > ProcessInstallForMakeSelectable(
        ParsedCommand command,
        CardState state,
        CardConfiguration config
    )
    {
        return ParseMakeSelectableData(command.Data)
            .Bind(data => ValidateApplicationExists(data.ApplicationAid, state))
            .Bind(app => MakeApplicationSelectable(app, state))
            .Map(newState => (CreateSuccessResponse(), newState));
    }

    /// <summary>
    /// Processes combined Install for Install and Make Selectable (P1=0x0C).
    /// </summary>
    private static Result<
        (ApduResponse, CardState),
        SmartCardError
    > ProcessInstallForInstallAndMakeSelectable(
        ParsedCommand command,
        CardState state,
        CardConfiguration config
    )
    {
        return ProcessInstallForInstall(command, state, config)
            .Bind(result => ProcessInstallForMakeSelectable(command, result.Item2, config));
    }

    /// <summary>
    /// Parses Install for Load command data according to GP specification Table 11-37.
    /// </summary>
    private static Result<InstallForLoadData, SmartCardError> ParseInstallForLoadData(byte[] data)
    {
        if (data.Length < 1)
            return SmartCardError.InvalidData("Install for Load data too short");

        int offset = 0;

        // Parse Load File AID (mandatory)
        if (offset >= data.Length)
            return SmartCardError.InvalidData("Missing Load File AID length");

        byte loadFileAidLength = data[offset++];
        if (offset + loadFileAidLength > data.Length)
            return SmartCardError.InvalidData("Load File AID data truncated");

        var loadFileAid = ImmutableArray.Create(data, offset, loadFileAidLength);
        offset += loadFileAidLength;

        // Parse Security Domain AID (mandatory)
        if (offset >= data.Length)
            return SmartCardError.InvalidData("Missing Security Domain AID length");

        byte sdAidLength = data[offset++];
        if (offset + sdAidLength > data.Length)
            return SmartCardError.InvalidData("Security Domain AID data truncated");

        var securityDomainAid = ImmutableArray.Create(data, offset, sdAidLength);
        offset += sdAidLength;

        // Parse Load File Data Block Hash (optional)
        var loadFileHash =
            offset < data.Length && data[offset] > 0
                ? Maybe<ImmutableArray<byte>>.From(
                    ImmutableArray.Create(data, offset + 1, data[offset])
                )
                : Maybe<ImmutableArray<byte>>.None;

        if (loadFileHash.HasValue)
            offset += 1 + data[offset];

        // Parse Load Parameters (optional)
        var loadParameters =
            offset < data.Length && data[offset] > 0
                ? Maybe<ImmutableArray<byte>>.From(
                    ImmutableArray.Create(data, offset + 1, data[offset])
                )
                : Maybe<ImmutableArray<byte>>.None;

        if (loadParameters.HasValue)
            offset += 1 + data[offset];

        // Parse Install Token (optional)
        var installToken =
            offset < data.Length
                ? Maybe<ImmutableArray<byte>>.From(
                    ImmutableArray.Create(data, offset, data.Length - offset)
                )
                : Maybe<ImmutableArray<byte>>.None;

        return new InstallForLoadData(
            loadFileAid,
            securityDomainAid,
            loadFileHash,
            loadParameters,
            installToken
        );
    }

    /// <summary>
    /// Validates the install token against the current card state and configuration.
    /// </summary>
    private static Result<bool, SmartCardError> ValidateInstallToken(
        Maybe<ImmutableArray<byte>> token,
        CardState state,
        CardConfiguration config
    )
    {
        return token.Match(
            Some: tokenData =>
                ValidateTokenStructure(tokenData.ToArray())
                    .Bind(parsedToken => ValidateTokenSignature(parsedToken, state, config))
                    .Bind(validToken => ValidateTokenAuthorization(validToken, state, config))
                    .Map(_ => true),
            None: () => Result.Success<bool, SmartCardError>(true) // No token provided - assume valid for emulation
        );
    }

    /// <summary>
    /// Creates the response for Install for Load command.
    /// </summary>
    private static Result<ApduResponse, SmartCardError> CreateInstallForLoadResponse(
        InstallForLoadData installData,
        CardState state
    )
    {
        // Create Load File Data Block Hash (simulated)
        byte[] lfdbh = ComputeSimulatedLfdbh(installData.LoadFileAid.ToArray());

        // Response format: Length of LFDBH (1 byte) + LFDBH + Status Word
        byte[] responseData = new byte[1 + lfdbh.Length];
        responseData[0] = (byte)lfdbh.Length;
        Array.Copy(lfdbh, 0, responseData, 1, lfdbh.Length);

        return ApduResponse.Success(responseData);
    }

    /// <summary>
    /// Creates a standard success response.
    /// </summary>
    private static ApduResponse CreateSuccessResponse()
    {
        return ApduResponse.Success([]);
    }

    /// <summary>
    /// Computes a simulated Load File Data Block Hash for emulation purposes.
    /// </summary>
    private static byte[] ComputeSimulatedLfdbh(byte[] loadFileAid)
    {
        // Simple deterministic hash based on Load File AID for emulation
        return CryptoService
            .Hash.Sha256(loadFileAid)
            .Match(
                onSuccess: hash => hash[..20], // Take first 20 bytes
                onFailure: _ => new byte[20] // Fallback to zeros
            );
    }

    /// <summary>
    /// Validates token structure according to GP specification.
    /// </summary>
    private static Result<InstallToken, SmartCardError> ValidateTokenStructure(byte[] tokenData)
    {
        if (tokenData.Length < 8)
            return SmartCardError.SecurityStatusNotSatisfied("Install token too short");

        return Result.Success<InstallToken, SmartCardError>(
            new InstallToken(
                ImmutableArray.Create(tokenData, 0, Math.Min(8, tokenData.Length)),
                ImmutableArray.Create(tokenData, 8, Math.Max(0, tokenData.Length - 8))
            )
        );
    }

    /// <summary>
    /// Validates token signature (simplified for emulation).
    /// </summary>
    private static Result<InstallToken, SmartCardError> ValidateTokenSignature(
        InstallToken token,
        CardState state,
        CardConfiguration config
    )
    {
        // Simplified validation - in real implementation, verify cryptographic signature
        return Result.Success<InstallToken, SmartCardError>(token);
    }

    /// <summary>
    /// Validates token authorization (simplified for emulation).
    /// </summary>
    private static Result<InstallToken, SmartCardError> ValidateTokenAuthorization(
        InstallToken token,
        CardState state,
        CardConfiguration config
    )
    {
        // Simplified validation - in real implementation, check authorization levels
        return Result.Success<InstallToken, SmartCardError>(token);
    }

    /// <summary>
    /// Parses Install for Install command data.
    /// </summary>
    private static Result<InstallForInstallData, SmartCardError> ParseInstallForInstallData(
        byte[] data
    )
    {
        // Simplified parsing for emulation - in real implementation, parse full TLV structure
        return Result.Success<InstallForInstallData, SmartCardError>(
            new InstallForInstallData(
                ImmutableArray.Create(data, 0, Math.Min(16, data.Length)), // Application AID
                ImmutableArray.Create(data, 0, Math.Min(16, data.Length)) // Load File AID (same for simplicity)
            )
        );
    }

    /// <summary>
    /// Validates application installation parameters.
    /// </summary>
    private static Result<InstallForInstallData, SmartCardError> ValidateApplicationInstall(
        InstallForInstallData data,
        CardState state,
        CardConfiguration config
    )
    {
        // Check if application already exists
        bool exists = state.Applications.Values.Any(app =>
            app.Aid.SequenceEqual(data.ApplicationAid)
        );

        return exists
            ? Result.Failure<InstallForInstallData, SmartCardError>(
                SmartCardError.InvalidData("Application already exists")
            )
            : Result.Success<InstallForInstallData, SmartCardError>(data);
    }

    /// <summary>
    /// Creates a new application instance in the card state.
    /// </summary>
    private static Result<CardState, SmartCardError> CreateApplicationInstance(
        InstallForInstallData data,
        CardState state
    )
    {
        string aidString = Convert.ToHexString(data.ApplicationAid.ToArray());
        var newApp = new InstalledApplication(
            data.ApplicationAid.ToArray(),
            data.LoadFileAid.ToArray(), // Load file AID
            0x01, // LOADED state
            0x00, // No privileges
            ImmutableDictionary<string, byte[]>.Empty
        );

        return Result.Success<CardState, SmartCardError>(state.WithApplication(aidString, newApp));
    }

    /// <summary>
    /// Parses Make Selectable command data.
    /// </summary>
    private static Result<MakeSelectableData, SmartCardError> ParseMakeSelectableData(byte[] data)
    {
        return new MakeSelectableData(ImmutableArray.Create(data, 0, Math.Min(16, data.Length)));
    }

    /// <summary>
    /// Validates that the specified application exists.
    /// </summary>
    private static Result<InstalledApplication, SmartCardError> ValidateApplicationExists(
        ImmutableArray<byte> applicationAid,
        CardState state
    )
    {
        string aidString = Convert.ToHexString(applicationAid.ToArray());
        return state.Applications.ContainsKey(aidString)
            ? Result.Success<InstalledApplication, SmartCardError>(state.Applications[aidString])
            : Result.Failure<InstalledApplication, SmartCardError>(
                SmartCardError.InvalidData("Application not found")
            );
    }

    /// <summary>
    /// Makes the specified application selectable.
    /// </summary>
    private static Result<CardState, SmartCardError> MakeApplicationSelectable(
        InstalledApplication app,
        CardState state
    )
    {
        string aidString = Convert.ToHexString(app.Aid);
        var selectableApp = app with { LifecycleState = 0x07 }; // SELECTABLE state

        return Result.Success<CardState, SmartCardError>(
            state.WithApplication(aidString, selectableApp)
        );
    }

    /// <summary>
    /// Data structure for Install for Load command.
    /// </summary>
    private record InstallForLoadData(
        ImmutableArray<byte> LoadFileAid,
        ImmutableArray<byte> SecurityDomainAid,
        Maybe<ImmutableArray<byte>> LoadFileDataBlockHash,
        Maybe<ImmutableArray<byte>> LoadParameters,
        Maybe<ImmutableArray<byte>> InstallToken
    );

    /// <summary>
    /// Data structure for Install for Install command.
    /// </summary>
    private record InstallForInstallData(
        ImmutableArray<byte> ApplicationAid,
        ImmutableArray<byte> LoadFileAid
    );

    /// <summary>
    /// Data structure for Make Selectable command.
    /// </summary>
    private record MakeSelectableData(ImmutableArray<byte> ApplicationAid);

    /// <summary>
    /// Parsed install token structure.
    /// </summary>
    private record InstallToken(ImmutableArray<byte> TokenData, ImmutableArray<byte> Signature);
}
