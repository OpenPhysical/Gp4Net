// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using WSCT.ISO7816;
using static Gp4Net.Constants.Constants;

namespace Gp4Net.Domain.Commands;

/// <summary>
/// Represents the BEGIN R-MAC SESSION command.
/// </summary>
public class BeginRMacSessionCommand
{
    /// <summary>
    /// Gets the command class byte.
    /// </summary>
    public byte Cla { get; }

    /// <summary>
    /// Gets the instruction byte.
    /// </summary>
    public byte Ins => GlobalPlatform.Ins.BEGIN_R_MAC_SESSION;

    /// <summary>
    /// Gets the P1 parameter (security level for responses).
    /// </summary>
    public byte P1 { get; }

    /// <summary>
    /// Gets the P2 parameter (fixed to begin session).
    /// </summary>
    public byte P2 => GlobalPlatform.RMacParameters.P2_BEGIN_SESSION;

    /// <summary>
    /// Gets the command data including MAC if present.
    /// </summary>
    public byte[] Data { get; }

    /// <summary>
    /// Gets the expected response length.
    /// </summary>
    public Maybe<int> ExpectedResponseLength => Maybe<int>.None;

    /// <summary>
    /// Gets whether this command uses extended length.
    /// </summary>
    public bool IsExtendedLength => false;

    /// <summary>
    /// Gets the data field (optional).
    /// </summary>
    private Maybe<byte[]> CommandData { get; }

    /// <summary>
    /// Gets the MAC value (optional).
    /// </summary>
    private Maybe<byte[]> Mac { get; }

    /// <summary>
    /// Initializes a new instance of the BeginRMacSessionCommand class.
    /// </summary>
    /// <param name="cla">The command class byte.</param>
    /// <param name="p1">The P1 parameter (0x10 for R-MAC, 0x30 for R-ENCRYPTION and R-MAC).</param>
    /// <param name="data">Optional data field.</param>
    /// <param name="mac">Optional MAC value (8 bytes).</param>
    private BeginRMacSessionCommand(
        byte cla,
        byte p1,
        Maybe<byte[]> data = default,
        Maybe<byte[]> mac = default
    )
    {
        Cla = cla;
        P1 = p1;
        CommandData = data.Map(d => (byte[])d.Clone());
        Mac = mac.Map(m => (byte[])m.Clone());

        var commandData = CommandData.GetValueOrDefault([]);
        var combinedData = new List<byte> { (byte)commandData.Length };
        combinedData.AddRange(commandData);
        Mac.Execute(m => combinedData.AddRange(m));
        Data = [.. combinedData];
    }

    /// <summary>
    /// Creates a BEGIN R-MAC SESSION command with the specified security level.
    /// </summary>
    /// <param name="securityLevel">The security level for the R-MAC session.</param>
    /// <param name="cla">The command class byte (default: 0x80).</param>
    /// <param name="data">Optional data field.</param>
    /// <param name="mac">Optional MAC value (must be 8 bytes if provided).</param>
    /// <returns>A Result containing the BeginRMacSessionCommand or an error.</returns>
    public static Result<BeginRMacSessionCommand, SmartCardError> Create(
        SecurityLevel securityLevel,
        byte cla = GlobalPlatform.Cla.GP_STANDARD,
        Maybe<byte[]> data = default,
        Maybe<byte[]> mac = default
    )
    {
        // GP Card Specification v2.3.1, Table E-14 permits 00 and 10;
        // SCP03 Amendment D v1.1.2, Table 7-9 permits 10 and 30.
        if (
            securityLevel
            is not SecurityLevel.None
                and not SecurityLevel.RMac
                and not (SecurityLevel.RMac | SecurityLevel.REncryption)
        )
        {
            return Result.Failure<BeginRMacSessionCommand, SmartCardError>(
                SmartCardError.InvalidArgument($"Invalid security level: {securityLevel}")
            );
        }

        if (
            cla != GlobalPlatform.Cla.GP_STANDARD
            && cla != GlobalPlatform.Cla.R_MAC_SECURE
            && cla != GlobalPlatform.Cla.R_MAC_ENCRYPTED
        )
        {
            return Result.Failure<BeginRMacSessionCommand, SmartCardError>(
                SmartCardError.InvalidArgument(
                    $"Invalid CLA byte: 0x{cla:X2}. Must be 0x80, 0xC0, or 0xE0"
                )
            );
        }

        var commandData = data.GetValueOrDefault([]);
        if (commandData.Length > 24)
            return SmartCardError.InvalidArgument("BEGIN R-MAC data must not exceed 24 bytes");

        var macValidation = mac.Match(
            m =>
                m.Length != 8
                    ? Result.Failure<byte[], SmartCardError>(
                        SmartCardError.InvalidArgument("MAC must be exactly 8 bytes")
                    )
                    : Result.Success<byte[], SmartCardError>(m),
            () => Result.Success<byte[], SmartCardError>([])
        );

        if (macValidation.IsFailure)
        {
            return Result.Failure<BeginRMacSessionCommand, SmartCardError>(macValidation.Error);
        }

        byte p1 = (byte)securityLevel;

        return Result.Success<BeginRMacSessionCommand, SmartCardError>(
            new BeginRMacSessionCommand(cla, p1, data, mac)
        );
    }

    /// <summary>
    /// Converts this command to a CommandAPDU.
    /// </summary>
    /// <returns>A result containing the CommandAPDU or an error.</returns>
    public Result<CommandAPDU, SmartCardError> ToCommandApdu()
    {
        return Result.Success<CommandAPDU, SmartCardError>(
            new CommandAPDU(Cla, Ins, P1, P2, (uint)Data.Length, Data)
        );
    }

    /// <summary>
    /// Returns a string representation of this command.
    /// </summary>
    /// <returns>A string describing this command.</returns>
    public override string ToString()
    {
        return "BEGIN R-MAC SESSION";
    }
}

/// <summary>
/// Represents the END R-MAC SESSION command.
/// </summary>
public class EndRMacSessionCommand
{
    /// <summary>
    /// Gets the command class byte.
    /// </summary>
    public byte Cla { get; }

    /// <summary>
    /// Gets the instruction byte.
    /// </summary>
    public byte Ins => GlobalPlatform.Ins.END_R_MAC_SESSION;

    /// <summary>
    /// Gets the P1 parameter (fixed to end session).
    /// </summary>
    public byte P1 => GlobalPlatform.RMacParameters.P1_END_SESSION;

    /// <summary>
    /// Gets the P2 parameter.
    /// </summary>
    public byte P2 { get; }

    /// <summary>
    /// Gets the command data (MAC if present).
    /// </summary>
    public byte[] Data { get; }

    /// <summary>
    /// Gets the expected response length.
    /// </summary>
    public Maybe<int> ExpectedResponseLength => Maybe<int>.None;

    /// <summary>
    /// Gets whether this command uses extended length.
    /// </summary>
    public bool IsExtendedLength => false;

    /// <summary>
    /// Gets the MAC value (optional).
    /// </summary>
    private Maybe<byte[]> Mac { get; }

    /// <summary>
    /// Initializes a new instance of the EndRMacSessionCommand class.
    /// </summary>
    /// <param name="cla">The command class byte.</param>
    /// <param name="p2">The P2 parameter (0x03 to end session and return R-MAC).</param>
    /// <param name="mac">Optional C-MAC value (8 bytes).</param>
    private EndRMacSessionCommand(byte cla, byte p2, Maybe<byte[]> mac = default)
    {
        Cla = cla;
        P2 = p2;
        Mac = mac.Map(m => (byte[])m.Clone());

        Data = Mac.Match(m => (byte[])m.Clone(), () => []);
    }

    /// <summary>
    /// Creates an END R-MAC SESSION command with the specified security level.
    /// </summary>
    /// <param name="securityLevel">The security level for the R-MAC session.</param>
    /// <param name="cla">The command class byte (default: 0x80).</param>
    /// <param name="mac">Optional C-MAC value (must be 8 bytes if provided).</param>
    /// <returns>A Result containing the EndRMacSessionCommand or an error.</returns>
    public static Result<EndRMacSessionCommand, SmartCardError> Create(
        SecurityLevel securityLevel,
        byte cla = GlobalPlatform.Cla.GP_STANDARD,
        Maybe<byte[]> mac = default
    )
    {
        // GP Card Specification v2.3.1, Table E-18 and SCP03 Amendment D v1.1.2,
        // Table 7-11 require P1=00; the active response level does not change P1.
        if (
            securityLevel
            is not SecurityLevel.None
                and not SecurityLevel.RMac
                and not (SecurityLevel.RMac | SecurityLevel.REncryption)
        )
        {
            return Result.Failure<EndRMacSessionCommand, SmartCardError>(
                SmartCardError.InvalidArgument($"Invalid security level: {securityLevel}")
            );
        }

        if (
            cla != GlobalPlatform.Cla.GP_STANDARD
            && cla != GlobalPlatform.Cla.R_MAC_SECURE
            && cla != GlobalPlatform.Cla.R_MAC_ENCRYPTED
        )
        {
            return Result.Failure<EndRMacSessionCommand, SmartCardError>(
                SmartCardError.InvalidArgument(
                    $"Invalid CLA byte: 0x{cla:X2}. Must be 0x80, 0xC0, or 0xE0"
                )
            );
        }

        var macValidation = mac.Match(
            m =>
                m.Length != 8
                    ? Result.Failure<byte[], SmartCardError>(
                        SmartCardError.InvalidArgument("MAC must be exactly 8 bytes")
                    )
                    : Result.Success<byte[], SmartCardError>(m),
            () => Result.Success<byte[], SmartCardError>([])
        );

        if (macValidation.IsFailure)
        {
            return Result.Failure<EndRMacSessionCommand, SmartCardError>(macValidation.Error);
        }

        byte p2 = GlobalPlatform.RMacParameters.P2_END_SESSION_RETURN_RMAC;

        return Result.Success<EndRMacSessionCommand, SmartCardError>(
            new EndRMacSessionCommand(cla, p2, mac)
        );
    }

    /// <summary>
    /// Converts this command to a CommandAPDU.
    /// </summary>
    /// <returns>A result containing the CommandAPDU or an error.</returns>
    public Result<CommandAPDU, SmartCardError> ToCommandApdu()
    {
        // GP Card Specification v2.3.1, Table E-18; SCP03 Amendment D v1.1.2, Table 7-11.
        return Result.Success<CommandAPDU, SmartCardError>(
            new CommandAPDU(Cla, Ins, P1, P2, (uint)Data.Length, Data, 0)
        );
    }

    /// <summary>
    /// Returns a string representation of this command.
    /// </summary>
    /// <returns>A string describing this command.</returns>
    public override string ToString()
    {
        return "END R-MAC SESSION";
    }
}

/// <summary>
/// Represents the response to an END R-MAC SESSION command.
/// </summary>
public class EndRMacSessionResponse
{
    /// <summary>
    /// Gets the R-MAC value.
    /// </summary>
    public byte[] RMac { get; }

    /// <summary>
    /// Initializes a new instance of the EndRMacSessionResponse class.
    /// </summary>
    /// <param name="rMac">The R-MAC value (8 bytes).</param>
    private EndRMacSessionResponse(byte[] rMac)
    {
        RMac = (byte[])rMac.Clone();
    }

    /// <summary>
    /// Parses an END R-MAC SESSION response.
    /// </summary>
    /// <param name="responseData">The response data (excluding status word).</param>
    /// <returns>A Result containing the parsed response or an error.</returns>
    public static Result<EndRMacSessionResponse, SmartCardError> Parse(Maybe<byte[]> responseData)
    {
        return responseData.Match(
            data =>
                data.Length != 8
                    ? Result.Failure<EndRMacSessionResponse, SmartCardError>(
                        SmartCardError.InvalidData(
                            $"Response must be exactly 8 bytes, but got {data.Length} bytes"
                        )
                    )
                    : Result.Success<EndRMacSessionResponse, SmartCardError>(
                        new EndRMacSessionResponse(data)
                    ),
            () =>
                Result.Failure<EndRMacSessionResponse, SmartCardError>(
                    SmartCardError.InvalidData("Response data is required")
                )
        );
    }

    /// <summary>
    /// Returns a string representation of this response.
    /// </summary>
    /// <returns>A string describing this response.</returns>
    public override string ToString()
    {
        return $"END R-MAC SESSION RESPONSE (R-MAC: {Convert.ToHexString(RMac)})";
    }
}
