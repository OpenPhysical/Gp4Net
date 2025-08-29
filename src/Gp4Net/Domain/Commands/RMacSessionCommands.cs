// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;

namespace Gp4Net.Domain.Commands;

/// <summary>
/// Represents the BEGIN R-MAC SESSION command.
/// </summary>
public class BeginRMacSessionCommand
{
    /// <summary>
    /// The command class byte options.
    /// </summary>
    public const byte Cla80 = 0x80;
    public const byte ClaC0 = 0xC0;
    public const byte ClaE0 = 0xE0;

    /// <summary>
    /// The command instruction byte.
    /// </summary>
    public const byte Ins = 0x7A;

    /// <summary>
    /// Gets the command class byte.
    /// </summary>
    public byte Cla { get; }

    /// <summary>
    /// Gets the P1 parameter (security level for responses).
    /// </summary>
    public byte P1 { get; }

    /// <summary>
    /// Gets the data field (optional).
    /// </summary>
    public byte[] Data { get; }

    /// <summary>
    /// Gets the MAC value (optional).
    /// </summary>
    public byte[] Mac { get; }

    /// <summary>
    /// Initializes a new instance of the BeginRMacSessionCommand class.
    /// </summary>
    /// <param name="cla">The command class byte.</param>
    /// <param name="p1">The P1 parameter (0x10 for R-MAC, 0x30 for R-ENCRYPTION and R-MAC).</param>
    /// <param name="data">Optional data field.</param>
    /// <param name="mac">Optional MAC value (8 bytes).</param>
    private BeginRMacSessionCommand(byte cla, byte p1, byte[] data = null, byte[] mac = null)
    {
        Cla = cla;
        P1 = p1;
        Data = data != null ? (byte[])data.Clone() : [];
        Mac = mac != null ? (byte[])mac.Clone() : null;
    }

    /// <summary>
    /// Converts this command to an APDU byte array.
    /// </summary>
    /// <returns>The APDU command bytes.</returns>
    public byte[] ToApdu()
    {
        int dataLength = (Data?.Length ?? 0) + (Mac?.Length ?? 0);
        byte[] apdu = new byte[5 + dataLength];

        apdu[0] = Cla;
        apdu[1] = Ins;
        apdu[2] = P1;
        apdu[3] = 0x01; // P2
        apdu[4] = (byte)dataLength; // Lc

        int offset = 5;

        // Copy data if present
        if (Data.Length > 0)
        {
            Array.Copy(Data, 0, apdu, offset, Data.Length);
            offset += Data.Length;
        }

        // Copy MAC if present
        if (Mac != null)
        {
            Array.Copy(Mac, 0, apdu, offset, Mac.Length);
        }

        return apdu;
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
        byte cla = Cla80,
        byte[] data = null,
        byte[] mac = null)
    {
        // Validate security level
        if (!Enum.IsDefined(typeof(SecurityLevel), securityLevel))
        {
            return Result.Failure<BeginRMacSessionCommand, SmartCardError>(
                SmartCardError.InvalidArgument($"Invalid security level: {securityLevel}")
            );
        }

        // Validate CLA byte
        if (cla != Cla80 && cla != ClaC0 && cla != ClaE0)
        {
            return Result.Failure<BeginRMacSessionCommand, SmartCardError>(
                SmartCardError.InvalidArgument($"Invalid CLA byte: 0x{cla:X2}. Must be 0x80, 0xC0, or 0xE0")
            );
        }

        // Validate MAC length
        if (mac != null && mac.Length != 8)
        {
            return Result.Failure<BeginRMacSessionCommand, SmartCardError>(
                SmartCardError.InvalidArgument("MAC must be exactly 8 bytes")
            );
        }

        // Convert security level to P1 parameter
        byte p1 = (byte)securityLevel;

        return Result.Success<BeginRMacSessionCommand, SmartCardError>(
            new BeginRMacSessionCommand(cla, p1, data, mac)
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
    /// The command class byte options.
    /// </summary>
    public const byte Cla80 = 0x80;
    public const byte ClaC0 = 0xC0;
    public const byte ClaE0 = 0xE0;

    /// <summary>
    /// The command instruction byte.
    /// </summary>
    public const byte Ins = 0x78;

    /// <summary>
    /// Gets the command class byte.
    /// </summary>
    public byte Cla { get; }

    /// <summary>
    /// Gets the P2 parameter.
    /// </summary>
    public byte P2 { get; }

    /// <summary>
    /// Gets the MAC value (optional).
    /// </summary>
    public byte[] Mac { get; }

    /// <summary>
    /// Initializes a new instance of the EndRMacSessionCommand class.
    /// </summary>
    /// <param name="cla">The command class byte.</param>
    /// <param name="p2">The P2 parameter (0x03 to end session and return R-MAC).</param>
    /// <param name="mac">Optional C-MAC value (8 bytes).</param>
    private EndRMacSessionCommand(byte cla, byte p2, byte[] mac = null)
    {
        Cla = cla;
        P2 = p2;
        Mac = mac != null ? (byte[])mac.Clone() : null;
    }

    /// <summary>
    /// Converts this command to an APDU byte array.
    /// </summary>
    /// <returns>The APDU command bytes.</returns>
    public byte[] ToApdu()
    {
        int dataLength = Mac?.Length ?? 0;
        byte[] apdu = new byte[5 + dataLength];

        apdu[0] = Cla;
        apdu[1] = Ins;
        apdu[2] = 0x00; // P1
        apdu[3] = P2;
        apdu[4] = (byte)dataLength; // Lc

        // Copy MAC if present
        if (Mac != null)
        {
            Array.Copy(Mac, 0, apdu, 5, Mac.Length);
        }

        return apdu;
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
        byte cla = Cla80,
        byte[] mac = null)
    {
        // Validate security level
        if (!Enum.IsDefined(typeof(SecurityLevel), securityLevel))
        {
            return Result.Failure<EndRMacSessionCommand, SmartCardError>(
                SmartCardError.InvalidArgument($"Invalid security level: {securityLevel}")
            );
        }

        // Validate CLA byte
        if (cla != Cla80 && cla != ClaC0 && cla != ClaE0)
        {
            return Result.Failure<EndRMacSessionCommand, SmartCardError>(
                SmartCardError.InvalidArgument($"Invalid CLA byte: 0x{cla:X2}. Must be 0x80, 0xC0, or 0xE0")
            );
        }

        // Validate MAC length
        if (mac != null && mac.Length != 8)
        {
            return Result.Failure<EndRMacSessionCommand, SmartCardError>(
                SmartCardError.InvalidArgument("MAC must be exactly 8 bytes")
            );
        }

        // P2 parameter is typically 0x03 to end session and return R-MAC
        byte p2 = 0x03;

        return Result.Success<EndRMacSessionCommand, SmartCardError>(
            new EndRMacSessionCommand(cla, p2, mac)
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
    public static Result<EndRMacSessionResponse, SmartCardError> Parse(byte[] responseData)
    {
        if (responseData == null)
        {
            return Result.Failure<EndRMacSessionResponse, SmartCardError>(
                SmartCardError.InvalidData("Response data cannot be null")
            );
        }

        if (responseData.Length != 8)
        {
            return Result.Failure<EndRMacSessionResponse, SmartCardError>(
                SmartCardError.InvalidData($"Response must be exactly 8 bytes, but got {responseData.Length} bytes")
            );
        }

        return Result.Success<EndRMacSessionResponse, SmartCardError>(
            new EndRMacSessionResponse(responseData)
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