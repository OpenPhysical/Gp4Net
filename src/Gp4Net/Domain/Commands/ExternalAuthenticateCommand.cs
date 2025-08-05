// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Commands;

/// <summary>
/// Represents the EXTERNAL AUTHENTICATE command for secure channel authentication.
/// </summary>
[PublicAPI]
public class ExternalAuthenticateCommand : BaseApduCommand
{
    /// <summary>
    /// The command class byte.
    /// </summary>
    public const byte ClassByte = 0x84;

    /// <summary>
    /// The command instruction byte.
    /// </summary>
    public const byte InstructionByte = 0x82;

    /// <summary>
    /// Gets the security level.
    /// </summary>
    public SecurityLevel SecurityLevel { get; }

    /// <summary>
    /// Gets the host cryptogram.
    /// </summary>
    public byte[] HostCryptogram { get; }

    /// <summary>
    /// Gets the MAC value (empty array when C-MAC is not requested).
    /// </summary>
    public byte[] Mac { get; }

    /// <summary>
    /// Initializes a new instance of the ExternalAuthenticateCommand class.
    /// </summary>
    /// <param name="securityLevel">The security level for the secure channel.</param>
    /// <param name="hostCryptogram">The host cryptogram (8 bytes).</param>
    /// <param name="mac">The MAC value (8 bytes or empty).</param>
    private ExternalAuthenticateCommand(
        SecurityLevel securityLevel,
        byte[] hostCryptogram,
        byte[] mac
    )
    {
        SecurityLevel = securityLevel;
        HostCryptogram = (byte[])hostCryptogram.Clone();
        Mac = (byte[])mac.Clone();
    }

    /// <summary>
    /// Creates a new ExternalAuthenticateCommand instance with MAC.
    /// </summary>
    /// <param name="securityLevel">The security level for the secure channel.</param>
    /// <param name="hostCryptogram">The host cryptogram (8 bytes).</param>
    /// <param name="mac">The MAC value (8 bytes).</param>
    /// <returns>A result containing the command or an error.</returns>
    public static Result<ExternalAuthenticateCommand, SmartCardError> CreateWithMac(
        SecurityLevel securityLevel,
        byte[] hostCryptogram,
        byte[] mac
    )
    {
        if (hostCryptogram == null)
        {
            return Result.Failure<ExternalAuthenticateCommand, SmartCardError>(
                SmartCardError.InvalidArgument("Host cryptogram cannot be null"));
        }

        if (mac == null)
        {
            return Result.Failure<ExternalAuthenticateCommand, SmartCardError>(
                SmartCardError.InvalidArgument("MAC cannot be null"));
        }

        if (hostCryptogram.Length != 8)
        {
            return Result.Failure<ExternalAuthenticateCommand, SmartCardError>(
                SmartCardError.InvalidArgument($"Host cryptogram must be 8 bytes, got {hostCryptogram.Length}"));
        }

        if (mac.Length != 8)
        {
            return Result.Failure<ExternalAuthenticateCommand, SmartCardError>(
                SmartCardError.InvalidArgument($"MAC must be 8 bytes, got {mac.Length}"));
        }

        return Result.Success<ExternalAuthenticateCommand, SmartCardError>(
            new ExternalAuthenticateCommand(securityLevel, hostCryptogram, mac));
    }

    /// <summary>
    /// Creates a new ExternalAuthenticateCommand instance without MAC.
    /// </summary>
    /// <param name="securityLevel">The security level for the secure channel.</param>
    /// <param name="hostCryptogram">The host cryptogram (8 bytes).</param>
    /// <returns>A result containing the command or an error.</returns>
    public static Result<ExternalAuthenticateCommand, SmartCardError> CreateWithoutMac(
        SecurityLevel securityLevel,
        byte[] hostCryptogram
    )
    {
        if (hostCryptogram == null)
        {
            return Result.Failure<ExternalAuthenticateCommand, SmartCardError>(
                SmartCardError.InvalidArgument("Host cryptogram cannot be null"));
        }

        if (hostCryptogram.Length != 8)
        {
            return Result.Failure<ExternalAuthenticateCommand, SmartCardError>(
                SmartCardError.InvalidArgument($"Host cryptogram must be 8 bytes, got {hostCryptogram.Length}"));
        }

        return Result.Success<ExternalAuthenticateCommand, SmartCardError>(
            new ExternalAuthenticateCommand(securityLevel, hostCryptogram, []));
    }

    /// <inheritdoc />
    public override byte Cla
    {
        get
        {
            return ClassByte;
        }
    }

    /// <inheritdoc />
    public override byte Ins
    {
        get
        {
            return InstructionByte;
        }
    }

    /// <inheritdoc />
    public override byte P1
    {
        get
        {
            return (byte)SecurityLevel;
        }
    }

    /// <inheritdoc />
    public override byte P2
    {
        get
        {
            return 0x00;
        }
    }

    /// <inheritdoc />
    public override byte[] Data
    {
        get
        {
            if (Mac.Length == 0)
            {
                return HostCryptogram;
            }

            var data = new byte[HostCryptogram.Length + Mac.Length];
            Array.Copy(HostCryptogram, 0, data, 0, HostCryptogram.Length);
            Array.Copy(Mac, 0, data, HostCryptogram.Length, Mac.Length);
            return data;
        }
    }

    /// <inheritdoc />
    public override Maybe<int> ExpectedResponseLength
    {
        get
        {
            return Maybe<int>.None;

            // No response data expected
        }
    }


    /// <summary>
    /// Returns a string representation of this command.
    /// </summary>
    public override string ToString()
    {
        return "EXTERNAL AUTHENTICATE";
    }
}