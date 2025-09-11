// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Transport;
using JetBrains.Annotations;
using WSCT.ISO7816;

namespace Gp4Net.Domain.Commands;

/// <summary>
/// Base class for GlobalPlatform APDU commands that extends WSCT CommandAPDU.
/// Provides common functionality and factory patterns for functional-style command creation.
/// </summary>
[PublicAPI]
public abstract class GpCommandBase : CommandAPDU, IApduCommand
{
    /// <summary>
    /// Protected constructor for CC1 commands (no data, no response).
    /// </summary>
    protected GpCommandBase(byte cla, byte ins, byte p1, byte p2)
        : base(cla, ins, p1, p2)
    {
    }

    /// <summary>
    /// Protected constructor for CC2 commands (no data, with response).
    /// </summary>
    protected GpCommandBase(byte cla, byte ins, byte p1, byte p2, uint le)
        : base(cla, ins, p1, p2, le)
    {
    }

    /// <summary>
    /// Protected constructor for CC3 commands (with data, no response).
    /// </summary>
    protected GpCommandBase(byte cla, byte ins, byte p1, byte p2, uint lc, byte[] udc)
        : base(cla, ins, p1, p2, lc, udc)
    {
    }

    /// <summary>
    /// Protected constructor for CC4 commands (with data, with response).
    /// </summary>
    protected GpCommandBase(byte cla, byte ins, byte p1, byte p2, uint lc, byte[] udc, uint le)
        : base(cla, ins, p1, p2, lc, udc, le)
    {
    }

    /// <summary>
    /// Factory method for creating commands with validation in functional style.
    /// </summary>
    /// <typeparam name="T">The command type to create.</typeparam>
    /// <param name="factory">Factory function to create the command.</param>
    /// <param name="validations">Validation conditions and error messages.</param>
    /// <returns>A Result containing the command or an error.</returns>
    protected static Result<T, SmartCardError> CreateValidated<T>(
        Func<T> factory,
        params (bool condition, string error)[] validations)
        where T : GpCommandBase
    {
        var errors = validations
            .Where(v => !v.condition)
            .Select(v => v.error)
            .ToList();

        return errors.Any()
            ? Result.Failure<T, SmartCardError>(SmartCardError.InvalidData(errors.First()))
            : Result.Try(
                factory,
                ex => SmartCardError.InvalidData($"Failed to create command: {ex.Message}"));
    }

    /// <summary>
    /// Gets the binary representation of this command.
    /// This property is already provided by WSCT's CommandAPDU base class.
    /// </summary>
    public byte[] ToBytes() => BinaryCommand;

    /// <summary>
    /// Gets the command as a WSCT CommandAPDU.
    /// Since this class extends CommandAPDU, it returns itself.
    /// </summary>
    public CommandAPDU ToApdu() => this;

    /// <summary>
    /// Creates a Result containing this command as a CommandAPDU.
    /// </summary>
    /// <returns>A successful Result containing this command.</returns>
    public Result<CommandAPDU, SmartCardError> ToCommandApdu()
    {
        return Result.Success<CommandAPDU, SmartCardError>(this);
    }
}