using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Transport;

namespace Gp4Net.Domain.Commands;

/// <summary>
/// Represents a SET STATUS command for changing lifecycle states.
/// </summary>
public sealed class SetStatusCommand : BaseApduCommand
{
    private readonly byte _p1;
    private readonly byte _p2;
    private readonly byte[] _data;

    private SetStatusCommand(byte p1, byte p2, byte[] data)
    {
        _p1 = p1;
        _p2 = p2;
        _data = data ?? [];
    }

    /// <inheritdoc/>
    public override byte Cla => 0x80;

    /// <inheritdoc/>
    public override byte Ins => 0xF0;

    /// <inheritdoc/>
    public override byte P1 => _p1;

    /// <inheritdoc/>
    public override byte P2 => _p2;

    /// <inheritdoc/>
    public override byte[] Data => _data;

    /// <inheritdoc/>
    public override Maybe<int> ExpectedResponseLength => Maybe<int>.None;

    /// <summary>
    /// Creates a SET STATUS command.
    /// </summary>
    /// <param name="aid">The AID of the target (empty for card-level operations).</param>
    /// <param name="p1">The P1 parameter (lifecycle state transition).</param>
    /// <returns>The command or an error.</returns>
    public static Result<SetStatusCommand, SmartCardError> Create(byte[] aid, byte p1)
    {
        if (aid == null)
        {
            return Result.Failure<SetStatusCommand, SmartCardError>(
                SmartCardError.InvalidArgument("AID cannot be null"));
        }

        // P2 is always 0x00 for SET STATUS
        byte p2 = 0x00;

        // For card-level operations (empty AID), we send a zero-length data field
        byte[] data = aid.Length > 0 ? aid : [];

        return Result.Success<SetStatusCommand, SmartCardError>(
            new SetStatusCommand(p1, p2, data));
    }

    /// <summary>
    /// Creates a SET STATUS command for making an application selectable.
    /// </summary>
    /// <param name="aid">The application AID.</param>
    /// <returns>The command or an error.</returns>
    public static Result<SetStatusCommand, SmartCardError> CreateForMakeSelectable(byte[] aid)
    {
        if (aid == null || aid.Length == 0)
        {
            return Result.Failure<SetStatusCommand, SmartCardError>(
                SmartCardError.InvalidArgument("AID is required for make selectable"));
        }

        // P1=0x07 for make selectable
        return Create(aid, 0x07);
    }

    /// <summary>
    /// Creates a SET STATUS command for locking an application.
    /// </summary>
    /// <param name="aid">The application AID.</param>
    /// <returns>The command or an error.</returns>
    public static Result<SetStatusCommand, SmartCardError> CreateForLock(byte[] aid)
    {
        if (aid == null || aid.Length == 0)
        {
            return Result.Failure<SetStatusCommand, SmartCardError>(
                SmartCardError.InvalidArgument("AID is required for lock"));
        }

        // P1=0x83 for lock
        return Create(aid, 0x83);
    }

    /// <summary>
    /// Creates a SET STATUS command for card lock.
    /// </summary>
    /// <returns>The command or an error.</returns>
    public static Result<SetStatusCommand, SmartCardError> CreateForCardLock()
    {
        return Create([], 0x7F);
    }

    /// <summary>
    /// Creates a SET STATUS command for card termination.
    /// </summary>
    /// <returns>The command or an error.</returns>
    public static Result<SetStatusCommand, SmartCardError> CreateForCardTerminate()
    {
        return Create([], 0xFF);
    }
}