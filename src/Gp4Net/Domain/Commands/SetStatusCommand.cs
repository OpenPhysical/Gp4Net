using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Transport;
using WSCT.ISO7816;

namespace Gp4Net.Domain.Commands;

/// <summary>
/// Represents a SET STATUS command for changing lifecycle states.
/// </summary>
public sealed class SetStatusCommand : IApduCommand
{
    private readonly byte _p1;
    private readonly byte _p2;
    private readonly byte[] _data;

    private SetStatusCommand(byte p1, byte p2, byte[] data)
    {
        _p1 = p1;
        _p2 = p2;
        _data = Maybe<byte[]>.From(data).GetValueOrDefault([]);
    }

    /// <inheritdoc />
    public byte Cla => 0x80;

    /// <inheritdoc />
    public byte Ins => 0xF0;

    /// <summary>
    /// Converts this command to a CommandAPDU.
    /// </summary>
    /// <returns>A result containing the CommandAPDU or an error.</returns>
    public Result<CommandAPDU, SmartCardError> ToCommandApdu()
    {
        // Build APDU bytes using immutable construction
        var headerBytes = new byte[] { 0x80, 0xF0, _p1, _p2 };

        var apduBytes =
            _data.Length > 0
                ? headerBytes
                    .Concat([(byte)_data.Length]) // Lc
                    .Concat(_data)
                    .ToArray()
                : headerBytes;

        return Result.Success<CommandAPDU, SmartCardError>(new CommandAPDU(apduBytes));
    }

    /// <summary>
    /// Creates a SET STATUS command.
    /// </summary>
    /// <param name="aid">The AID of the target (empty for card-level operations).</param>
    /// <param name="p1">The P1 parameter (lifecycle state transition).</param>
    /// <returns>The command or an error.</returns>
    public static Result<SetStatusCommand, SmartCardError> Create(byte[] aid, byte p1)
    {
        return Maybe<byte[]>
            .From(aid)
            .Match(
                Some: aidValue => CreateSetStatusCommand(aidValue, p1),
                None: () => SmartCardError.InvalidArgument("AID cannot be null")
            );
    }

    private static Result<SetStatusCommand, SmartCardError> CreateSetStatusCommand(
        byte[] aid,
        byte p1
    )
    {
        // P2 is always 0x00 for SET STATUS
        byte p2 = 0x00;

        // For card-level operations (empty AID), we send a zero-length data field
        byte[] data = aid.Length > 0 ? aid : [];

        return new SetStatusCommand(p1, p2, data);
    }

    /// <summary>
    /// Creates a SET STATUS command for making an application selectable.
    /// </summary>
    /// <param name="aid">The application AID.</param>
    /// <returns>The command or an error.</returns>
    public static Result<SetStatusCommand, SmartCardError> CreateForMakeSelectable(byte[] aid)
    {
        return Maybe<byte[]>
            .From(aid)
            .Match(
                Some: aidValue =>
                    aidValue.Length == 0
                        ? SmartCardError.InvalidArgument("AID is required for make selectable")
                        : Create(aidValue, 0x07),
                None: () => SmartCardError.InvalidArgument("AID is required for make selectable")
            );
    }

    /// <summary>
    /// Creates a SET STATUS command for locking an application.
    /// </summary>
    /// <param name="aid">The application AID.</param>
    /// <returns>The command or an error.</returns>
    public static Result<SetStatusCommand, SmartCardError> CreateForLock(byte[] aid)
    {
        return Maybe<byte[]>
            .From(aid)
            .Match(
                Some: aidValue =>
                    aidValue.Length == 0
                        ? SmartCardError.InvalidArgument("AID is required for lock")
                        : Create(aidValue, 0x83),
                None: () => SmartCardError.InvalidArgument("AID is required for lock")
            );
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

    /// <inheritdoc />
    public CommandAPDU ToApdu()
    {
        return ToCommandApdu().GetValueOrDefault(new CommandAPDU([]));
    }

    /// <inheritdoc />
    public byte[] ToBytes()
    {
        return ToCommandApdu().Map(cmd => cmd.ToBytes()).GetValueOrDefault([]);
    }
}
