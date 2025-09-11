using JetBrains.Annotations;
using WSCT.ISO7816;

namespace Gp4Net.Transport;

/// <summary>
/// Wraps a WSCT CommandAPDU to implement IApduCommand interface.
/// </summary>
[PublicAPI]
public sealed class WrappedApduCommand : IApduCommand
{
    private readonly CommandAPDU _command;
    private readonly byte[] _bytes;

    /// <summary>
    /// Initializes a new instance of WrappedApduCommand.
    /// </summary>
    /// <param name="command">The CommandAPDU to wrap.</param>
    public WrappedApduCommand(CommandAPDU command)
    {
        _command = command;
        _bytes = command.ToBytes();
    }

    /// <summary>
    /// Initializes a new instance of WrappedApduCommand with bytes.
    /// </summary>
    /// <param name="bytes">The APDU bytes.</param>
    public WrappedApduCommand(byte[] bytes)
    {
        _bytes = bytes;
        _command = new CommandAPDU(bytes);
    }

    /// <summary>
    /// Gets the wrapped bytes for direct access.
    /// </summary>
    public byte[] WrappedBytes => _bytes;

    /// <inheritdoc />
    public byte Cla => _command.Cla;

    /// <inheritdoc />
    public byte Ins => _command.Ins;

    /// <summary>
    /// Creates a new WrappedApduCommand from a CommandAPDU.
    /// </summary>
    /// <param name="command">The CommandAPDU to wrap.</param>
    /// <returns>A new WrappedApduCommand.</returns>
    public static WrappedApduCommand Create(CommandAPDU command) => new(command);

    /// <summary>
    /// Creates a new WrappedApduCommand from bytes.
    /// </summary>
    /// <param name="bytes">The APDU bytes.</param>
    /// <returns>A new WrappedApduCommand.</returns>
    public static WrappedApduCommand Create(byte[] bytes) => new(bytes);

    /// <inheritdoc />
    public CommandAPDU ToApdu() => _command;

    /// <inheritdoc />
    public byte[] ToBytes() => _bytes;

    /// <summary>
    /// Implicitly converts a CommandAPDU to a WrappedApduCommand.
    /// </summary>
    /// <param name="command">The CommandAPDU to wrap.</param>
    /// <returns>A WrappedApduCommand.</returns>
    public static implicit operator WrappedApduCommand(CommandAPDU command) => new(command);

    /// <summary>
    /// Implicitly converts a WrappedApduCommand to a CommandAPDU.
    /// </summary>
    /// <param name="wrapped">The wrapped command.</param>
    /// <returns>The underlying CommandAPDU.</returns>
    public static implicit operator CommandAPDU(WrappedApduCommand wrapped) => wrapped._command;
}
