using JetBrains.Annotations;
using WSCT.ISO7816;

namespace Gp4Net.Transport;

/// <summary>
/// Extensions to make WSCT CommandAPDU compatible with IApduCommand interface.
/// This allows direct use of CommandAPDU instances in the functional processing pipeline
/// without the need for wrapping.
/// </summary>
[PublicAPI]
public static class CommandApduExtensions
{
    /// <summary>
    /// Wraps a CommandAPDU in an adapter that implements IApduCommand.
    /// </summary>
    /// <param name="command">The CommandAPDU to adapt.</param>
    /// <returns>An IApduCommand adapter.</returns>
    public static IApduCommand AsApduCommand(this CommandAPDU command) => new CommandApduAdapter(command);

    /// <summary>
    /// Adapter class that makes CommandAPDU implement IApduCommand.
    /// This is a lightweight wrapper that provides the required interface without additional overhead.
    /// </summary>
    private sealed class CommandApduAdapter : IApduCommand
    {
        private readonly CommandAPDU _command;

        public CommandApduAdapter(CommandAPDU command)
        {
            _command = command;
        }

        public byte Cla => _command.Cla;
        public byte Ins => _command.Ins;

        public CommandAPDU ToApdu() => _command;
        public byte[] ToBytes() => _command.BinaryCommand;

        /// <summary>
        /// Implicit conversion from CommandAPDU to adapter.
        /// </summary>
        public static implicit operator CommandApduAdapter(CommandAPDU command) => new(command);

        /// <summary>
        /// Implicit conversion from adapter to CommandAPDU.
        /// </summary>
        public static implicit operator CommandAPDU(CommandApduAdapter adapter) => adapter._command;
    }
}