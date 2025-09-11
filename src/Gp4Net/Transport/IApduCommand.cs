using JetBrains.Annotations;
using WSCT.ISO7816;

namespace Gp4Net.Transport;

/// <summary>
/// Represents a command that can be converted to an APDU.
/// </summary>
[PublicAPI]
public interface IApduCommand
{
    /// <summary>
    /// Gets the command class byte.
    /// </summary>
    byte Cla { get; }

    /// <summary>
    /// Gets the command instruction byte.
    /// </summary>
    byte Ins { get; }

    /// <summary>
    /// Converts this command to a WSCT CommandAPDU.
    /// </summary>
    /// <returns>The CommandAPDU representation of this command.</returns>
    CommandAPDU ToApdu();

    /// <summary>
    /// Gets the raw APDU bytes for this command.
    /// </summary>
    /// <returns>The APDU bytes.</returns>
    byte[] ToBytes();
}
