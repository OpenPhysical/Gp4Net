using JetBrains.Annotations;
using static Gp4Net.Cryptography.CryptoOperations;

namespace Gp4Net.Domain.Keys;

/// <summary>
/// Immutable context for cryptogram calculation operations.
/// </summary>
/// <param name="ProtocolVersionEnum">The protocol version enumeration.</param>
/// <param name="Key">The key to use for cryptogram calculation.</param>
/// <param name="Data">The data to calculate cryptogram over.</param>
/// <param name="Type">The cryptogram type.</param>
[PublicAPI]
public sealed record CryptogramContext(
    ScpVersion ProtocolVersionEnum,
    byte[] Key,
    byte[] Data,
    CryptogramType Type
)
{
    /// <summary>
    /// Gets the protocol version as byte to match interface.
    /// </summary>
    public byte ProtocolVersion => (byte)ProtocolVersionEnum;
}
