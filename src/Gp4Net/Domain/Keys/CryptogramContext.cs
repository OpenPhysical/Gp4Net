using Gp4Net.Cryptography;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Keys;

/// <summary>
/// Immutable context for cryptogram calculation operations.
/// </summary>
/// <param name="ProtocolVersion">The protocol version byte.</param>
/// <param name="Key">The key to use for cryptogram calculation.</param>
/// <param name="Data">The data to calculate cryptogram over.</param>
/// <param name="Type">The cryptogram type.</param>
[PublicAPI]
public sealed record CryptogramContext(
    byte ProtocolVersion,
    byte[] Key,
    byte[] Data,
    CryptogramType Type) : ICryptogramContext;