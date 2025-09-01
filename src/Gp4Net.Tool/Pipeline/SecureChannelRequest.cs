using System.Collections.Generic;
using CSharpFunctionalExtensions;
using Gp4Net.Domain;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Pipeline;

/// <summary>
/// Immutable request for secure channel establishment.
/// Pure data structure for functional secure channel pipeline.
/// </summary>
[PublicAPI]
public sealed record SecureChannelRequest(
    Maybe<string> KeysetName,
    Maybe<ExplicitKeys> ExplicitKeys,
    Maybe<Dictionary<string, string>> KeysetParameters,
    SecurityLevel SecurityLevel,
    byte KeyVersion
);

/// <summary>
/// Immutable container for explicit key specifications.
/// Pure value object for functional key management.
/// </summary>
[PublicAPI]
public sealed record ExplicitKeys(byte[] EncryptionKey, byte[] MacKey, byte[] DataEncryptionKey);
