using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Cryptography;

/// <summary>
/// Defines the interface for key derivation operations.
/// Supports multiple derivation strategies for different secure channel protocols.
/// All operations use Result&lt;T&gt; for error handling and Maybe&lt;T&gt; for optional values.
/// </summary>
[PublicAPI]
public interface IKeyDerivationService
{
    /// <summary>
    /// Derives session keys from the given context.
    /// </summary>
    /// <param name="context">The key derivation context containing all necessary parameters.</param>
    /// <returns>The derived session keys or an error.</returns>
    Result<SessionKeys, SmartCardError> DeriveSessionKeys(IKeyDerivationContext context);

    /// <summary>
    /// Calculates a cryptogram for authentication purposes.
    /// </summary>
    /// <param name="context">The cryptogram calculation context.</param>
    /// <returns>The calculated cryptogram or an error.</returns>
    Result<byte[], SmartCardError> CalculateCryptogram(ICryptogramContext context);
}

/// <summary>
/// Represents the context for key derivation operations.
/// Uses Maybe&lt;T&gt; for optional values to avoid nulls.
/// </summary>
[PublicAPI]
public interface IKeyDerivationContext
{
    /// <summary>
    /// Gets the secure channel protocol version.
    /// </summary>
    ScpVersion Protocol { get; }

    /// <summary>
    /// Gets the static key set.
    /// </summary>
    IKeySet KeySet { get; }

    /// <summary>
    /// Gets the host challenge.
    /// </summary>
    byte[] HostChallenge { get; }

    /// <summary>
    /// Gets the card challenge.
    /// </summary>
    byte[] CardChallenge { get; }

    /// <summary>
    /// Gets the sequence counter (required for SCP02, optional for SCP03).
    /// </summary>
    Maybe<byte[]> SequenceCounter { get; }

    /// <summary>
    /// Gets the SCP implementation details.
    /// </summary>
    Maybe<Gp4Net.Domain.Protocol.ScpImplementation> Implementation { get; }
    
    /// <summary>
    /// Gets the implementation parameter value for use in derivation.
    /// </summary>
    /// <returns>The implementation parameter byte value.</returns>
    byte GetImplementationParameter();
}

/// <summary>
/// Represents the context for cryptogram calculation.
/// </summary>
[PublicAPI]
public interface ICryptogramContext
{
    /// <summary>
    /// Gets the secure channel protocol version.
    /// </summary>
    byte ProtocolVersion { get; }

    /// <summary>
    /// Gets the key to use for cryptogram calculation.
    /// </summary>
    byte[] Key { get; }

    /// <summary>
    /// Gets the data to calculate the cryptogram over.
    /// </summary>
    byte[] Data { get; }

    /// <summary>
    /// Gets the cryptogram type (card cryptogram, host cryptogram, etc.).
    /// </summary>
    CryptogramType Type { get; }
}

/// <summary>
/// Defines the types of cryptograms that can be calculated.
/// </summary>
public enum CryptogramType
{
    /// <summary>
    /// Card cryptogram for authentication.
    /// </summary>
    CardCryptogram,

    /// <summary>
    /// Host cryptogram for authentication.
    /// </summary>
    HostCryptogram,

    /// <summary>
    /// Command MAC (C-MAC).
    /// </summary>
    CommandMac,

    /// <summary>
    /// Response MAC (R-MAC).
    /// </summary>
    ResponseMac,
}


