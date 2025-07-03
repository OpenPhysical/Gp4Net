using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Cryptography
{
    /// <summary>
    /// Defines the interface for key derivation operations.
    /// Supports multiple derivation strategies for different secure channel protocols.
    /// </summary>
    [PublicAPI]
    public interface IKeyDerivationService
    {
        /// <summary>
        /// Derives session keys from the given context.
        /// </summary>
        /// <param name="context">The key derivation context containing all necessary parameters.</param>
        /// <returns>The derived session keys.</returns>
        SessionKeys DeriveSessionKeys(IKeyDerivationContext context);

        /// <summary>
        /// Calculates a cryptogram for authentication purposes.
        /// </summary>
        /// <param name="context">The cryptogram calculation context.</param>
        /// <returns>The calculated cryptogram.</returns>
        byte[] CalculateCryptogram(ICryptogramContext context);
    }

    /// <summary>
    /// Represents the context for key derivation operations.
    /// </summary>
    [PublicAPI]
    public interface IKeyDerivationContext
    {
        /// <summary>
        /// Gets the secure channel protocol version.
        /// </summary>
        byte ProtocolVersion { get; }

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
        /// Gets the sequence counter (for SCP02).
        /// </summary>
        byte[]? SequenceCounter { get; }

        /// <summary>
        /// Gets additional derivation parameters.
        /// </summary>
        byte[]? AdditionalParameters { get; }
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

    /// <summary>
    /// Strategy interface for protocol-specific key derivation.
    /// </summary>
    [PublicAPI]
    public interface IKeyDerivationStrategy
    {
        /// <summary>
        /// Gets whether this strategy supports the given context.
        /// </summary>
        /// <param name="context">The key derivation context.</param>
        /// <returns>True if supported, false otherwise.</returns>
        bool Supports(IKeyDerivationContext context);

        /// <summary>
        /// Derives session keys using this strategy.
        /// </summary>
        /// <param name="context">The key derivation context.</param>
        /// <returns>The derived session keys.</returns>
        SessionKeys DeriveSessionKeys(IKeyDerivationContext context);
    }

    /// <summary>
    /// Strategy interface for protocol-specific cryptogram calculation.
    /// </summary>
    [PublicAPI]
    public interface ICryptogramStrategy
    {
        /// <summary>
        /// Gets whether this strategy supports the given context.
        /// </summary>
        /// <param name="context">The cryptogram context.</param>
        /// <returns>True if supported, false otherwise.</returns>
        bool Supports(ICryptogramContext context);

        /// <summary>
        /// Calculates a cryptogram using this strategy.
        /// </summary>
        /// <param name="context">The cryptogram context.</param>
        /// <returns>The calculated cryptogram.</returns>
        byte[] CalculateCryptogram(ICryptogramContext context);
    }
}
