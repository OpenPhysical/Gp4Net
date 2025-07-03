using System;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Cryptography.Implementation
{
    /// <summary>
    /// Default implementation of IKeyDerivationContext.
    /// </summary>
    [PublicAPI]
    public class KeyDerivationContext : IKeyDerivationContext
    {
        /// <inheritdoc />
        public byte ProtocolVersion { get; }

        /// <inheritdoc />
        public IKeySet KeySet { get; }

        /// <inheritdoc />
        public byte[] HostChallenge { get; }

        /// <inheritdoc />
        public byte[] CardChallenge { get; }

        /// <inheritdoc />
        public byte[]? SequenceCounter { get; }

        /// <inheritdoc />
        public byte[]? AdditionalParameters { get; }

        /// <summary>
        /// Initializes a new instance of KeyDerivationContext.
        /// </summary>
        /// <param name="protocolVersion">The protocol version.</param>
        /// <param name="keySet">The static key set.</param>
        /// <param name="hostChallenge">The host challenge.</param>
        /// <param name="cardChallenge">The card challenge.</param>
        /// <param name="sequenceCounter">The sequence counter (optional, for SCP02).</param>
        /// <param name="additionalParameters">Additional parameters (optional).</param>
        public KeyDerivationContext(
            byte protocolVersion,
            IKeySet keySet,
            byte[] hostChallenge,
            byte[] cardChallenge,
            byte[]? sequenceCounter = null,
            byte[]? additionalParameters = null
        )
        {
            if (hostChallenge?.Length != 8)
            {
                throw new ArgumentException(
                    "Host challenge must be 8 bytes.",
                    nameof(hostChallenge)
                );
            }

            if (cardChallenge?.Length != 8)
            {
                throw new ArgumentException(
                    "Card challenge must be 8 bytes.",
                    nameof(cardChallenge)
                );
            }

            ProtocolVersion = protocolVersion;
            ArgumentNullException.ThrowIfNull(keySet);
            KeySet = keySet;
            HostChallenge = (byte[])hostChallenge.Clone();
            CardChallenge = (byte[])cardChallenge.Clone();
            SequenceCounter = sequenceCounter != null ? (byte[])sequenceCounter.Clone() : null;
            AdditionalParameters =
                additionalParameters != null ? (byte[])additionalParameters.Clone() : null;
        }
    }

    /// <summary>
    /// Default implementation of ICryptogramContext.
    /// </summary>
    [PublicAPI]
    public class CryptogramContext : ICryptogramContext
    {
        /// <inheritdoc />
        public byte ProtocolVersion { get; }

        /// <inheritdoc />
        public byte[] Key { get; }

        /// <inheritdoc />
        public byte[] Data { get; }

        /// <inheritdoc />
        public CryptogramType Type { get; }

        /// <summary>
        /// Initializes a new instance of CryptogramContext.
        /// </summary>
        /// <param name="protocolVersion">The protocol version.</param>
        /// <param name="key">The key for cryptogram calculation.</param>
        /// <param name="data">The data to calculate cryptogram over.</param>
        /// <param name="type">The cryptogram type.</param>
        public CryptogramContext(byte protocolVersion, byte[] key, byte[] data, CryptogramType type)
        {
            ProtocolVersion = protocolVersion;
            ArgumentNullException.ThrowIfNull(key);
            Key = (byte[])key.Clone();
            ArgumentNullException.ThrowIfNull(data);
            Data = (byte[])data.Clone();
            Type = type;
        }
    }
}
