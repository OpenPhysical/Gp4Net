using System;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Protocol
{
    /// <summary>
    /// Contains the context information needed for secure channel establishment.
    /// Stores authentication data required for completing the authentication process.
    /// </summary>
    [PublicAPI]
    public class SecureChannelContext
    {
        /// <summary>
        /// Gets the host challenge used in INITIALIZE UPDATE.
        /// </summary>
        public byte[] HostChallenge { get; }

        /// <summary>
        /// Gets the INITIALIZE UPDATE response.
        /// </summary>
        public InitializeUpdateResponse InitializeUpdateResponse { get; }

        /// <summary>
        /// Gets the derived session keys.
        /// </summary>
        public SessionKeys SessionKeys { get; }

        /// <summary>
        /// Gets the protocol version.
        /// </summary>
        public byte ProtocolVersion { get; }

        /// <summary>
        /// Gets the key set used for authentication.
        /// </summary>
        public IKeySet KeySet { get; }

        /// <summary>
        /// Initializes a new instance of SecureChannelContext.
        /// </summary>
        /// <param name="hostChallenge">The host challenge (8 bytes).</param>
        /// <param name="initializeUpdateResponse">The INITIALIZE UPDATE response.</param>
        /// <param name="sessionKeys">The derived session keys.</param>
        /// <param name="protocolVersion">The protocol version.</param>
        /// <param name="keySet">The key set used for authentication.</param>
        public SecureChannelContext(
            byte[] hostChallenge,
            InitializeUpdateResponse initializeUpdateResponse,
            SessionKeys sessionKeys,
            byte protocolVersion,
            IKeySet keySet
        )
        {
            if (hostChallenge?.Length != 8)
            {
                throw new ArgumentException(
                    "Host challenge must be 8 bytes.",
                    nameof(hostChallenge)
                );
            }

            HostChallenge = (byte[])hostChallenge.Clone();
            ArgumentNullException.ThrowIfNull(initializeUpdateResponse);
            ArgumentNullException.ThrowIfNull(sessionKeys);
            InitializeUpdateResponse = initializeUpdateResponse;
            SessionKeys = sessionKeys;
            ProtocolVersion = protocolVersion;
            ArgumentNullException.ThrowIfNull(keySet);
            KeySet = keySet;
        }
    }
}
