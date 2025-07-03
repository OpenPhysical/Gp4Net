using System.Collections.Generic;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Services
{
    /// <summary>
    /// Interface for resolving keysets from script functions or explicit parameters.
    /// </summary>
    [PublicAPI]
    public interface IKeysetResolver
    {
        /// <summary>
        /// Resolves a keyset from various sources.
        /// </summary>
        /// <param name="keysetSpec">The keyset specification (e.g., 'gp_test_keys' or 'script:function').</param>
        /// <param name="keysetParams">Parameters for the keyset function.</param>
        /// <param name="encKey">Explicit encryption key (overrides keyset).</param>
        /// <param name="macKey">Explicit MAC key (overrides keyset).</param>
        /// <param name="dekKey">Explicit DEK key (overrides keyset).</param>
        /// <param name="keyVersion">The key version.</param>
        /// <param name="cardResponse">Optional card response for key diversification.</param>
        /// <returns>The resolved keyset.</returns>
        IKeySet ResolveKeyset(
            string? keysetSpec,
            Dictionary<string, string>? keysetParams,
            byte[]? encKey,
            byte[]? macKey,
            byte[]? dekKey,
            byte keyVersion,
            InitializeUpdateResponse? cardResponse = null
        );
    }
}
