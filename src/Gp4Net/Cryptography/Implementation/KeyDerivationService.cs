using System;
using System.Collections.Generic;
using System.Linq;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Cryptography.Implementation
{
    /// <summary>
    /// Implementation of IKeyDerivationService using strategy pattern.
    /// Routes key derivation requests to appropriate protocol-specific strategies.
    /// </summary>
    [PublicAPI]
    public class KeyDerivationService : IKeyDerivationService
    {
        private readonly IEnumerable<IKeyDerivationStrategy> _keyDerivationStrategies;
        private readonly IEnumerable<ICryptogramStrategy> _cryptogramStrategies;
        private readonly ILogger<KeyDerivationService> _logger;

        /// <summary>
        /// Initializes a new instance of KeyDerivationService.
        /// </summary>
        /// <param name="keyDerivationStrategies">The key derivation strategies.</param>
        /// <param name="cryptogramStrategies">The cryptogram calculation strategies.</param>
        /// <param name="logger">The logger.</param>
        public KeyDerivationService(
            IEnumerable<IKeyDerivationStrategy> keyDerivationStrategies,
            IEnumerable<ICryptogramStrategy> cryptogramStrategies,
            ILogger<KeyDerivationService> logger
        )
        {
            ArgumentNullException.ThrowIfNull(keyDerivationStrategies);
            ArgumentNullException.ThrowIfNull(cryptogramStrategies);
            ArgumentNullException.ThrowIfNull(logger);
            _keyDerivationStrategies = keyDerivationStrategies;
            _cryptogramStrategies = cryptogramStrategies;
            _logger = logger;
        }

        /// <inheritdoc />
        public SessionKeys DeriveSessionKeys(IKeyDerivationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            _logger.LogDebug(
                "Deriving session keys for protocol {Protocol}",
                context.ProtocolVersion
            );

            var strategy = _keyDerivationStrategies.FirstOrDefault(s => s.Supports(context));
            if (strategy == null)
            {
                throw new NotSupportedException(
                    $"No key derivation strategy found for protocol {context.ProtocolVersion:X2}"
                );
            }

            _logger.LogDebug(
                "Using strategy {Strategy} for key derivation",
                strategy.GetType().Name
            );

            var sessionKeys = strategy.DeriveSessionKeys(context);

            _logger.LogDebug("Successfully derived session keys");

            return sessionKeys;
        }

        /// <inheritdoc />
        public byte[] CalculateCryptogram(ICryptogramContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            _logger.LogDebug(
                "Calculating {Type} cryptogram for protocol {Protocol}",
                context.Type,
                context.ProtocolVersion
            );

            var strategy = _cryptogramStrategies.FirstOrDefault(s => s.Supports(context));
            if (strategy == null)
            {
                throw new NotSupportedException(
                    $"No cryptogram strategy found for protocol {context.ProtocolVersion:X2} and type {context.Type}"
                );
            }

            _logger.LogDebug(
                "Using strategy {Strategy} for cryptogram calculation",
                strategy.GetType().Name
            );

            var cryptogram = strategy.CalculateCryptogram(context);

            _logger.LogDebug(
                "Successfully calculated cryptogram: {Length} bytes",
                cryptogram.Length
            );

            return cryptogram;
        }
    }
}
