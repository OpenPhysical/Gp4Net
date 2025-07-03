using System;
using Gp4Net.Constants;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.Cryptography.Strategies
{
    /// <summary>
    /// Cryptogram calculation strategy for SCP02 protocol.
    /// Implements 3DES-based cryptogram and MAC calculation.
    /// </summary>
    [PublicAPI]
    public class Scp02CryptogramStrategy : ICryptogramStrategy
    {
        private readonly ILogger<Scp02CryptogramStrategy> _logger;

        /// <summary>
        /// Initializes a new instance of Scp02CryptogramStrategy.
        /// </summary>
        /// <param name="logger">The logger.</param>
        public Scp02CryptogramStrategy(ILogger<Scp02CryptogramStrategy> logger)
        {
            ArgumentNullException.ThrowIfNull(logger);
            _logger = logger;
        }

        /// <inheritdoc />
        public bool Supports(ICryptogramContext context)
        {
            return context.ProtocolVersion == ProtocolIdentifiers.Scp02;
        }

        /// <inheritdoc />
        public byte[] CalculateCryptogram(ICryptogramContext context)
        {
            if (!Supports(context))
            {
                throw new NotSupportedException(
                    $"SCP02 cryptogram strategy does not support protocol {context.ProtocolVersion:X2}"
                );
            }

            _logger.LogDebug(
                "Calculating SCP02 {Type} cryptogram with {KeyLength}-byte key",
                context.Type,
                context.Key.Length
            );

            return context.Type switch
            {
                CryptogramType.CardCryptogram => CalculateCardCryptogram(context),
                CryptogramType.HostCryptogram => CalculateHostCryptogram(context),
                CryptogramType.CommandMac => CalculateCommandMac(context),
                CryptogramType.ResponseMac => CalculateResponseMac(context),
                _
                    => throw new NotSupportedException(
                        $"Cryptogram type {context.Type} not supported for SCP02"
                    ),
            };
        }

        /// <summary>
        /// Calculates the card cryptogram for SCP02.
        /// </summary>
        private byte[] CalculateCardCryptogram(ICryptogramContext context)
        {
            // For SCP02, card cryptogram is calculated over:
            // Host Challenge || Card Challenge || Padding
            var cryptogram = Calculate3DesMac(context.Key, context.Data);

            _logger.LogDebug("Calculated SCP02 card cryptogram");
            return cryptogram;
        }

        /// <summary>
        /// Calculates the host cryptogram for SCP02.
        /// </summary>
        private byte[] CalculateHostCryptogram(ICryptogramContext context)
        {
            // For SCP02, host cryptogram is calculated over:
            // Card Challenge || Host Challenge || Padding
            var cryptogram = Calculate3DesMac(context.Key, context.Data);

            _logger.LogDebug("Calculated SCP02 host cryptogram");
            return cryptogram;
        }

        /// <summary>
        /// Calculates a command MAC for SCP02.
        /// </summary>
        private byte[] CalculateCommandMac(ICryptogramContext context)
        {
            // For SCP02, use ISO 9797-1 MAC Algorithm 3 (retail MAC)
            var mac = CalculateRetailMac(context.Key, context.Data);

            _logger.LogDebug("Calculated SCP02 command MAC");
            return mac;
        }

        /// <summary>
        /// Calculates a response MAC for SCP02.
        /// </summary>
        private byte[] CalculateResponseMac(ICryptogramContext context)
        {
            // For SCP02, response MAC uses the same algorithm as command MAC
            var mac = CalculateRetailMac(context.Key, context.Data);

            _logger.LogDebug("Calculated SCP02 response MAC");
            return mac;
        }

        /// <summary>
        /// Calculates 3DES MAC for cryptogram calculation.
        /// </summary>
        private byte[] Calculate3DesMac(byte[] key, byte[] data)
        {
            // Use ISO 9797-1 MAC Algorithm 3 for cryptogram calculation
            var engine = new DesEdeEngine();
            var mac = new ISO9797Alg3Mac(engine);
            mac.Init(new KeyParameter(key));
            mac.BlockUpdate(data, 0, data.Length);

            var result = new byte[8];
            _ = mac.DoFinal(result, 0);

            return result;
        }

        /// <summary>
        /// Calculates retail MAC (ISO 9797-1 Algorithm 3) for SCP02.
        /// This is the standard MAC algorithm for SCP02 command and response MACs.
        /// </summary>
        private byte[] CalculateRetailMac(byte[] key, byte[] data)
        {
            // Retail MAC algorithm:
            // 1. Apply DES-CBC to all blocks except the last using the first 8 bytes of the key
            // 2. Apply 3DES to the last block using the full key

            if (data.Length == 0)
            {
                throw new ArgumentException(
                    "Data cannot be empty for MAC calculation",
                    nameof(data)
                );
            }

            // Pad data to multiple of 8 bytes using ISO 7816-4 padding
            var paddedData = ApplyIso7816Padding(data);

            // If we only have one block, use 3DES directly
            if (paddedData.Length == 8)
            {
                return Calculate3DesBlock(key, paddedData);
            }

            // For multiple blocks, use retail MAC algorithm
            var singleDesKey = new byte[8];
            Array.Copy(key, 0, singleDesKey, 0, 8);

            // Process all blocks except the last with single DES
            var iv = new byte[8]; // Start with zero IV
            var desEngine = new DesEngine();

            for (int i = 0; i < paddedData.Length - 8; i += 8)
            {
                var block = new byte[8];
                Array.Copy(paddedData, i, block, 0, 8);

                // XOR with IV
                for (int j = 0; j < 8; j++)
                {
                    block[j] ^= iv[j];
                }

                // Encrypt with single DES
                desEngine.Init(true, new KeyParameter(singleDesKey));
                _ = desEngine.ProcessBlock(block, 0, iv, 0);
            }

            // Process the last block with 3DES
            var lastBlock = new byte[8];
            Array.Copy(paddedData, paddedData.Length - 8, lastBlock, 0, 8);

            // XOR with previous result
            for (int j = 0; j < 8; j++)
            {
                lastBlock[j] ^= iv[j];
            }

            return Calculate3DesBlock(key, lastBlock);
        }

        /// <summary>
        /// Calculates 3DES encryption of a single 8-byte block.
        /// </summary>
        private byte[] Calculate3DesBlock(byte[] key, byte[] block)
        {
            var engine = new DesEdeEngine();
            engine.Init(true, new KeyParameter(key));

            var result = new byte[8];
            _ = engine.ProcessBlock(block, 0, result, 0);

            return result;
        }

        /// <summary>
        /// Applies ISO 7816-4 padding to data.
        /// </summary>
        private byte[] ApplyIso7816Padding(byte[] data)
        {
            var blockSize = 8;
            var paddingLength = blockSize - (data.Length % blockSize);

            var paddedData = new byte[data.Length + paddingLength];
            Array.Copy(data, 0, paddedData, 0, data.Length);

            // ISO 7816-4 padding: 0x80 followed by zeros
            paddedData[data.Length] = 0x80;
            // Remaining bytes are already zero from array initialization

            return paddedData;
        }
    }
}
