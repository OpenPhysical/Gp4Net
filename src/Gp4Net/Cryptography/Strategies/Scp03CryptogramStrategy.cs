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
    /// Cryptogram calculation strategy for SCP03 protocol.
    /// Implements CMAC-AES based cryptogram calculation.
    /// </summary>
    [PublicAPI]
    public class Scp03CryptogramStrategy : ICryptogramStrategy
    {
        private readonly ILogger<Scp03CryptogramStrategy> _logger;

        /// <summary>
        /// Initializes a new instance of Scp03CryptogramStrategy.
        /// </summary>
        /// <param name="logger">The logger.</param>
        public Scp03CryptogramStrategy(ILogger<Scp03CryptogramStrategy> logger)
        {
            ArgumentNullException.ThrowIfNull(logger);
            _logger = logger;
        }

        /// <inheritdoc />
        public bool Supports(ICryptogramContext context)
        {
            return context.ProtocolVersion == ProtocolIdentifiers.Scp03;
        }

        /// <inheritdoc />
        public byte[] CalculateCryptogram(ICryptogramContext context)
        {
            if (!Supports(context))
            {
                throw new NotSupportedException(
                    $"SCP03 cryptogram strategy does not support protocol {context.ProtocolVersion:X2}"
                );
            }

            _logger.LogDebug(
                "Calculating SCP03 {Type} cryptogram with {KeyLength}-byte key",
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
                        $"Cryptogram type {context.Type} not supported for SCP03"
                    ),
            };
        }

        /// <summary>
        /// Calculates the card cryptogram for SCP03.
        /// </summary>
        private byte[] CalculateCardCryptogram(ICryptogramContext context)
        {
            // Card cryptogram data: Label || 0x00 || 0x00 || L || Host Challenge || Card Challenge
            var data = BuildCryptogramData(DerivationConstants.CardCryptogram, context.Data);
            var cryptogram = CalculateCmac(context.Key, data);

            _logger.LogDebug("Calculated SCP03 card cryptogram");
            return cryptogram;
        }

        /// <summary>
        /// Calculates the host cryptogram for SCP03.
        /// </summary>
        private byte[] CalculateHostCryptogram(ICryptogramContext context)
        {
            // Host cryptogram data: Label || 0x01 || 0x00 || L || Host Challenge || Card Challenge
            var data = BuildCryptogramData(DerivationConstants.HostCryptogram, context.Data);
            var cryptogram = CalculateCmac(context.Key, data);

            _logger.LogDebug("Calculated SCP03 host cryptogram");
            return cryptogram;
        }

        /// <summary>
        /// Calculates a command MAC for SCP03.
        /// </summary>
        private byte[] CalculateCommandMac(ICryptogramContext context)
        {
            // For SCP03, command MAC is calculated directly over the data using CMAC-AES
            var mac = CalculateCmac(context.Key, context.Data);

            _logger.LogDebug("Calculated SCP03 command MAC");
            return mac;
        }

        /// <summary>
        /// Calculates a response MAC for SCP03.
        /// </summary>
        private byte[] CalculateResponseMac(ICryptogramContext context)
        {
            // For SCP03, response MAC is calculated directly over the data using CMAC-AES
            var mac = CalculateCmac(context.Key, context.Data);

            _logger.LogDebug("Calculated SCP03 response MAC");
            return mac;
        }

        /// <summary>
        /// Builds cryptogram data with the SCP03 structure.
        /// </summary>
        private byte[] BuildCryptogramData(byte derivationConstant, byte[] challengeData)
        {
            // Structure: Label || DerivationConstant || 0x00 || L || Challenge Data
            var data = new byte[11 + 1 + 1 + 2 + challengeData.Length];
            var offset = 0;

            // Label (11 bytes of 0x00)
            Array.Copy(DerivationConstants.Scp03Label, 0, data, offset, 11);
            offset += 11;

            // Derivation constant
            data[offset++] = derivationConstant;

            // Separator
            data[offset++] = 0x00;

            // Length (64 bits = 8 bytes for cryptogram output)
            data[offset++] = 0x00;
            data[offset++] = 0x40;

            // Challenge data
            Array.Copy(challengeData, 0, data, offset, challengeData.Length);

            return data;
        }

        /// <summary>
        /// Calculates CMAC-AES with 64-bit output.
        /// </summary>
        private byte[] CalculateCmac(byte[] key, byte[] data)
        {
            var cmac = new CMac(new AesEngine(), 64); // 64-bit MAC (8 bytes)
            cmac.Init(new KeyParameter(key));
            cmac.BlockUpdate(data, 0, data.Length);

            var result = new byte[8];
            _ = cmac.DoFinal(result, 0);

            return result;
        }
    }
}
