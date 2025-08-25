using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Gp4Net.Domain.Security;

/// <summary>
/// The one and only cryptogram service. Uses type-safe parameters to make invalid states unrepresentable.
/// Per GP SCP03 v1.1.1 Section 6.2.2: SCP03 cryptograms use data derivation scheme (KDF).
/// Per GP Card Spec v2.3.1 Section E.4.2: SCP02 cryptograms use Full 3DES MAC.
/// </summary>
public sealed class CryptogramService
{
    private readonly ILogger<CryptogramService> _logger;
    private readonly MacService _macService;

    /// <summary>
    /// Initializes the cryptogram service with required dependencies.
    /// </summary>
    /// <param name="logger">Logger instance.</param>
    /// <param name="macService">MAC service for cryptogram calculations.</param>
    public CryptogramService(
        Maybe<ILogger<CryptogramService>> logger = default, 
        Maybe<MacService> macService = default)
    {
        _logger = logger.Match(
            Some: log => log,
            None: () => NullLogger<CryptogramService>.Instance);
        _macService = macService.Match(
            Some: service => service,
            None: () => new MacService(NullLogger<MacService>.Instance));
    }

    /// <summary>
    /// Calculates SCP02 card cryptogram.
    /// Per GP Card Specification v2.3.1 Section E.4.2.1: Uses Full 3DES MAC (ISO 9797-1 Algorithm 1).
    /// Data format: Host Challenge (8) || Sequence Counter (2) || Card Challenge (6) || Padding.
    /// </summary>
    /// <param name="parameters">Validated SCP02 parameters.</param>
    /// <returns>8-byte card cryptogram.</returns>
    public Result<byte[], SmartCardError> CalculateCardCryptogram(Scp02CryptogramParameters parameters)
    {
        _logger.LogDebug("Calculating SCP02 card cryptogram");
        
        // Build cryptogram data: Host Challenge (8) || Sequence Counter (2) || Card Challenge (6) || Padding
        var cryptogramData = new byte[24];
        Array.Copy(parameters.HostChallenge, 0, cryptogramData, 0, 8);
        Array.Copy(parameters.SequenceCounter, 0, cryptogramData, 8, 2);
        Array.Copy(parameters.CardChallenge, 0, cryptogramData, 10, 6);
        cryptogramData[16] = 0x80; // ISO 7816-4 padding

        // Use Full 3DES MAC (ISO 9797-1 Algorithm 1) with S-ENC key
        return _macService.CalculateMac(
            parameters.Keys.SEnc, 
            cryptogramData, 
            ScpVersion.Scp02, 
            MacUsage.Cryptogram, 
            macLength: 8);
    }

    /// <summary>
    /// Calculates SCP03 card cryptogram.
    /// Per GP SCP03 v1.1.1 Section 6.2.2.2: Uses data derivation scheme with S-MAC key.
    /// </summary>
    /// <param name="parameters">Validated SCP03 parameters.</param>
    /// <returns>8-byte card cryptogram.</returns>
    public Result<byte[], SmartCardError> CalculateCardCryptogram(Scp03CryptogramParameters parameters)
    {
        _logger.LogDebug("Calculating SCP03 card cryptogram");
        
        var context = new byte[16];
        Array.Copy(parameters.HostChallenge, 0, context, 0, 8);
        Array.Copy(parameters.CardChallenge, 0, context, 8, 8);
        
        return CalculateScp03DataDerivation(
            parameters.Keys.SMac, 
            context, 
            Gp4Net.Constants.DerivationConstants.CardCryptogram,
            outputLengthBits: 64);
    }

    /// <summary>
    /// Calculates SCP02 host cryptogram.
    /// Per GP Card Specification v2.3.1 Section E.4.2.2: Uses Full 3DES MAC (ISO 9797-1 Algorithm 1).
    /// Data format: Sequence Counter (2) || Card Challenge (6) || Host Challenge (8) || Padding.
    /// </summary>
    /// <param name="parameters">Validated SCP02 parameters.</param>
    /// <returns>8-byte host cryptogram.</returns>
    public Result<byte[], SmartCardError> CalculateHostCryptogram(Scp02CryptogramParameters parameters)
    {
        _logger.LogDebug("Calculating SCP02 host cryptogram");
        
        var cryptogramData = new byte[24];
        Array.Copy(parameters.SequenceCounter, 0, cryptogramData, 0, 2);
        Array.Copy(parameters.CardChallenge, 0, cryptogramData, 2, 6);
        Array.Copy(parameters.HostChallenge, 0, cryptogramData, 8, 8);
        cryptogramData[16] = 0x80; // ISO 7816-4 padding

        return _macService.CalculateMac(
            parameters.Keys.SEnc, 
            cryptogramData, 
            ScpVersion.Scp02, 
            MacUsage.Cryptogram, 
            macLength: 8);
    }

    /// <summary>
    /// Calculates SCP03 host cryptogram.
    /// Per GP SCP03 v1.1.1 Section 6.2.2.3: Uses data derivation scheme with S-MAC key.
    /// </summary>
    /// <param name="parameters">Validated SCP03 parameters.</param>
    /// <returns>8-byte host cryptogram.</returns>
    public Result<byte[], SmartCardError> CalculateHostCryptogram(Scp03CryptogramParameters parameters)
    {
        _logger.LogDebug("Calculating SCP03 host cryptogram");
        
        var context = new byte[16];
        Array.Copy(parameters.HostChallenge, 0, context, 0, 8);
        Array.Copy(parameters.CardChallenge, 0, context, 8, 8);
        
        return CalculateScp03DataDerivation(
            parameters.Keys.SMac, 
            context, 
            Gp4Net.Constants.DerivationConstants.HostCryptogram,
            outputLengthBits: 64);
    }

    /// <summary>
    /// SCP03 data derivation scheme per GP SCP03 v1.1.1 Section 6.2.2.
    /// </summary>
    private Result<byte[], SmartCardError> CalculateScp03DataDerivation(
        byte[] key,
        byte[] context,
        byte derivationConstant,
        int outputLengthBits)
    {
        return Result.Try(() =>
        {
            // Per GP SCP03 v1.1.1 Section 4.1.5 and NIST SP 800-108:
            // Structure: label || separator || L || i || context
            // Where:
            //   - label = 11 zero bytes || 1-byte derivation constant
            //   - separator = 0x00
            //   - L = 2-byte length in bits (big-endian)
            //   - i = 1-byte counter (0x01 for first block)
            //   - context = input data (challenges, etc.)
            
            var label = Gp4Net.Constants.DerivationConstants.Scp03Label; // 11 zero bytes
            var derivationByte = new byte[] { derivationConstant }; // 1 byte
            var separator = new byte[] { 0x00 }; // 1 byte
            var lengthBytes = new byte[] { (byte)(outputLengthBits >> 8), (byte)outputLengthBits }; // 2 bytes big-endian
            var counter = new byte[] { 0x01 }; // 1 byte counter
            
            var fixedInput = label
                .Concat(derivationByte)
                .Concat(separator)
                .Concat(lengthBytes)
                .Concat(counter)
                .Concat(context)
                .ToArray();

            return _macService.CalculateAesCmac(key, fixedInput, macLength: outputLengthBits / 8);
        }, ex => SmartCardError.CryptographicError($"SCP03 data derivation failed: {ex.Message}"))
        .Bind(result => result);
    }
}

