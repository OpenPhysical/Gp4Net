// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using static Gp4Net.Cryptography.CryptoService;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// Unified cryptographic service for both SCP02 and SCP03 protocols.
/// Consolidates all cryptographic operations (key derivation, MAC calculation, encryption) into a single service.
/// Per GlobalPlatform Card Specification v2.3.1 Appendix E "Secure Channel Protocol".
/// </summary>
[PublicAPI]
public sealed class ScpCryptographyService
{
    /// <summary>
    /// Private constructor for functional creation pattern.
    /// </summary>
    private ScpCryptographyService()
    {
        // Pure functional cryptographic service with no dependencies
    }

    /// <summary>
    /// Creates a new ScpCryptographyService instance.
    /// </summary>
    /// <returns>A result containing the service or error.</returns>
    public static Result<ScpCryptographyService, SmartCardError> Create()
    {
        return Result.Success<ScpCryptographyService, SmartCardError>(new ScpCryptographyService());
    }

    /// <summary>
    /// Derives session keys for the specified SCP protocol and parameters.
    /// Handles both SCP02 and SCP03 key derivation transparently.
    /// </summary>
    /// <param name="protocolVersion">The SCP protocol version.</param>
    /// <param name="keySet">The static key set.</param>
    /// <param name="hostChallenge">The host challenge.</param>
    /// <param name="cardChallenge">The card challenge.</param>
    /// <param name="sequenceCounter">The sequence counter (SCP02) or null (SCP03).</param>
    /// <param name="implementationParameter">The implementation parameter.</param>
    /// <returns>A result containing the derived session keys or error.</returns>
    public Result<SessionKeys, SmartCardError> DeriveSessionKeys(
        ScpVersion protocolVersion,
        IKeySet keySet,
        byte[] hostChallenge,
        byte[] cardChallenge,
        Maybe<byte[]> sequenceCounter,
        byte implementationParameter
    )
    {
        return protocolVersion switch
        {
            ScpVersion.Scp02 => DeriveSessionKeysScp02(
                keySet,
                hostChallenge,
                cardChallenge,
                sequenceCounter,
                implementationParameter
            ),
            ScpVersion.Scp03 => DeriveSessionKeysScp03(
                keySet,
                hostChallenge,
                cardChallenge,
                implementationParameter
            ),
            _ => SmartCardError.InvalidArgument(
                $"Unsupported protocol version: {protocolVersion:X2}"
            ),
        };
    }

    /// <summary>
    /// Calculates a cryptogram for the specified SCP protocol and data.
    /// Handles both SCP02 (3DES) and SCP03 (AES) cryptogram calculation.
    /// </summary>
    /// <param name="protocolVersion">The SCP protocol version.</param>
    /// <param name="key">The S-ENC key for cryptogram calculation.</param>
    /// <param name="cryptogramData">The cryptogram data (protocol-specific format).</param>
    /// <returns>A result containing the calculated cryptogram or error.</returns>
    public Result<byte[], SmartCardError> CalculateCryptogram(
        ScpVersion protocolVersion,
        byte[] key,
        byte[] cryptogramData
    )
    {
        return protocolVersion switch
        {
            ScpVersion.Scp02 => Scp02Protocol.CalculateScp02Cryptogram(key, cryptogramData),
            ScpVersion.Scp03 => CryptoService.Cryptogram.CalculateScp03Cryptogram(key, cryptogramData),
            _ => SmartCardError.InvalidArgument(
                $"Unsupported protocol version: {protocolVersion:X2}"
            ),
        };
    }

    /// <summary>
    /// Calculates a command MAC for the specified SCP protocol and command data.
    /// Handles both SCP02 (Retail MAC) and SCP03 (CMAC) calculation.
    /// </summary>
    /// <param name="protocolVersion">The SCP protocol version.</param>
    /// <param name="macKey">The MAC key (S-MAC).</param>
    /// <param name="macInput">The MAC input data (includes chaining value for SCP03).</param>
    /// <returns>A result containing the calculated MAC or error.</returns>
    public Result<byte[], SmartCardError> CalculateCommandMac(
        ScpVersion protocolVersion,
        byte[] macKey,
        byte[] macInput
    )
    {
        return protocolVersion switch
        {
            ScpVersion.Scp02 => CryptoService.Mac.CalculateScp02CommandMac(macKey, macInput),
            ScpVersion.Scp03 => CryptoService.Mac.CalculateScp03CommandMac(macKey, macInput),
            _ => SmartCardError.InvalidArgument(
                $"Unsupported protocol version: {protocolVersion:X2}"
            ),
        };
    }

    /// <summary>
    /// Calculates a response MAC for the specified SCP protocol and response data.
    /// Handles both SCP02 (Retail MAC) and SCP03 (CMAC) calculation.
    /// </summary>
    /// <param name="protocolVersion">The SCP protocol version.</param>
    /// <param name="rMacKey">The R-MAC key (SR-MAC).</param>
    /// <param name="macInput">The MAC input data (includes chaining value for SCP03).</param>
    /// <returns>A result containing the calculated R-MAC or error.</returns>
    public Result<byte[], SmartCardError> CalculateResponseMac(
        ScpVersion protocolVersion,
        byte[] rMacKey,
        byte[] macInput
    )
    {
        return protocolVersion switch
        {
            ScpVersion.Scp02 => CryptoService.Mac.CalculateScp02ResponseMac(rMacKey, macInput),
            ScpVersion.Scp03 => CryptoService.Mac.CalculateScp03ResponseMac(rMacKey, macInput),
            _ => SmartCardError.InvalidArgument(
                $"Unsupported protocol version: {protocolVersion:X2}"
            ),
        };
    }

    /// <summary>
    /// Encrypts command data using the specified SCP protocol and encryption parameters.
    /// Handles both SCP02 (3DES-CBC) and SCP03 (AES-CBC) encryption.
    /// </summary>
    /// <param name="protocolVersion">The SCP protocol version.</param>
    /// <param name="encryptionKey">The encryption key (S-ENC).</param>
    /// <param name="iv">The initialization vector.</param>
    /// <param name="data">The data to encrypt.</param>
    /// <returns>A result containing the encrypted data or error.</returns>
    public Result<byte[], SmartCardError> EncryptData(
        ScpVersion protocolVersion,
        byte[] encryptionKey,
        byte[] iv,
        byte[] data
    )
    {
        return protocolVersion switch
        {
            ScpVersion.Scp02 => CryptoService.Cipher.Encrypt3DesCbcWithPadding(
                encryptionKey,
                iv,
                data
            ),
            ScpVersion.Scp03 => CryptoService.Cipher.EncryptAesCbc(encryptionKey, iv, data),
            _ => SmartCardError.InvalidArgument(
                $"Unsupported protocol version: {protocolVersion:X2}"
            ),
        };
    }

    /// <summary>
    /// Decrypts response data using the specified SCP protocol and encryption parameters.
    /// Handles both SCP02 (3DES-CBC) and SCP03 (AES-CBC) decryption.
    /// </summary>
    /// <param name="protocolVersion">The SCP protocol version.</param>
    /// <param name="encryptionKey">The encryption key (S-ENC).</param>
    /// <param name="iv">The initialization vector.</param>
    /// <param name="encryptedData">The data to decrypt.</param>
    /// <returns>A result containing the decrypted data or error.</returns>
    public Result<byte[], SmartCardError> DecryptData(
        ScpVersion protocolVersion,
        byte[] encryptionKey,
        byte[] iv,
        byte[] encryptedData
    )
    {
        return protocolVersion switch
        {
            ScpVersion.Scp02 => CryptoService.Cipher.Decrypt3DesCbcWithPadding(
                encryptionKey,
                iv,
                encryptedData
            ),
            ScpVersion.Scp03 => CryptoService.Cipher.DecryptAesCbc(
                encryptionKey,
                iv,
                encryptedData
            ),
            _ => SmartCardError.InvalidArgument(
                $"Unsupported protocol version: {protocolVersion:X2}"
            ),
        };
    }

    /// <summary>
    /// Builds cryptogram data for card or host cryptogram calculation.
    /// Handles protocol-specific data formatting requirements.
    /// </summary>
    /// <param name="protocolVersion">The SCP protocol version.</param>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <param name="hostChallenge">The host challenge.</param>
    /// <param name="cryptogramType">The type of cryptogram (card or host).</param>
    /// <returns>A result containing the formatted cryptogram data or error.</returns>
    public Result<byte[], SmartCardError> BuildCryptogramData(
        ScpVersion protocolVersion,
        InitializeUpdateResponse response,
        byte[] hostChallenge,
        CryptogramType cryptogramType
    )
    {
        return protocolVersion switch
        {
            ScpVersion.Scp02 => cryptogramType switch
            {
                CryptogramType.Card => CryptoService.Cryptogram.BuildScp02CardCryptogramData(
                    response,
                    hostChallenge
                ),
                CryptogramType.Host => CryptoService.Cryptogram.BuildScp02HostCryptogramData(
                    response,
                    hostChallenge
                ),
                _ => SmartCardError.InvalidArgument(
                    $"Unsupported cryptogram type: {cryptogramType}"
                ),
            },
            ScpVersion.Scp03 => cryptogramType switch
            {
                CryptogramType.Card => CryptoService.Cryptogram.BuildScp03CardCryptogramData(
                    response,
                    hostChallenge
                ),
                CryptogramType.Host => CryptoService.Cryptogram.BuildScp03HostCryptogramData(
                    response,
                    hostChallenge
                ),
                _ => SmartCardError.InvalidArgument(
                    $"Unsupported cryptogram type: {cryptogramType}"
                ),
            },
            _ => SmartCardError.InvalidArgument(
                $"Unsupported protocol version: {protocolVersion:X2}"
            ),
        };
    }

    /// <summary>
    /// Creates secure channel context from INITIALIZE UPDATE response and derived session keys.
    /// Consolidates context creation for both protocols.
    /// </summary>
    /// <param name="protocolVersion">The SCP protocol version.</param>
    /// <param name="hostChallenge">The host challenge that was sent.</param>
    /// <param name="response">The parsed INITIALIZE UPDATE response.</param>
    /// <param name="sessionKeys">The derived session keys.</param>
    /// <param name="keySet">The original key set.</param>
    /// <returns>A result containing the secure channel context or error.</returns>
    public Result<SecureChannelContext, SmartCardError> CreateSecureChannelContext(
        ScpVersion protocolVersion,
        byte[] hostChallenge,
        InitializeUpdateResponse response,
        SessionKeys sessionKeys,
        IKeySet keySet
    )
    {
        // Verify card cryptogram first
        return BuildCryptogramData(protocolVersion, response, hostChallenge, CryptogramType.Card)
            .Bind(cardCryptogramData =>
                CalculateCryptogram(protocolVersion, sessionKeys.SEnc, cardCryptogramData)
            )
            .Bind(calculatedCardCryptogram =>
            {
                // Compare cryptograms (protocol-specific comparison)
                Result<byte[], SmartCardError> expectedCryptogramResult = protocolVersion switch
                {
                    ScpVersion.Scp02 => Result.Success<byte[], SmartCardError>(
                        calculatedCardCryptogram
                    ), // SCP02 uses full 8-byte comparison
                    ScpVersion.Scp03 => Result.Success<byte[], SmartCardError>(
                        [.. calculatedCardCryptogram.Take(8)]
                    ), // SCP03 uses first 8 bytes
                    _ => SmartCardError.InvalidArgument($"Unsupported protocol: {protocolVersion}"),
                };

                return expectedCryptogramResult.Bind(expectedCryptogram =>
                {
                    if (
                        !CryptoService.Utils.CompareBytes(
                            expectedCryptogram,
                            response.CardCryptogram
                        )
                    )
                    {
                        return SmartCardError.AuthenticationFailed(
                            "Card cryptogram verification failed"
                        );
                    }

                    // Create context with validated cryptogram
                    return SecureChannelContext.Create(
                        hostChallenge,
                        response,
                        sessionKeys,
                        protocolVersion,
                        keySet
                    );
                });
            });
    }

    // Private implementation methods

    private static Result<SessionKeys, SmartCardError> DeriveSessionKeysScp02(
        IKeySet keySet,
        byte[] hostChallenge,
        byte[] cardChallenge,
        Maybe<byte[]> sequenceCounter,
        byte implementationParameter
    )
    {
        if (keySet is not Scp02KeySet scp02KeySet)
            return SmartCardError.InvalidArgument("SCP02 requires Scp02KeySet");

        return sequenceCounter
            .ToResult(SmartCardError.InvalidArgument("SCP02 requires sequence counter"))
            .Bind(seqCounter =>
                Scp02Protocol.DeriveSessionKeys(
                    scp02KeySet,
                    hostChallenge,
                    cardChallenge,
                    seqCounter,
                    implementationParameter
                )
            );
    }

    private static Result<SessionKeys, SmartCardError> DeriveSessionKeysScp03(
        IKeySet keySet,
        byte[] hostChallenge,
        byte[] cardChallenge,
        byte implementationParameter
    )
    {
        if (keySet is not Scp03KeySet scp03KeySet)
            return SmartCardError.InvalidArgument("SCP03 requires Scp03KeySet");

        return Scp03Protocol.DeriveSessionKeys(
            scp03KeySet,
            hostChallenge,
            cardChallenge,
            implementationParameter
        );
    }
}
