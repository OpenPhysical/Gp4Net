using System;
using System.Linq;
using System.Text;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Kdf.Modes;

namespace Gp4Net.CardEmulator.Persistence;

/// <summary>
/// Service for deriving storage encryption keys from GlobalPlatform key sets.
/// Uses KDF108 in counter mode with comprehensive key material incorporation.
/// Implements proper SCP02/SCP03 key handling with all variations supported.
/// </summary>
[PublicAPI]
public class CardPersistenceKeyService : ICardPersistenceKeyService
{
    private readonly CounterModeKdf _kdf;

    /// <summary>
    /// Initializes a new instance of the CardPersistenceKeyService class.
    /// </summary>
    public CardPersistenceKeyService()
    {
        _kdf = new CounterModeKdf();
    }

    /// <summary>
    /// Derives storage encryption key using KDF108 with all available key material.
    /// Per SP 800-108r1: K1 (KIN) = ENC key, K2 and K3 encoded in context as secret inputs.
    /// Supports all SCP02/SCP03 key set variations including single keys and missing DEK.
    /// </summary>
    public Result<byte[], SmartCardError> DeriveStorageKey(IKeySet keySet, CardUuid cardUuid)
    {
        Result<bool, SmartCardError> validationResult = ValidateInputs(keySet, cardUuid);
        if (validationResult.IsFailure)
            return Result.Failure<byte[], SmartCardError>(validationResult.Error);

        Result<KdfParameters, SmartCardError> kdfParamsResult = BuildKdfParameters(
            keySet,
            cardUuid
        );
        if (kdfParamsResult.IsFailure)
            return Result.Failure<byte[], SmartCardError>(kdfParamsResult.Error);

        return ExecuteKeyDerivation(kdfParamsResult.Value);
    }

    /// <summary>
    /// Generates cryptographically secure card UUID.
    /// </summary>
    public Result<CardUuid, SmartCardError> GenerateCardUuid()
    {
        return CardUuid.Generate();
    }

    /// <summary>
    /// Validates key fingerprint for integrity checking.
    /// </summary>
    public Result<bool, SmartCardError> ValidateKeyFingerprint(IKeySet keySet, byte[] fingerprint)
    {
        return ComputeKeyFingerprint(keySet).Map(computed => computed.SequenceEqual(fingerprint));
    }

    /// <summary>
    /// Computes SHA-256 fingerprint of key set for integrity verification.
    /// </summary>
    public Result<byte[], SmartCardError> ComputeKeyFingerprint(IKeySet keySet)
    {
        Result<bool, SmartCardError> validationResult = ValidateKeySet(keySet);
        if (validationResult.IsFailure)
            return Result.Failure<byte[], SmartCardError>(validationResult.Error);

        Result<byte[], SmartCardError> fingerprintDataResult = BuildFingerprintData(keySet);
        if (fingerprintDataResult.IsFailure)
            return Result.Failure<byte[], SmartCardError>(fingerprintDataResult.Error);

        return ComputeSha256Hash(fingerprintDataResult.Value);
    }

    private static Result<bool, SmartCardError> ValidateInputs(IKeySet keySet, CardUuid cardUuid)
    {
        Result<bool, SmartCardError> keySetValidation = ValidateKeySet(keySet);
        if (keySetValidation.IsFailure)
            return Result.Failure<bool, SmartCardError>(keySetValidation.Error);

        return ValidateCardUuid(cardUuid);
    }

    private static Result<bool, SmartCardError> ValidateKeySet(IKeySet keySet)
    {
        return Maybe<IKeySet>
            .From(keySet)
            .ToResult(SmartCardError.InvalidArgument("Key set cannot be null"))
            .Map(_ => true);
    }

    private static Result<bool, SmartCardError> ValidateCardUuid(CardUuid cardUuid)
    {
        return cardUuid.IsEmpty
            ? Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument("Card UUID cannot be empty")
            )
            : Result.Success<bool, SmartCardError>(true);
    }

    private static Result<KdfParameters, SmartCardError> BuildKdfParameters(
        IKeySet keySet,
        CardUuid cardUuid
    )
    {
        return CreateKdfParametersWithErrorHandling(keySet, cardUuid);
    }

    private static Result<KdfParameters, SmartCardError> CreateKdfParametersWithErrorHandling(
        IKeySet keySet,
        CardUuid cardUuid
    )
    {
        return Result.Try(
            () =>
            {
                // K1 = ENC key (always present, use as KDF input key)
                byte[] k1 = keySet.EncKey;

                // K2 = MAC key (always present, encode in context)
                byte[] k2 = keySet.MacKey;

                // K3 = DEK key (may be present, handle gracefully)
                // Use zero-filled array if absent, matching key length
                byte[] k3 = Maybe<byte[]>
                    .From(keySet.DekKey)
                    .Match(
                        dek => dek,
                        () => new byte[k1.Length] // Zero if absent
                    );

                // Build unambiguous tuple encoding for context
                byte[] label = Encoding.ASCII.GetBytes("gp4net-card-persistence/v1");
                byte[] context = EncodeTuple(
                    Encoding.ASCII.GetBytes("alg=HMAC-SHA-256"),
                    Encoding.ASCII.GetBytes("outlen=256"),
                    Encoding.ASCII.GetBytes("purpose=KEK"),
                    Encoding.ASCII.GetBytes($"scp={GetScpVersionString(keySet)}"),
                    cardUuid.ToByteArray(),
                    k2, // MAC key as secret context
                    k3 // DEK key as secret context (zero if absent)
                );

                // Build fixed input per SP 800-108r1: Label || 0x00 || Context
                byte[] fixedInput = BuildFixedInput(label, context);

                KdfParameters parameters = new KdfParameters(k1, fixedInput, keySet);
                return parameters;
            },
            ex => SmartCardError.CryptographicError($"Failed to build KDF parameters: {ex.Message}")
        );
    }

    private Result<byte[], SmartCardError> ExecuteKeyDerivation(KdfParameters parameters)
    {
        return ExecuteKdf108WithErrorHandling(parameters);
    }

    private Result<byte[], SmartCardError> ExecuteKdf108WithErrorHandling(KdfParameters parameters)
    {
        return Result.Try(
            () =>
            {
                KdfOptions options = KdfOptions
                    .CreateBuilder()
                    .WithPrfType(PrfType.HmacSha256)
                    .WithCounterLengthBits(32)
                    .WithUseCounter(true)
                    .WithCounterLocation(CounterLocation.BeforeFixed)
                    .Build();

                byte[] derivedKey = _kdf.DeriveWithFixedInput(
                    parameters.Kin,
                    parameters.FixedInput,
                    256, // Output length in bits (32 bytes)
                    options
                );

                return derivedKey;
            },
            ex => SmartCardError.CryptographicError($"KDF108 key derivation failed: {ex.Message}")
        );
    }

    private static string GetScpVersionString(IKeySet keySet) =>
        keySet switch
        {
            Scp02KeySet scp02 =>
                $"scp02-{(scp02.EncKey.SequenceEqual(scp02.MacKey) ? "single" : "triple")}",
            Scp03KeySet scp03 => $"scp03-aes{scp03.EncKey.Length * 8}",
            _ => $"unknown-{keySet.GetType().Name}",
        };

    private static byte[] EncodeTuple(params byte[][] components)
    {
        // Functional tuple encoding: length-prefixed components using LINQ
        return components
            .SelectMany(component =>
            {
                // Encode length as 4-byte big-endian integer
                byte[] lengthBytes = BitConverter.GetBytes((uint)component.Length);
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(lengthBytes);
                }
                return lengthBytes.Concat(component);
            })
            .ToArray();
    }

    private static byte[] BuildFixedInput(byte[] label, byte[] context)
    {
        // Per SP 800-108r1: Label || 0x00 || Context
        byte[] fixedInput = new byte[label.Length + 1 + context.Length];
        int offset = 0;

        Array.Copy(label, 0, fixedInput, offset, label.Length);
        offset += label.Length;

        fixedInput[offset] = 0x00; // Separator
        offset++;

        Array.Copy(context, 0, fixedInput, offset, context.Length);

        return fixedInput;
    }

    private static Result<byte[], SmartCardError> BuildFingerprintData(IKeySet keySet)
    {
        return Result.Try(
            () =>
            {
                byte[] dekKey = Maybe<byte[]>.From(keySet.DekKey).Match(dek => dek, () => []);

                byte[] concatenated = keySet.EncKey.Concat(keySet.MacKey).Concat(dekKey).ToArray();

                return concatenated;
            },
            ex =>
                SmartCardError.CryptographicError($"Failed to build fingerprint data: {ex.Message}")
        );
    }

    private static Result<byte[], SmartCardError> ComputeSha256Hash(byte[] data)
    {
        return CryptoService.Hash.Sha256(data);
    }

    /// <summary>
    /// Internal record for KDF parameters to ensure type safety.
    /// </summary>
    private record KdfParameters(byte[] Kin, byte[] FixedInput, IKeySet KeySet);
}
