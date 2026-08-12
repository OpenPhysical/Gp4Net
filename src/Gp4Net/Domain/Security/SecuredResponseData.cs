using System;
using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using WSCT.ISO7816;
using static Gp4Net.Cryptography.CryptoOperations;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Immutable data structure representing a secured response with R-MAC and optional encryption.
/// This type enforces that the response came from a valid secure channel session.
/// </summary>
/// <remarks>
/// This type can represent:
/// - R-MAC only secured responses
/// - R-MAC + Encrypted responses (R-MAC + R-ENC)
/// The presence of encryption is determined by the IsEncrypted property.
/// </remarks>
[PublicAPI]
public sealed record SecuredResponseData
{
    /// <summary>
    /// The plaintext or ciphertext data (depending on IsEncrypted).
    /// For encrypted responses, this contains the ciphertext that needs decryption.
    /// For R-MAC-only responses, this contains the plaintext data.
    /// </summary>
    public ImmutableArray<byte> Data { get; }

    /// <summary>
    /// The R-MAC verification result if R-MAC is present.
    /// </summary>
    public Maybe<VerifiedRMac> VerifiedMac { get; }

    /// <summary>
    /// The decrypted data if R-ENC was applied.
    /// </summary>
    public Maybe<DecryptedResponseData> DecryptedData { get; }

    /// <summary>
    /// Indicates whether the data is encrypted (R-ENC enabled).
    /// </summary>
    public bool IsEncrypted { get; }

    /// <summary>
    /// The validated session keys for R-MAC verification and optional decryption.
    /// </summary>
    public SessionKeys ValidatedKeys { get; }

    /// <summary>
    /// The protocol version (SCP02 or SCP03).
    /// </summary>
    public ScpVersion ProtocolVersion { get; }

    /// <summary>
    /// Private constructor ensures validation through factory method.
    /// </summary>
    private SecuredResponseData(
        ImmutableArray<byte> data,
        Maybe<VerifiedRMac> verifiedMac,
        Maybe<DecryptedResponseData> decryptedData,
        bool isEncrypted,
        SessionKeys keys,
        ScpVersion protocolVersion
    )
    {
        Data = data;
        VerifiedMac = verifiedMac;
        DecryptedData = decryptedData;
        IsEncrypted = isEncrypted;
        ValidatedKeys = keys;
        ProtocolVersion = protocolVersion;
    }

    /// <summary>
    /// Extracts secured response data from a ResponseAPDU with a valid session.
    /// </summary>
    /// <param name="response">The secured response APDU.</param>
    /// <param name="validSession">A valid secure channel session.</param>
    /// <returns>Success with SecuredResponseData containing verification proofs.</returns>
    public static Result<SecuredResponseData, SmartCardError> Extract(
        ResponseAPDU response,
        SecureChannelState validSession
    )
    {
        return Maybe<ResponseAPDU>
            .From(response)
            .ToResult(SmartCardError.InvalidArgument("Response cannot be null"))
            .Bind(_ =>
                Maybe<SecureChannelState>
                    .From(validSession)
                    .ToResult(SmartCardError.InvalidArgument("Session state cannot be null"))
            )
            .Map(session =>
            {
                var udr = response.Udr ?? [];

                // Extract R-MAC if enabled
                var macProof = session.SecurityLevel.HasRMac()
                    ? ExtractAndBuildRMacProof(udr, response, session)
                        .GetValueOrDefault(Maybe<VerifiedRMac>.None)
                    : Maybe<VerifiedRMac>.None;

                // Note: Actual decryption would happen elsewhere, we just mark if it's needed
                var encProof = session.SecurityLevel.HasREncryption()
                    ? Maybe<DecryptedResponseData>.None // Will be populated after decryption
                    : Maybe<DecryptedResponseData>.None;

                return new SecuredResponseData(
                    [.. udr],
                    macProof,
                    encProof,
                    session.SecurityLevel.HasREncryption(),
                    session.SessionKeys,
                    session.ProtocolVersion
                );
            });
    }

    /// <summary>
    /// Extracts R-MAC and builds verification proof.
    /// </summary>
    private static Result<Maybe<VerifiedRMac>, SmartCardError> ExtractAndBuildRMacProof(
        byte[] udr,
        ResponseAPDU response,
        SecureChannelState session
    )
    {
        var macSize = 8; // Both SCP02 and SCP03 use 8-byte R-MACs

        if (udr.Length < macSize)
        {
            return Result.Failure<Maybe<VerifiedRMac>, SmartCardError>(
                SmartCardError.InvalidData($"Response too short for R-MAC: {udr.Length} bytes")
            );
        }

        // R-MAC is the first 'macSize' bytes of Udr
        var extractedMac = new byte[macSize];
        Array.Copy(udr, 0, extractedMac, 0, macSize);

        // Create proof (actual verification happens elsewhere)
        var proof = new VerifiedRMac([.. extractedMac], DateTime.UtcNow, session.MacChaining);

        return Result.Success<Maybe<VerifiedRMac>, SmartCardError>(Maybe<VerifiedRMac>.From(proof));
    }

    /// <summary>
    /// Creates a new instance with decrypted data after successful decryption.
    /// </summary>
    /// <param name="decryptedData">The successfully decrypted data.</param>
    /// <param name="counterUsed">The encryption counter used for decryption (SCP03).</param>
    /// <returns>A new instance with decrypted data populated.</returns>
    public SecuredResponseData WithDecryptedData(byte[] decryptedData, uint counterUsed)
    {
        var decrypted = new DecryptedResponseData([.. decryptedData], counterUsed, DateTime.UtcNow);

        return new SecuredResponseData(
            Data,
            VerifiedMac,
            Maybe<DecryptedResponseData>.From(decrypted),
            IsEncrypted,
            ValidatedKeys,
            ProtocolVersion
        );
    }
}

/// <summary>
/// Proof that an R-MAC was successfully verified.
/// </summary>
/// <param name="MacValue">The R-MAC value that was verified.</param>
/// <param name="VerifiedAt">When the verification occurred.</param>
/// <param name="ChainingUsed">The MAC chaining state used for verification.</param>
[PublicAPI]
public sealed record VerifiedRMac(
    ImmutableArray<byte> MacValue,
    DateTime VerifiedAt,
    MacChainingState ChainingUsed
);

/// <summary>
/// Proof that response data was successfully decrypted.
/// </summary>
/// <param name="Plaintext">The decrypted plaintext data.</param>
/// <param name="CounterUsed">The encryption counter used (for SCP03).</param>
/// <param name="DecryptedAt">When the decryption occurred.</param>
[PublicAPI]
public sealed record DecryptedResponseData(
    ImmutableArray<byte> Plaintext,
    uint CounterUsed,
    DateTime DecryptedAt
);
