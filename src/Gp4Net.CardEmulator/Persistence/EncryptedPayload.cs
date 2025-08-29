using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Persistence;

/// <summary>
/// Immutable record representing an encrypted payload with all necessary AEAD parameters.
/// Contains the results of AES-256-GCM encryption including IV, ciphertext, and authentication tag.
/// </summary>
[PublicAPI]
public record EncryptedPayload(
    string Algorithm,
    byte[] IV,
    byte[] Ciphertext,
    byte[] AuthTag
)
{
    /// <summary>
    /// Gets the total size of the encrypted payload in bytes.
    /// </summary>
    public int TotalSize => IV.Length + Ciphertext.Length + AuthTag.Length;

    /// <summary>
    /// Validates that the encrypted payload has the expected structure for AES-256-GCM.
    /// </summary>
    public bool IsValid =>
        Algorithm == "aes-256-gcm" &&
        IV.Length == 12 &&
        AuthTag.Length == 16 &&
        Ciphertext.Length > 0;
}