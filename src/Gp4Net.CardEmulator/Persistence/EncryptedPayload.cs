using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Persistence;

/// <summary>
/// Immutable record representing an encrypted payload with all necessary AEAD parameters.
/// Contains the results of AES-256-GCM encryption including IV, ciphertext, and authentication tag.
/// </summary>
[PublicAPI]
public record EncryptedPayload(string Algorithm, byte[] Iv, byte[] Ciphertext, byte[] AuthTag)
{
    /// <summary>
    /// Gets the total size of the encrypted payload in bytes.
    /// </summary>
    public int TotalSize => (Iv?.Length ?? 0) + (Ciphertext?.Length ?? 0) + (AuthTag?.Length ?? 0);

    /// <summary>
    /// Validates that the encrypted payload has the expected structure for AES-256-GCM.
    /// </summary>
    public bool IsValid =>
        string.Equals(Algorithm, "aes-256-gcm", System.StringComparison.OrdinalIgnoreCase)
        && Iv is { Length: 12 }
        && AuthTag is { Length: 16 }
        && Ciphertext is { Length: > 0 };
}
