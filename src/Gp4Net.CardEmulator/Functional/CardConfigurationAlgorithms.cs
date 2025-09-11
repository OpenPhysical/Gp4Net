using System.Collections.Immutable;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Extension methods for CardConfiguration algorithm support.
/// </summary>
public static class CardConfigurationAlgorithms
{
    /// <summary>
    /// Creates standard supported algorithms list for most cards.
    /// </summary>
    public static ImmutableList<string> CreateStandardAlgorithms()
    {
        return ImmutableList.Create(
            "RSA-1024",
            "RSA-2048",
            "ECDSA-P256",
            "ECDSA-P384",
            "AES-128",
            "AES-256",
            "SHA-1",
            "SHA-256",
            "SHA-384",
            "SHA-512",
            "HMAC-SHA1",
            "HMAC-SHA256"
        );
    }

    /// <summary>
    /// Creates minimal supported algorithms list for restricted cards.
    /// </summary>
    public static ImmutableList<string> CreateMinimalAlgorithms()
    {
        return ImmutableList.Create("RSA-1024", "AES-128", "SHA-256");
    }

    /// <summary>
    /// Creates dual-protocol algorithms supporting both SCP02 and SCP03.
    /// </summary>
    public static ImmutableList<string> CreateDualProtocolAlgorithms()
    {
        return ImmutableList.Create(
            "RSA-1024",
            "RSA-2048",
            "ECDSA-P256",
            "ECDSA-P384",
            "ECDSA-P521",
            "AES-128",
            "AES-192",
            "AES-256",
            "3DES",
            "SHA-1",
            "SHA-256",
            "SHA-384",
            "SHA-512",
            "HMAC-SHA1",
            "HMAC-SHA256",
            "HMAC-SHA384",
            "HMAC-SHA512"
        );
    }

    /// <summary>
    /// Creates SCP03-focused algorithms with modern cryptography.
    /// </summary>
    public static ImmutableList<string> CreateScp03Algorithms()
    {
        return ImmutableList.Create(
            "RSA-2048",
            "RSA-3072",
            "ECDSA-P256",
            "ECDSA-P384",
            "ECDSA-P521",
            "AES-128",
            "AES-192",
            "AES-256",
            "SHA-256",
            "SHA-384",
            "SHA-512",
            "HMAC-SHA256",
            "HMAC-SHA384",
            "HMAC-SHA512"
        );
    }
}
