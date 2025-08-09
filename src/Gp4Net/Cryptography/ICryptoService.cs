using CSharpFunctionalExtensions;
using JetBrains.Annotations;

namespace Gp4Net.Cryptography;

/// <summary>
/// Defines the interface for cryptographic operations used in GlobalPlatform.
/// Supports encryption, decryption, and other cryptographic primitives.
/// </summary>
[PublicAPI]
public interface ICryptoService
{
    /// <summary>
    /// Encrypts data using the specified context.
    /// </summary>
    /// <param name="context">The encryption context.</param>
    /// <returns>The encrypted data.</returns>
    byte[] Encrypt(IEncryptionContext context);

    /// <summary>
    /// Decrypts data using the specified context.
    /// </summary>
    /// <param name="context">The decryption context.</param>
    /// <returns>The decrypted data.</returns>
    byte[] Decrypt(IEncryptionContext context);

    /// <summary>
    /// Generates a cryptographically secure random number.
    /// </summary>
    /// <param name="length">The length in bytes.</param>
    /// <returns>The random bytes.</returns>
    byte[] GenerateRandom(int length);

    /// <summary>
    /// Applies padding to data according to the specified scheme.
    /// </summary>
    /// <param name="data">The data to pad.</param>
    /// <param name="blockSize">The block size in bytes.</param>
    /// <param name="scheme">The padding scheme.</param>
    /// <returns>The padded data.</returns>
    byte[] ApplyPadding(byte[] data, int blockSize, PaddingScheme scheme);

    /// <summary>
    /// Removes padding from data according to the specified scheme.
    /// </summary>
    /// <param name="data">The padded data.</param>
    /// <param name="scheme">The padding scheme.</param>
    /// <returns>The unpadded data.</returns>
    byte[] RemovePadding(byte[] data, PaddingScheme scheme);
}

/// <summary>
/// Represents the context for encryption/decryption operations.
/// </summary>
[PublicAPI]
public interface IEncryptionContext
{
    /// <summary>
    /// Gets the encryption algorithm to use.
    /// </summary>
    EncryptionAlgorithm Algorithm { get; }

    /// <summary>
    /// Gets the encryption key.
    /// </summary>
    byte[] Key { get; }

    /// <summary>
    /// Gets the data to encrypt/decrypt.
    /// </summary>
    byte[] Data { get; }

    /// <summary>
    /// Gets the initialization vector (if required).
    /// </summary>
    Maybe<byte[]> InitializationVector { get; }

    /// <summary>
    /// Gets the cipher mode.
    /// </summary>
    CipherMode Mode { get; }

    /// <summary>
    /// Gets the padding scheme.
    /// </summary>
    PaddingScheme Padding { get; }
}

/// <summary>
/// Defines the encryption algorithms supported by GlobalPlatform.
/// </summary>
public enum EncryptionAlgorithm
{
    /// <summary>
    /// Single DES algorithm.
    /// </summary>
    Des,

    /// <summary>
    /// Triple DES (3DES) algorithm.
    /// </summary>
    DesEde,

    /// <summary>
    /// AES algorithm.
    /// </summary>
    Aes,
}

/// <summary>
/// Defines the cipher modes supported.
/// </summary>
public enum CipherMode
{
    /// <summary>
    /// Electronic Codebook mode.
    /// </summary>
    Ecb,

    /// <summary>
    /// Cipher Block Chaining mode.
    /// </summary>
    Cbc,
}

/// <summary>
/// Defines the padding schemes supported.
/// </summary>
public enum PaddingScheme
{
    /// <summary>
    /// No padding.
    /// </summary>
    None,

    /// <summary>
    /// ISO 7816-4 padding (0x80 followed by zeros).
    /// </summary>
    Iso78164,

    /// <summary>
    /// PKCS#7 padding.
    /// </summary>
    Pkcs7,
}

/// <summary>
/// Default implementation of IEncryptionContext.
/// </summary>
[PublicAPI]
public class EncryptionContext : IEncryptionContext
{
    /// <inheritdoc />
    public EncryptionAlgorithm Algorithm { get; }

    /// <inheritdoc />
    public byte[] Key { get; }

    /// <inheritdoc />
    public byte[] Data { get; }

    /// <inheritdoc />
    public Maybe<byte[]> InitializationVector { get; }

    /// <inheritdoc />
    public CipherMode Mode { get; }

    /// <inheritdoc />
    public PaddingScheme Padding { get; }

    /// <summary>
    /// Initializes a new instance of EncryptionContext.
    /// </summary>
    /// <param name="algorithm">The encryption algorithm.</param>
    /// <param name="key">The encryption key.</param>
    /// <param name="data">The data to encrypt/decrypt.</param>
    /// <param name="mode">The cipher mode.</param>
    /// <param name="padding">The padding scheme.</param>
    /// <param name="initializationVector">The IV (optional).</param>
    public EncryptionContext(
        EncryptionAlgorithm algorithm,
        byte[] key,
        byte[] data,
        CipherMode mode = CipherMode.Cbc,
        PaddingScheme padding = PaddingScheme.Iso78164,
        Maybe<byte[]> initializationVector = default
    )
    {
        Algorithm = algorithm;
        Key = key;
        Data = data;
        Mode = mode;
        Padding = padding;
        InitializationVector = initializationVector;
    }
}