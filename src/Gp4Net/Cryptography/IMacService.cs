using CSharpFunctionalExtensions;
using JetBrains.Annotations;

namespace Gp4Net.Cryptography;

/// <summary>
/// Defines the interface for MAC (Message Authentication Code) operations.
/// Supports different MAC algorithms used in GlobalPlatform protocols.
/// </summary>
[PublicAPI]
public interface IMacService
{
    /// <summary>
    /// Calculates a MAC using the specified context.
    /// </summary>
    /// <param name="context">The MAC calculation context.</param>
    /// <returns>The calculated MAC.</returns>
    byte[] CalculateMac(IMacContext context);

    /// <summary>
    /// Verifies a MAC using the specified context.
    /// </summary>
    /// <param name="context">The MAC verification context.</param>
    /// <param name="expectedMac">The expected MAC value.</param>
    /// <returns>True if the MAC is valid, false otherwise.</returns>
    bool VerifyMac(IMacContext context, byte[] expectedMac);
}

/// <summary>
/// Represents the context for MAC calculation operations.
/// </summary>
[PublicAPI]
public interface IMacContext
{
    /// <summary>
    /// Gets the MAC algorithm to use.
    /// </summary>
    MacAlgorithm Algorithm { get; }

    /// <summary>
    /// Gets the key to use for MAC calculation.
    /// </summary>
    byte[] Key { get; }

    /// <summary>
    /// Gets the data to calculate the MAC over.
    /// </summary>
    byte[] Data { get; }

    /// <summary>
    /// Gets the initialization vector or chaining value.
    /// </summary>
    Maybe<byte[]> InitializationVector { get; }

    /// <summary>
    /// Gets additional algorithm-specific parameters.
    /// </summary>
    Maybe<byte[]> Parameters { get; }
}

/// <summary>
/// Defines the MAC algorithms supported by GlobalPlatform.
/// </summary>
public enum MacAlgorithm
{
    /// <summary>
    /// 3DES retail MAC (ISO 9797-1 Algorithm 3).
    /// Used in SCP01 and SCP02.
    /// </summary>
    DesEdeRetailMac,

    /// <summary>
    /// AES CMAC (SP 800-38B).
    /// Used in SCP03.
    /// </summary>
    AesCmac,

    /// <summary>
    /// Single DES MAC (CBC-MAC).
    /// Used in some legacy implementations.
    /// </summary>
    DesCbcMac,

    /// <summary>
    /// 3DES CBC-MAC.
    /// Used in some SCP02 variants.
    /// </summary>
    DesEdeCbcMac,
}

/// <summary>
/// Strategy interface for MAC algorithm implementations.
/// </summary>
[PublicAPI]
public interface IMacAlgorithm
{
    /// <summary>
    /// Gets the algorithm type this implementation supports.
    /// </summary>
    MacAlgorithm Algorithm { get; }

    /// <summary>
    /// Gets whether this algorithm supports the given context.
    /// </summary>
    /// <param name="context">The MAC context.</param>
    /// <returns>True if supported, false otherwise.</returns>
    bool Supports(IMacContext context);

    /// <summary>
    /// Calculates a MAC using this algorithm.
    /// </summary>
    /// <param name="context">The MAC context.</param>
    /// <returns>The calculated MAC.</returns>
    byte[] Calculate(IMacContext context);

    /// <summary>
    /// Gets the expected MAC length for this algorithm.
    /// </summary>
    /// <param name="keyLength">The key length in bytes.</param>
    /// <returns>The MAC length in bytes.</returns>
    int GetMacLength(int keyLength);
}

/// <summary>
/// Default implementation of IMacContext.
/// </summary>
[PublicAPI]
public class MacContext : IMacContext
{
    /// <inheritdoc />
    public MacAlgorithm Algorithm { get; }

    /// <inheritdoc />
    public byte[] Key { get; }

    /// <inheritdoc />
    public byte[] Data { get; }

    /// <inheritdoc />
    public Maybe<byte[]> InitializationVector { get; }

    /// <inheritdoc />
    public Maybe<byte[]> Parameters { get; }

    /// <summary>
    /// Initializes a new instance of MacContext.
    /// </summary>
    /// <param name="algorithm">The MAC algorithm.</param>
    /// <param name="key">The MAC key.</param>
    /// <param name="data">The data to MAC.</param>
    /// <param name="initializationVector">The IV or chaining value (optional).</param>
    /// <param name="parameters">Additional parameters (optional).</param>
    public MacContext(
        MacAlgorithm algorithm,
        byte[] key,
        byte[] data,
        Maybe<byte[]> initializationVector = default,
        Maybe<byte[]> parameters = default
    )
    {
        Algorithm = algorithm;
        Key = key ?? throw new System.ArgumentNullException(nameof(key));
        Data = data ?? throw new System.ArgumentNullException(nameof(data));
        InitializationVector = initializationVector;
        Parameters = parameters;
    }
}