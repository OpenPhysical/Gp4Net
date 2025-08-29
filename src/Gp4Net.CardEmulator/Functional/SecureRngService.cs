using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;
using Org.BouncyCastle.Security;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Production RNG service using BouncyCastle SecureRandom for cryptographically secure entropy.
/// Provides unlimited entropy for production virtual card operations.
/// </summary>
[PublicAPI]
public class SecureRngService : IRngService
{
    private readonly SecureRandom _secureRandom;

    /// <summary>
    /// Initializes a new instance of the SecureRngService with a new SecureRandom instance.
    /// </summary>
    public SecureRngService()
    {
        _secureRandom = new SecureRandom();
    }

    /// <summary>
    /// Initializes a new instance of the SecureRngService with a provided SecureRandom instance.
    /// </summary>
    /// <param name="secureRandom">The SecureRandom instance to use.</param>
    public SecureRngService(SecureRandom secureRandom)
    {
        _secureRandom = secureRandom;
    }

    /// <inheritdoc />
    public Result<byte[], SmartCardError> GetBytes(int length)
    {
        if (length < 0)
        {
            return SmartCardError.InvalidArgument($"Length cannot be negative: {length}");
        }

        if (length == 0)
        {
            return Result.Success<byte[], SmartCardError>([]);
        }

        return Result.Try(() =>
        {
            byte[] bytes = new byte[length];
            _secureRandom.NextBytes(bytes);
            return bytes;
        },
        ex => SmartCardError.CryptographicError($"Failed to generate secure random bytes: {ex.Message}"));
    }

    /// <inheritdoc />
    public bool HasEnoughEntropy(int requiredBytes)
    {
        return requiredBytes >= 0; // Secure random has unlimited entropy
    }

    /// <inheritdoc />
    public Maybe<int> RemainingEntropy => Maybe<int>.None; // Unlimited entropy
}