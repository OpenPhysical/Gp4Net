using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Org.BouncyCastle.Security;

namespace Gp4Net.Domain.Modules;

/// <summary>
/// Pure functional cryptographic helper functions.
/// All functions are static and side-effect free.
/// </summary>
public static class CryptographyHelpers
{
    /// <summary>
    /// Generates cryptographically secure random bytes.
    /// </summary>
    /// <param name="length">Number of bytes to generate.</param>
    /// <returns>Array of random bytes or error.</returns>
    public static Result<byte[], SmartCardError> GenerateRandomBytes(int length)
    {
        if (length <= 0)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("Length must be positive"));
        }

        byte[] bytes = new byte[length];
        SecureRandom random = new SecureRandom();
        random.NextBytes(bytes);
        return Result.Success<byte[], SmartCardError>(bytes);
    }

    /// <summary>
    /// Generates an 8-byte host challenge for secure channel establishment.
    /// </summary>
    /// <returns>8-byte host challenge.</returns>
    public static byte[] GenerateHostChallenge()
    {
        // Host challenge is always 8 bytes, so this should never fail
        Result<byte[], SmartCardError> result = GenerateRandomBytes(8);
        return result.Value; // Safe because 8 is always valid
    }

    /// <summary>
    /// Generates a 16-byte sequence counter for SCP03.
    /// </summary>
    /// <returns>16-byte sequence counter.</returns>
    public static byte[] GenerateSequenceCounter()
    {
        // Sequence counter is always 16 bytes, so this should never fail
        Result<byte[], SmartCardError> result = GenerateRandomBytes(16);
        return result.Value; // Safe because 16 is always valid
    }
}