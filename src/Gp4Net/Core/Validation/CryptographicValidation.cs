using System.Linq;
using CSharpFunctionalExtensions;

namespace Gp4Net.Core.Validation;

/// <summary>
/// Centralized cryptographic validation utilities.
/// Eliminates DRY violations by providing shared validation methods for cryptographic operations.
/// All methods are pure functions that return Result&lt;T&gt; for functional composition.
/// </summary>
public static class CryptographicValidation
{
    /// <summary>
    /// Validates that both key and data are not null or empty.
    /// </summary>
    /// <param name="key">The cryptographic key to validate.</param>
    /// <param name="data">The data to validate.</param>
    /// <param name="errorMessage">Custom error message for validation failure.</param>
    /// <returns>Success if both inputs are valid, failure with specified error message otherwise.</returns>
    public static UnitResult<SmartCardError> ValidateInputs(
        byte[] key,
        byte[] data,
        string errorMessage
    )
    {
        Maybe<byte[]> keyMaybe = Maybe<byte[]>.From(key);
        Maybe<byte[]> dataMaybe = Maybe<byte[]>.From(data);

        return keyMaybe.HasValue && dataMaybe.HasValue
            ? UnitResult.Success<SmartCardError>()
            : UnitResult.Failure(SmartCardError.InvalidArgument(errorMessage));
    }

    /// <summary>
    /// Validates that a cryptographic key has one of the expected lengths.
    /// </summary>
    /// <param name="key">The key to validate.</param>
    /// <param name="validLengths">Array of valid key lengths in bytes.</param>
    /// <param name="errorMessage">Custom error message prefix for validation failure.</param>
    /// <returns>Success if key length is valid, failure with detailed error message otherwise.</returns>
    public static UnitResult<SmartCardError> ValidateKeyLength(
        byte[] key,
        int[] validLengths,
        string errorMessage
    )
    {
        return validLengths.Contains(key.Length)
            ? UnitResult.Success<SmartCardError>()
            : UnitResult.Failure(
                SmartCardError.InvalidArgument($"{errorMessage}, got {key.Length}")
            );
    }

    /// <summary>
    /// Validates that data length is properly aligned to the specified block size.
    /// </summary>
    /// <param name="data">The data to validate.</param>
    /// <param name="blockSize">The required block size in bytes.</param>
    /// <param name="errorMessage">Custom error message for validation failure.</param>
    /// <returns>Success if data is properly padded, failure with specified error message otherwise.</returns>
    public static UnitResult<SmartCardError> ValidateDataPadding(
        byte[] data,
        int blockSize,
        string errorMessage
    )
    {
        return data.Length % blockSize == 0
            ? UnitResult.Success<SmartCardError>()
            : UnitResult.Failure(SmartCardError.InvalidArgument(errorMessage));
    }

    /// <summary>
    /// Validates a single byte array input for null/empty conditions.
    /// </summary>
    /// <param name="input">The input to validate.</param>
    /// <param name="parameterName">Name of the parameter for error reporting.</param>
    /// <returns>Success if input is valid, failure otherwise.</returns>
    public static UnitResult<SmartCardError> ValidateInput(byte[] input, string parameterName)
    {
        return Maybe<byte[]>.From(input).HasValue
            ? UnitResult.Success<SmartCardError>()
            : UnitResult.Failure(
                SmartCardError.InvalidArgument($"{parameterName} cannot be null or empty")
            );
    }

    /// <summary>
    /// Validates that an input has exactly the expected length.
    /// </summary>
    /// <param name="input">The input to validate.</param>
    /// <param name="expectedLength">The expected length in bytes.</param>
    /// <param name="parameterName">Name of the parameter for error reporting.</param>
    /// <returns>Success if length matches, failure with detailed error message otherwise.</returns>
    public static UnitResult<SmartCardError> ValidateExactLength(
        byte[] input,
        int expectedLength,
        string parameterName
    )
    {
        return input.Length == expectedLength
            ? UnitResult.Success<SmartCardError>()
            : UnitResult.Failure(
                SmartCardError.InvalidArgument(
                    $"{parameterName} must be {expectedLength} bytes, got {input.Length}"
                )
            );
    }
}
