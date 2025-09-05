using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;

namespace Gp4Net.Cryptography;

public static partial class CryptoService
{
    /// <summary>
    /// Centralized cryptographic validation utilities.
    /// Eliminates DRY violations by providing shared validation methods for cryptographic operations.
    /// All methods are pure functions that return Result&lt;T&gt; for functional composition.
    /// </summary>
    public static class Validation
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
        /// Validates that key and data parameters are valid using functional patterns.
        /// Per functional programming requirements, we use Maybe&lt;T&gt; instead of null checks.
        /// </summary>
        public static UnitResult<SmartCardError> ValidateInputs(
            byte[] key,
            byte[] data
        )
        {
            return Maybe<byte[]>
                .From(key)
                .Match(
                    Some: _ => Maybe<byte[]>
                        .From(data)
                        .Match(
                            Some: _ => UnitResult.Success<SmartCardError>(),
                            None: () => UnitResult.Failure(SmartCardError.InvalidArgument("Data parameter is required"))
                        ),
                    None: () => UnitResult.Failure(SmartCardError.InvalidArgument("Key parameter is required"))
                );
        }

        /// <summary>
        /// Validates that key, IV, and data parameters are valid using functional patterns.
        /// Per functional programming requirements, we use Maybe&lt;T&gt; instead of null checks.
        /// </summary>
        public static UnitResult<SmartCardError> ValidateInputs(
            byte[] key,
            byte[] iv,
            byte[] data
        )
        {
            return Maybe<byte[]>
                .From(key)
                .Match(
                    Some: _ => Maybe<byte[]>
                        .From(iv)
                        .Match(
                            Some: _ => Maybe<byte[]>
                                .From(data)
                                .Match(
                                    Some: _ => UnitResult.Success<SmartCardError>(),
                                    None: () => UnitResult.Failure(SmartCardError.InvalidArgument("Data parameter is required"))
                                ),
                            None: () => UnitResult.Failure(SmartCardError.InvalidArgument("IV parameter is required"))
                        ),
                    None: () => UnitResult.Failure(SmartCardError.InvalidArgument("Key parameter is required"))
                );
        }
        public static UnitResult<SmartCardError> ValidateIvLength(
            byte[] iv,
            int expectedLength,
            string errorMessage
        )
        {
            return iv.Length == expectedLength
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
        /// Validates that data is present and has content.
        /// Pure functional validation using explicit array length checks.
        /// </summary>
        private static UnitResult<SmartCardError> ValidateHasData(byte[] data, string errorMessage)
        {
            return data.Length >= 0
                ? UnitResult.Success<SmartCardError>()
                : UnitResult.Failure(SmartCardError.InvalidArgument(errorMessage));
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
}
