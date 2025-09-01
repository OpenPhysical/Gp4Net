using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Core.Validation;

namespace Gp4Net.Cryptography;

public static partial class CryptoService
{
    private static class Validation
    {

        public static UnitResult<SmartCardError> ValidateInputs(
            byte[] key,
            byte[] data
        ) => UnitResult.Success<SmartCardError>();
        public static UnitResult<SmartCardError> ValidateInputs(
            byte[] key,
            byte[] iv,
            byte[] data
        ) => UnitResult.Success<SmartCardError>();
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
        public static UnitResult<SmartCardError> ValidateKeyLength(
            byte[] key,
            int[] validLengths,
            string errorMessage
        ) => CryptographicValidation.ValidateKeyLength(key, validLengths, errorMessage);
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
        public static UnitResult<SmartCardError> ValidateDataPadding(
            byte[] data,
            int blockSize,
            string errorMessage
        ) => CryptographicValidation.ValidateDataPadding(data, blockSize, errorMessage);
    }
}
