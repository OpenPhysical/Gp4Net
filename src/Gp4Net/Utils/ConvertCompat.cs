using System;

namespace Gp4Net.Utils
{
    /// <summary>
    /// Provides compatibility methods for Convert class functionality that is not available in .NET Standard 2.0.
    /// Uses BouncyCastle for hex string operations when running on older frameworks.
    /// </summary>
    public static class ConvertCompat
    {
        /// <summary>
        /// Converts a hex string to a byte array.
        /// </summary>
        /// <param name="hex">The hex string to convert.</param>
        /// <returns>The byte array representation of the hex string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when hex is null.</exception>
        /// <exception cref="ArgumentException">Thrown when hex has an odd length or contains invalid characters.</exception>
        public static byte[] FromHexString(string hex)
        {
            if (hex == null)
                throw new ArgumentNullException(nameof(hex));

            return Convert.FromHexString(hex);
        }

        /// <summary>
        /// Converts a byte array to a hex string.
        /// </summary>
        /// <param name="bytes">The byte array to convert.</param>
        /// <returns>The hex string representation of the byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when bytes is null.</exception>
        public static string ToHexString(byte[] bytes)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));

            return Convert.ToHexString(bytes);
        }

        /// <summary>
        /// Converts a byte array to a lowercase hex string.
        /// </summary>
        /// <param name="bytes">The byte array to convert.</param>
        /// <returns>The lowercase hex string representation of the byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when bytes is null.</exception>
        public static string ToHexStringLower(byte[] bytes)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));

            return Convert.ToHexString(bytes).ToLowerInvariant();
        }

        /// <summary>
        /// Tries to convert a hex string to a byte array.
        /// </summary>
        /// <param name="hex">The hex string to convert.</param>
        /// <param name="bytes">When this method returns, contains the byte array if the conversion succeeded, or null if the conversion failed.</param>
        /// <returns>true if the conversion succeeded; otherwise, false.</returns>
        public static bool TryFromHexString(string hex, out byte[]? bytes)
        {
            bytes = null;

            if (string.IsNullOrEmpty(hex) || hex.Length % 2 != 0)
                return false;

            try
            {
                bytes = FromHexString(hex);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
