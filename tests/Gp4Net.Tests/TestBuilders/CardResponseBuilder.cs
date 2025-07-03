using System;
using Gp4Net.Tool.Services;

namespace Gp4Net.Tests.TestBuilders
{
    /// <summary>
    /// Builder pattern for creating CardResponse instances for testing.
    /// </summary>
    public class CardResponseBuilder
    {
        private byte[] _data = new byte[0];
        private ushort _statusWord = 0x9000;

        /// <summary>
        /// Sets the response data.
        /// </summary>
        public CardResponseBuilder WithData(params byte[] data)
        {
            _data = data;
            return this;
        }

        /// <summary>
        /// Sets the response data from a hex string.
        /// </summary>
        public CardResponseBuilder WithDataFromHex(string hexData)
        {
            _data = ConvertFromHexString(hexData);
            return this;
        }

        /// <summary>
        /// Sets the status word.
        /// </summary>
        public CardResponseBuilder WithStatusWord(ushort statusWord)
        {
            _statusWord = statusWord;
            return this;
        }

        /// <summary>
        /// Sets the status word from SW1 and SW2 bytes.
        /// </summary>
        public CardResponseBuilder WithStatusBytes(byte sw1, byte sw2)
        {
            _statusWord = (ushort)((sw1 << 8) | sw2);
            return this;
        }

        /// <summary>
        /// Sets a success status (90 00).
        /// </summary>
        public CardResponseBuilder WithSuccessStatus()
        {
            _statusWord = 0x9000;
            return this;
        }

        /// <summary>
        /// Sets a warning status (62 XX or 63 XX).
        /// </summary>
        public CardResponseBuilder WithWarningStatus(byte sw2 = 0x00)
        {
            _statusWord = (ushort)(0x6200 | sw2);
            return this;
        }

        /// <summary>
        /// Sets an error status (6X XX where X > 3).
        /// </summary>
        public CardResponseBuilder WithErrorStatus(byte sw1 = 0x6A, byte sw2 = 0x82)
        {
            _statusWord = (ushort)((sw1 << 8) | sw2);
            return this;
        }

        /// <summary>
        /// Sets a "more data available" status (61 XX).
        /// </summary>
        public CardResponseBuilder WithMoreDataAvailable(byte remainingBytes)
        {
            _statusWord = (ushort)(0x6100 | remainingBytes);
            return this;
        }

        /// <summary>
        /// Sets a security status not satisfied error (69 82).
        /// </summary>
        public CardResponseBuilder WithSecurityNotSatisfied()
        {
            _statusWord = 0x6982;
            return this;
        }

        /// <summary>
        /// Sets an authentication failed error (63 00).
        /// </summary>
        public CardResponseBuilder WithAuthenticationFailed()
        {
            _statusWord = 0x6300;
            return this;
        }

        /// <summary>
        /// Builds the CardResponse instance.
        /// </summary>
        public CardResponse Build()
        {
            return new CardResponse(_data, _statusWord);
        }

        /// <summary>
        /// Implicit conversion to CardResponse.
        /// </summary>
        public static implicit operator CardResponse(CardResponseBuilder builder)
        {
            return builder.Build();
        }

        private static byte[] ConvertFromHexString(string hex)
        {
            // Remove spaces and convert to uppercase
            hex = hex.Replace(" ", "").Replace("-", "").ToUpperInvariant();

            // Ensure even length
            if (hex.Length % 2 != 0)
            {
                throw new ArgumentException("Hex string must have even length");
            }

            var bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }
    }
}
