using System;
using Gp4Net.Constants;
using JetBrains.Annotations;

namespace Gp4Net.Transport
{
    /// <summary>
    /// Base implementation of IApduCommand providing common functionality.
    /// </summary>
    [PublicAPI]
    public abstract class BaseApduCommand : IApduCommand
    {
        /// <inheritdoc />
        public abstract byte Cla { get; }

        /// <inheritdoc />
        public abstract byte Ins { get; }

        /// <inheritdoc />
        public abstract byte P1 { get; }

        /// <inheritdoc />
        public abstract byte P2 { get; }

        /// <inheritdoc />
        public abstract byte[]? Data { get; }

        /// <inheritdoc />
        public abstract int? ExpectedResponseLength { get; }

        /// <inheritdoc />
        public virtual bool IsExtendedLength
        {
            get
            {
                var dataLength = Data?.Length ?? 0;
                var responseLength = ExpectedResponseLength ?? 0;

                return dataLength > ApduConstants.MAX_SHORT_LENGTH_LC
                    || responseLength > ApduConstants.MAX_SHORT_LENGTH_LE;
            }
        }

        /// <summary>
        /// Converts this command to APDU bytes using the specified transport.
        /// This method is provided for backward compatibility.
        /// </summary>
        /// <param name="transport">The transport to use for APDU formatting.</param>
        /// <returns>The APDU bytes.</returns>
        [Obsolete("Use IApduTransport.TransmitAsync instead of manual APDU building")]
        public byte[] ToApdu(IApduTransport transport)
        {
            // This is a simplified implementation for backward compatibility
            // Real implementation would use the transport's formatting logic

            var apdu = new System.Collections.Generic.List<byte> { Cla, Ins, P1, P2 };

            var hasData = Data != null && Data.Length > 0;
            var expectsResponse = ExpectedResponseLength.HasValue;

            if (IsExtendedLength && !transport.SupportsExtendedLength)
            {
                throw new NotSupportedException(
                    $"Extended length not supported by {transport.Protocol}"
                );
            }

            if (hasData && expectsResponse)
            {
                // Case 4
                if (IsExtendedLength)
                {
                    apdu.Add(0x00);
                    apdu.Add((byte)(Data!.Length >> 8));
                    apdu.Add((byte)(Data.Length & 0xFF));
                    apdu.AddRange(Data);

                    var le = ExpectedResponseLength!.Value;
                    if (le == 65536)
                    {
                        apdu.Add(0x00);
                        apdu.Add(0x00);
                    }
                    else
                    {
                        apdu.Add((byte)(le >> 8));
                        apdu.Add((byte)(le & 0xFF));
                    }
                }
                else
                {
                    apdu.Add((byte)Data!.Length);
                    apdu.AddRange(Data);
                    apdu.Add(GetLeByte(ExpectedResponseLength!.Value));
                }
            }
            else if (hasData)
            {
                // Case 3
                if (IsExtendedLength)
                {
                    apdu.Add(0x00);
                    apdu.Add((byte)(Data!.Length >> 8));
                    apdu.Add((byte)(Data.Length & 0xFF));
                }
                else
                {
                    apdu.Add((byte)Data!.Length);
                }
                apdu.AddRange(Data!);
            }
            else if (expectsResponse)
            {
                // Case 2
                if (IsExtendedLength)
                {
                    apdu.Add(0x00);
                    var le = ExpectedResponseLength!.Value;
                    if (le == 65536)
                    {
                        apdu.Add(0x00);
                        apdu.Add(0x00);
                    }
                    else
                    {
                        apdu.Add((byte)(le >> 8));
                        apdu.Add((byte)(le & 0xFF));
                    }
                }
                else
                {
                    apdu.Add(GetLeByte(ExpectedResponseLength!.Value));
                }
            }
            // Case 1: No additions needed

            return [.. apdu];
        }

        /// <summary>
        /// Legacy ToApdu method for backward compatibility.
        /// </summary>
        /// <returns>APDU bytes formatted for T=1.</returns>
        [Obsolete("Use IApduTransport.TransmitAsync instead")]
        public byte[] ToApdu()
        {
            // Default to T=1 behavior for backward compatibility
            var factory = new ApduTransportFactory(
                Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance
            );
            var transport = factory.CreateTransport(TransportProtocol.T1, true);
            return ToApdu(transport);
        }

        private static byte GetLeByte(int expectedLength)
        {
            return expectedLength == 256 ? (byte)0 : (byte)expectedLength;
        }
    }
}
