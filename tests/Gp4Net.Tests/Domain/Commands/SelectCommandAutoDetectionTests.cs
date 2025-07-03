using System;
using System.Linq;
using Gp4Net.Core.Tlv;
using Gp4Net.Domain.Commands;
using Xunit;

namespace Gp4Net.Tests.Domain.Commands
{
    public class SelectCommandAutoDetectionTests
    {
        [Fact]
        public void CreateEmptySelect_CreatesSelectWithEmptyAid()
        {
            // Act
            var command = SelectCommand.CreateEmptySelect();

            // Assert
            Assert.NotNull(command);
            Assert.Empty(command.Aid);
            Assert.Equal(SelectCommand.SelectionControl.SelectByName, command.Control);
            Assert.Equal(SelectCommand.FileControlInfo.ReturnFci, command.ControlInfo);
        }

        [Fact]
        public void EmptySelectCommand_GeneratesCorrectApdu()
        {
            // Arrange
            var command = SelectCommand.CreateEmptySelect();

            // Act
            var apdu = command.ToApdu();

            // Assert
            Assert.Equal(new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 }, apdu);
        }

        [Fact]
        public void SelectCommand_AllowsEmptyAid()
        {
            // Act & Assert - Should not throw
            var command = new SelectCommand(Array.Empty<byte>());
            Assert.Empty(command.Aid);
        }

        [Fact]
        public void SelectResponse_ParsesFciWithAid()
        {
            // Arrange - FCI from the trace: 6F108408A000000151000000A5049F6501FF
            var fciData = Convert.FromHexString("6F108408A000000151000000A5049F6501FF");

            // Act
            var response = SelectResponse.Parse(fciData);

            // Assert
            Assert.NotNull(response);
            Assert.NotNull(response.Fci);
            Assert.NotNull(response.Fci.ApplicationAid);
            Assert.Equal("A000000151000000", Convert.ToHexString(response.Fci.ApplicationAid));
            Assert.Equal((ushort?)255, response.Fci.MaxCommandDataLength);
        }

        [Fact]
        public void SelectResponse_ParsesComplexFci()
        {
            // Arrange - More complex FCI with multiple fields
            var tlvBuilder = new TlvBuilder();
            tlvBuilder.Add(
                0x6F,
                builder =>
                {
                    builder.Add(0x84, Convert.FromHexString("A0000000030000")); // AID
                    builder.Add(0x50, System.Text.Encoding.UTF8.GetBytes("ISD")); // Label
                    builder.Add(
                        0xA5,
                        subBuilder =>
                        {
                            subBuilder.Add(0x9F65, new byte[] { 0xFF }); // Max command length
                            subBuilder.Add(0x9F66, new byte[] { 0xFF }); // Max response length
                        }
                    );
                }
            );

            var fciData = tlvBuilder.Build();

            // Act
            var response = SelectResponse.Parse(fciData);

            // Assert
            Assert.NotNull(response);
            Assert.NotNull(response.Fci);
            Assert.Equal("A0000000030000", Convert.ToHexString(response.Fci.ApplicationAid));
            Assert.Equal("ISD", response.Fci.ApplicationLabel);
            Assert.Equal((ushort?)255, response.Fci.MaxCommandDataLength);
            Assert.Equal((ushort?)255, response.Fci.MaxResponseDataLength);
        }

        [Fact]
        public void SelectResponse_HandlesEmptyResponse()
        {
            // Arrange
            var emptyData = Array.Empty<byte>();

            // Act
            var response = SelectResponse.Parse(emptyData);

            // Assert
            Assert.NotNull(response);
            Assert.Null(response.Fci);
            Assert.Empty(response.RawData);
        }

        [Fact]
        public void SelectResponse_HandlesNonFciResponse()
        {
            // Arrange - Some TLV data that's not FCI
            var nonFciData = Convert.FromHexString("9F7F2A47900000");

            // Act
            var response = SelectResponse.Parse(nonFciData);

            // Assert
            Assert.NotNull(response);
            Assert.Null(response.Fci); // Should not parse as FCI
            Assert.Equal(nonFciData, response.RawData);
        }
    }

    /// <summary>
    /// Helper class to build TLV structures for testing.
    /// </summary>
    internal class TlvBuilder
    {
        private readonly System.Collections.Generic.List<byte> _data = [];

        public void Add(int tag, byte[] value)
        {
            AddTag(tag);
            AddLength(value.Length);
            _data.AddRange(value);
        }

        public void Add(int tag, Action<TlvBuilder> constructedContent)
        {
            var subBuilder = new TlvBuilder();
            constructedContent(subBuilder);
            var value = subBuilder.Build();
            Add(tag, value);
        }

        public byte[] Build()
        {
            return [.. _data];
        }

        private void AddTag(int tag)
        {
            if (tag <= 0xFF)
            {
                _data.Add((byte)tag);
            }
            else if (tag <= 0xFFFF)
            {
                _data.Add((byte)(tag >> 8));
                _data.Add((byte)(tag & 0xFF));
            }
            else
            {
                throw new NotSupportedException(
                    "Tags larger than 2 bytes not supported in this helper"
                );
            }
        }

        private void AddLength(int length)
        {
            if (length <= 127)
            {
                _data.Add((byte)length);
            }
            else if (length <= 255)
            {
                _data.Add(0x81);
                _data.Add((byte)length);
            }
            else
            {
                throw new NotSupportedException(
                    "Lengths larger than 255 not supported in this helper"
                );
            }
        }
    }
}
