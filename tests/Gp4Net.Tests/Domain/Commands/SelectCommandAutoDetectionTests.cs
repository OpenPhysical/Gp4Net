using System;
using System.Linq;
using Gp4Net.Core;
using Gp4Net.Core.Tlv;
using Gp4Net.Domain.Commands;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands
{
    [TestFixture]
    public class SelectCommandAutoDetectionTests
    {
        [Test]
        public void CreateForIssuerSecurityDomain_CreatesSelectWithEmptyAid()
        {
            // Act
            var result = SelectCommand.CreateForIssuerSecurityDomain();

            // Assert
            Assert.That(result.IsSuccess, Is.True);
            var command = result.Value;
            Assert.That(command, Is.Not.Null);
            Assert.That(command.Aid, Is.Empty);
            Assert.That(command.Control, Is.EqualTo(SelectCommand.SelectionControl.SelectByName));
            Assert.That(command.ControlInfo, Is.EqualTo(SelectCommand.FileControlInfo.ReturnFci));
        }

        [Test]
        public void EmptySelectCommand_GeneratesCorrectApdu()
        {
            // Arrange
            var result = SelectCommand.CreateForIssuerSecurityDomain();
            Assert.That(result.IsSuccess, Is.True);
            var command = result.Value;

            // Act
            var apdu = command.ToApdu();

            // Assert
            Assert.That(apdu, Is.EqualTo(new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 }));
        }

        [Test]
        public void SelectCommand_AllowsEmptyAid()
        {
            // Act
            var result = SelectCommand.Create(Array.Empty<byte>());
            
            // Assert
            Assert.That(result.IsSuccess, Is.True);
            var command = result.Value;
            Assert.That(command.Aid, Is.Empty);
        }

        [Test]
        public void SelectResponse_ParsesFciWithAid()
        {
            // Arrange - FCI from the trace: 6F108408A000000151000000A5049F6501FF
            var fciData = Convert.FromHexString("6F108408A000000151000000A5049F6501FF");

            // Act
            var result = SelectResponse.Parse(fciData);

            // Assert
            Assert.That(result.IsSuccess, Is.True);
            var response = result.Value;
            Assert.That(response, Is.Not.Null);
            Assert.That(response.Fci, Is.Not.Null);
            Assert.That(response.Fci.ApplicationAid, Is.Not.Null);
            Assert.That(Convert.ToHexString(response.Fci.ApplicationAid), Is.EqualTo("A000000151000000"));
            Assert.That(response.Fci.MaxCommandDataLength, Is.EqualTo((ushort?)255));
        }

        [Test]
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
            var result = SelectResponse.Parse(fciData);

            // Assert
            Assert.That(result.IsSuccess, Is.True);
            var response = result.Value;
            Assert.That(response, Is.Not.Null);
            Assert.That(response.Fci, Is.Not.Null);
            Assert.That(Convert.ToHexString(response.Fci.ApplicationAid), Is.EqualTo("A0000000030000"));
            Assert.That(response.Fci.ApplicationLabel, Is.EqualTo("ISD"));
            Assert.That(response.Fci.MaxCommandDataLength, Is.EqualTo((ushort?)255));
            Assert.That(response.Fci.MaxResponseDataLength, Is.EqualTo((ushort?)255));
        }

        [Test]
        public void SelectResponse_HandlesEmptyResponse()
        {
            // Arrange
            var emptyData = Array.Empty<byte>();

            // Act
            var result = SelectResponse.Parse(emptyData);

            // Assert
            Assert.That(result.IsSuccess, Is.True);
            var response = result.Value;
            Assert.That(response, Is.Not.Null);
            Assert.That(response.Fci, Is.Null);
            Assert.That(response.RawData, Is.Empty);
        }

        [Test]
        public void SelectResponse_HandlesNonFciResponse()
        {
            // Arrange - Some TLV data that's not FCI
            var nonFciData = Convert.FromHexString("9F7F2A47900000");

            // Act
            var result = SelectResponse.Parse(nonFciData);

            // Assert
            Assert.That(result.IsSuccess, Is.True);
            var response = result.Value;
            Assert.That(response, Is.Not.Null);
            Assert.That(response.Fci, Is.Null); // Should not parse as FCI
            Assert.That(response.RawData, Is.EqualTo(nonFciData));
        }

        [Test]
        public void SelectCommand_Create_WithNullAid_ReturnsFailure()
        {
            // Act
            var result = SelectCommand.Create(null);

            // Assert
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Code, Is.EqualTo("INVALID_DATA"));
            Assert.That(result.Error.Message, Does.Contain("AID cannot be null"));
        }

        [Test]
        public void SelectCommand_Create_WithTooLongAid_ReturnsFailure()
        {
            // Arrange
            var tooLongAid = new byte[17]; // 17 bytes is too long

            // Act
            var result = SelectCommand.Create(tooLongAid);

            // Assert
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Code, Is.EqualTo("INVALID_DATA"));
            Assert.That(result.Error.Message, Does.Contain("AID must be 16 bytes or less"));
        }

        [Test]
        public void SelectCommand_Create_WithValidAid_ReturnsSuccess()
        {
            // Arrange
            var aid = Convert.FromHexString("A000000151000000");

            // Act
            var result = SelectCommand.Create(aid);

            // Assert
            Assert.That(result.IsSuccess, Is.True);
            var command = result.Value;
            Assert.That(command.Aid, Is.EqualTo(aid));
            Assert.That(command.Control, Is.EqualTo(SelectCommand.SelectionControl.SelectByName));
        }

        [Test]
        public void SelectCommand_Create_WithNextMode_SetsCorrectControlInfo()
        {
            // Arrange
            var aid = Convert.FromHexString("A000000151000000");

            // Act
            var result = SelectCommand.Create(aid, SelectCommand.SelectMode.Next);

            // Assert
            Assert.That(result.IsSuccess, Is.True);
            var command = result.Value;
            Assert.That(command.Aid, Is.EqualTo(aid));
            Assert.That((byte)command.ControlInfo, Is.EqualTo(0x02)); // ReturnFci | Next
        }

        [Test]
        public void SelectResponse_Parse_WithNullData_ReturnsFailure()
        {
            // Act
            var result = SelectResponse.Parse(null);

            // Assert
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Code, Is.EqualTo("INVALID_DATA"));
            Assert.That(result.Error.Message, Does.Contain("Response data cannot be null"));
        }

        [Test]
        public void SelectCommand_ToString_ReturnsSelect()
        {
            // Arrange
            var result = SelectCommand.Create(Convert.FromHexString("A000000151000000"));
            Assert.That(result.IsSuccess, Is.True);
            var command = result.Value;

            // Act
            var str = command.ToString();

            // Assert
            Assert.That(str, Is.EqualTo("SELECT"));
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
