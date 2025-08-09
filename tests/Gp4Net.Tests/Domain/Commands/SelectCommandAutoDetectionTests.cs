using System;
using AwesomeAssertions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Transport;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands;

[TestFixture]
[Category("Unit")]
public class SelectCommandAutoDetectionTests
{
    [Test]
    public void CreateForIssuerSecurityDomain_CreatesSelectWithEmptyAid()
    {
        // Act
        var result = SelectCommand.CreateForIssuerSecurityDomain();

        // Assert
        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.Should().NotBeNull();
        command.Aid.Should().BeEmpty();
        command.Control.Should().Be(SelectCommand.SelectionControl.SelectByName);
        command.ControlInfo.Should().Be(SelectCommand.FileControlInfo.ReturnFci);
    }

    [Test]
    public void EmptySelectCommand_GeneratesCorrectApdu()
    {
        // Arrange
        var result = SelectCommand.CreateForIssuerSecurityDomain();
        result.IsSuccess.Should().BeTrue();
        var command = result.Value;

        // Act
        var apdu = ApduBuilder.BuildApdu(command);

        // Assert
        apdu.Should().BeEquivalentTo(new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 });
    }

    [Test]
    public void SelectCommand_AllowsEmptyAid()
    {
        // Act
        var result = SelectCommand.Create([]);

        // Assert
        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.Aid.Should().BeEmpty();
    }

    [Test]
    public void SelectResponse_ParsesFciWithAid()
    {
        // Arrange - FCI from the trace: 6F108408A000000151000000A5049F6501FF
        var fciData = Convert.FromHexString("6F108408A000000151000000A5049F6501FF");

        // Act
        var result = SelectResponse.Parse(fciData);

        // Assert
        result.IsSuccess.Should().BeTrue();
        var response = result.Value;
        response.Should().NotBeNull();
        response.Fci.Should().NotBeNull();
        response.Fci.ApplicationAid.Should().NotBeNull();
        // After verifying ApplicationAid is not null, we can safely convert it
        var aidHex = Convert.ToHexString(response.Fci.ApplicationAid);
        aidHex.Should().BeEquivalentTo("A000000151000000");
        response.Fci.MaxCommandDataLength.Should().Be((ushort?)255);
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
        result.IsSuccess.Should().BeTrue();
        var response = result.Value;
        response.Should().NotBeNull();
        response.Fci.Should().NotBeNull();
        // After verifying Fci is not null, we can safely access its properties
        response.Fci.ApplicationAid.Should().NotBeNull();
        // After verifying ApplicationAid is not null, we can safely convert it
        var aidHex = Convert.ToHexString(response.Fci.ApplicationAid);
        aidHex.Should().BeEquivalentTo("A0000000030000");
        response.Fci.ApplicationLabel.Should().BeEquivalentTo("ISD");
        response.Fci.MaxCommandDataLength.Should().Be((ushort?)255);
        response.Fci.MaxResponseDataLength.Should().Be((ushort?)255);
    }

    [Test]
    public void SelectResponse_HandlesEmptyResponse()
    {
        // Arrange
        var emptyData = Array.Empty<byte>();

        // Act
        var result = SelectResponse.Parse(emptyData);

        // Assert
        result.IsSuccess.Should().BeTrue();
        var response = result.Value;
        response.Should().NotBeNull();
        response.Fci.Should().BeNull();
        response.RawData.Should().BeEmpty();
    }

    [Test]
    public void SelectResponse_HandlesNonFciResponse()
    {
        // Arrange - Some TLV data that's not FCI
        var nonFciData = Convert.FromHexString("9F7F2A47900000");

        // Act
        var result = SelectResponse.Parse(nonFciData);

        // Assert
        result.IsSuccess.Should().BeTrue();
        var response = result.Value;
        response.Should().NotBeNull();
        response.Fci.Should().BeNull(); // Should not parse as FCI
        response.RawData.Should().BeEquivalentTo(nonFciData);
    }

    [Test]
    public void SelectCommand_Create_WithNullAid_ReturnsFailure()
    {
        // Act
        var result = SelectCommand.Create(null);

        // Assert
        result.IsFailure.Should().BeTrue();
        result.Error.Should().BeOfType<InvalidDataError>();
        var error = result.Error as InvalidDataError;
        error.Should().NotBeNull();
        error!.Field.Should().Be("AID");
        error.Message.Should().Contain("cannot be null");
    }

    [Test]
    public void SelectCommand_Create_WithTooLongAid_ReturnsFailure()
    {
        // Arrange
        var tooLongAid = new byte[17]; // 17 bytes is too long

        // Act
        var result = SelectCommand.Create(tooLongAid);

        // Assert
        result.IsFailure.Should().BeTrue();
        result.Error.Should().BeOfType<InvalidLengthError>();
        var error = result.Error as InvalidLengthError;
        error.Should().NotBeNull();
        error!.Field.Should().Be("AID");
        error.Expected.Should().Be(16);
        error.Actual.Should().Be(17);
    }

    [Test]
    public void SelectCommand_Create_WithValidAid_ReturnsSuccess()
    {
        // Arrange
        var aid = Convert.FromHexString("A000000151000000");

        // Act
        var result = SelectCommand.Create(aid);

        // Assert
        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.Aid.Should().BeEquivalentTo(aid);
        command.Control.Should().Be(SelectCommand.SelectionControl.SelectByName);
    }

    [Test]
    public void SelectCommand_Create_WithNextMode_SetsCorrectControlInfo()
    {
        // Arrange
        var aid = Convert.FromHexString("A000000151000000");

        // Act
        var result = SelectCommand.Create(aid, SelectCommand.SelectMode.Next);

        // Assert
        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.Aid.Should().BeEquivalentTo(aid);
        ((byte)command.ControlInfo).Should().Be(0x02); // ReturnFci | Next
    }

    [Test]
    public void SelectResponse_Parse_WithNullData_ReturnsFailure()
    {
        // Act
        var result = SelectResponse.Parse(null);

        // Assert
        result.IsFailure.Should().BeTrue();
        result.Error.Should().BeOfType<InvalidDataError>();
        var error = result.Error as InvalidDataError;
        error.Should().NotBeNull();
        error!.Field.Should().Be("Response");
        error.Message.Should().Contain("cannot be null");
    }

    [Test]
    public void SelectCommand_ToString_ReturnsSelect()
    {
        // Arrange
        var result = SelectCommand.Create(Convert.FromHexString("A000000151000000"));
        result.IsSuccess.Should().BeTrue();
        var command = result.Value;

        // Act
        var str = command.ToString();

        // Assert
        str.Should().Be("SELECT");
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
