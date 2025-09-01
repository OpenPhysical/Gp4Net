using System;
using System.Collections.Generic;
using System.Text;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
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
        Result<SelectCommand, SmartCardError> result =
            SelectCommand.CreateForIssuerSecurityDomain();

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        SelectCommand? command = result.Value;
        _ = command.Should().NotBeNull();
        _ = command.Aid.Should().BeEmpty();
        _ = command.Control.Should().Be(SelectCommand.SelectionControl.SelectByName);
        _ = command.ControlInfo.Should().Be(SelectCommand.FileControlInfo.ReturnFci);
    }

    [Test]
    public void EmptySelectCommand_GeneratesCorrectApdu()
    {
        // Arrange
        Result<SelectCommand, SmartCardError> result =
            SelectCommand.CreateForIssuerSecurityDomain();
        _ = result.IsSuccess.Should().BeTrue();
        SelectCommand? command = result.Value;

        // Act
        byte[]? apdu = ApduBuilder.BuildApdu(command);

        // Assert
        _ = apdu.Should().BeEquivalentTo(new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 });
    }

    [Test]
    public void SelectCommand_AllowsEmptyAid()
    {
        // Act
        Result<SelectCommand, SmartCardError> result = SelectCommand.Create([]);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        SelectCommand? command = result.Value;
        _ = command.Aid.Should().BeEmpty();
    }

    [Test]
    public void SelectResponse_ParsesFciWithAid()
    {
        // Arrange - FCI from the trace: 6F108408A000000151000000A5049F6501FF
        byte[] fciData = Convert.FromHexString("6F108408A000000151000000A5049F6501FF");

        // Act
        Result<SelectResponse, SmartCardError> result = SelectResponse.Parse(fciData);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        SelectResponse? response = result.Value;
        _ = response.Fci.HasValue.Should().BeTrue();
        _ = response.Fci.Match(
            fci =>
            {
                _ = fci.ApplicationAid.Should().NotBeEmpty();
                string aidHex = Convert.ToHexString(fci.ApplicationAid);
                _ = aidHex.Should().BeEquivalentTo("A000000151000000");
                _ = fci.MaxCommandDataLength.Match(
                    value =>
                    {
                        _ = value.Should().Be(255);
                        return true;
                    },
                    () =>
                    {
                        _ = false.Should().BeTrue("MaxCommandDataLength should have a value");
                        return false;
                    }
                );
                return true;
            },
            () =>
            {
                _ = false.Should().BeTrue("FCI should have a value");
                return false;
            }
        );
    }

    [Test]
    public void SelectResponse_ParsesComplexFci()
    {
        // Arrange - More complex FCI with multiple fields
        TlvBuilder tlvBuilder = new TlvBuilder();
        tlvBuilder.Add(
            0x6F,
            builder =>
            {
                builder.Add(0x84, Convert.FromHexString("A0000000030000")); // AID
                builder.Add(0x50, Encoding.UTF8.GetBytes("ISD")); // Label
                builder.Add(
                    0xA5,
                    subBuilder =>
                    {
                        subBuilder.Add(0x9F65, [0xFF]); // Max command length
                        subBuilder.Add(0x9F66, [0xFF]); // Max response length
                    }
                );
            }
        );

        byte[] fciData = tlvBuilder.Build();

        // Act
        Result<SelectResponse, SmartCardError> result = SelectResponse.Parse(fciData);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        SelectResponse? response = result.Value;
        _ = response.Fci.HasValue.Should().BeTrue();
        _ = response.Fci.Match(
            fci =>
            {
                _ = fci.ApplicationAid.Should().NotBeEmpty();
                string aidHex = Convert.ToHexString(fci.ApplicationAid);
                _ = aidHex.Should().BeEquivalentTo("A0000000030000");
                _ = fci.ApplicationLabel.Match(
                    label =>
                    {
                        _ = label.Should().BeEquivalentTo("ISD");
                        return true;
                    },
                    () =>
                    {
                        _ = false.Should().BeTrue("ApplicationLabel should have a value");
                        return false;
                    }
                );
                _ = fci.MaxCommandDataLength.Match(
                    value =>
                    {
                        _ = value.Should().Be(255);
                        return true;
                    },
                    () =>
                    {
                        _ = false.Should().BeTrue("MaxCommandDataLength should have a value");
                        return false;
                    }
                );
                _ = fci.MaxResponseDataLength.Match(
                    value =>
                    {
                        _ = value.Should().Be(255);
                        return true;
                    },
                    () =>
                    {
                        _ = false.Should().BeTrue("MaxResponseDataLength should have a value");
                        return false;
                    }
                );
                return true;
            },
            () =>
            {
                _ = false.Should().BeTrue("FCI should have a value");
                return false;
            }
        );
    }

    [Test]
    public void SelectResponse_HandlesEmptyResponse()
    {
        // Arrange
        byte[] emptyData = [];

        // Act
        Result<SelectResponse, SmartCardError> result = SelectResponse.Parse(emptyData);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        SelectResponse? response = result.Value;
        _ = response.Should().NotBeNull();
        _ = response.Fci.HasValue.Should().BeFalse();
        _ = response.RawData.Should().BeEmpty();
    }

    [Test]
    public void SelectResponse_HandlesNonFciResponse()
    {
        // Arrange - Some TLV data that's not FCI
        byte[] nonFciData = Convert.FromHexString("9F7F2A47900000");

        // Act
        Result<SelectResponse, SmartCardError> result = SelectResponse.Parse(nonFciData);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        SelectResponse? response = result.Value;
        _ = response.Should().NotBeNull();
        _ = response.Fci.HasValue.Should().BeFalse(); // Should not parse as FCI
        _ = response.RawData.Should().BeEquivalentTo(nonFciData);
    }

    [Test]
    public void SelectCommand_Create_WithNullAid_ReturnsFailure()
    {
        // Act
        Result<SelectCommand, SmartCardError> result = SelectCommand.Create(null);

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<InvalidDataError>();
        InvalidDataError? error = result.Error as InvalidDataError;
        _ = error.Should().NotBeNull();
        _ = error!.Field.Should().Be("AID");
        _ = error.Message.Should().Contain("cannot be null");
    }

    [Test]
    public void SelectCommand_Create_WithTooLongAid_ReturnsFailure()
    {
        // Arrange
        byte[] tooLongAid = new byte[17]; // 17 bytes is too long

        // Act
        Result<SelectCommand, SmartCardError> result = SelectCommand.Create(tooLongAid);

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<InvalidLengthError>();
        InvalidLengthError? error = result.Error as InvalidLengthError;
        _ = error.Should().NotBeNull();
        _ = error!.Field.Should().Be("AID");
        _ = error.Expected.Should().Be(16);
        _ = error.Actual.Should().Be(17);
    }

    [Test]
    public void SelectCommand_Create_WithValidAid_ReturnsSuccess()
    {
        // Arrange
        byte[] aid = Convert.FromHexString("A000000151000000");

        // Act
        Result<SelectCommand, SmartCardError> result = SelectCommand.Create(aid);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        SelectCommand? command = result.Value;
        _ = command.Aid.Should().BeEquivalentTo(aid);
        _ = command.Control.Should().Be(SelectCommand.SelectionControl.SelectByName);
    }

    [Test]
    public void SelectCommand_Create_WithNextMode_SetsCorrectControlInfo()
    {
        // Arrange
        byte[] aid = Convert.FromHexString("A000000151000000");

        // Act
        Result<SelectCommand, SmartCardError> result = SelectCommand.Create(
            aid,
            SelectCommand.SelectMode.Next
        );

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        SelectCommand? command = result.Value;
        _ = command.Aid.Should().BeEquivalentTo(aid);
        _ = ((byte)command.ControlInfo).Should().Be(0x02); // ReturnFci | Next
    }

    [Test]
    public void SelectResponse_Parse_WithNullData_ReturnsFailure()
    {
        // Act
        Result<SelectResponse, SmartCardError> result = SelectResponse.Parse(null);

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<InvalidDataError>();
        InvalidDataError? error = result.Error as InvalidDataError;
        _ = error.Should().NotBeNull();
        _ = error!.Field.Should().Be("Response");
        _ = error.Message.Should().Contain("cannot be null");
    }

    [Test]
    public void SelectCommand_ToString_ReturnsSelect()
    {
        // Arrange
        Result<SelectCommand, SmartCardError> result = SelectCommand.Create(
            Convert.FromHexString("A000000151000000")
        );
        _ = result.IsSuccess.Should().BeTrue();
        SelectCommand? command = result.Value;

        // Act
        string? str = command.ToString();

        // Assert
        _ = str.Should().Be("SELECT");
    }
}

/// <summary>
/// Helper class to build TLV structures for testing.
/// </summary>
internal class TlvBuilder
{
    private readonly List<byte> _data = [];

    public void Add(int tag, byte[] value)
    {
        AddTag(tag);
        AddLength(value.Length);
        _data.AddRange(value);
    }

    public void Add(int tag, Action<TlvBuilder> constructedContent)
    {
        TlvBuilder subBuilder = new TlvBuilder();
        constructedContent(subBuilder);
        byte[] value = subBuilder.Build();
        Add(tag, value);
    }

    public byte[] Build()
    {
        return [.. _data];
    }

    private void AddTag(int tag)
    {
        switch (tag)
        {
            case <= 0xFF:
                _data.Add((byte)tag);
                break;
            case <= 0xFFFF:
                _data.Add((byte)(tag >> 8));
                _data.Add((byte)(tag & 0xFF));
                break;
            default:
                throw new NotSupportedException(
                    "Tags larger than 2 bytes not supported in this helper"
                );
        }
    }

    private void AddLength(int length)
    {
        switch (length)
        {
            case <= 127:
                _data.Add((byte)length);
                break;
            case <= 255:
                _data.Add(0x81);
                _data.Add((byte)length);
                break;
            default:
                throw new NotSupportedException(
                    "Lengths larger than 255 not supported in this helper"
                );
        }
    }
}
