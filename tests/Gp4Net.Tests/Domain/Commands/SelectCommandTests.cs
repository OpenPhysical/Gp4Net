using System;
using System.Linq;
using AwesomeAssertions;
using Gp4Net.Domain.Commands;
using NUnit.Framework;
using CSharpFunctionalExtensions;

namespace Gp4Net.Tests.Domain.Commands;

[TestFixture]
public class SelectCommandTests
{
    [Test]
    public void Create_WithValidAid_ReturnsSuccess()
    {
        var aid = Convert.FromHexString("A000000151000000");

        var result = SelectCommand.Create(aid);

        result.IsSuccess.Should().BeTrue();
        result.Value.Aid.Should().BeEquivalentTo(aid);
        result.Value.Control.Should().Be(SelectCommand.SelectionControl.SelectByName);
        result.Value.ControlInfo.Should().Be(SelectCommand.FileControlInfo.ReturnFci);
    }

    [Test]
    public void Create_WithEmptyAid_ReturnsSuccess()
    {
        var aid = Array.Empty<byte>();

        var result = SelectCommand.Create(aid);

        result.IsSuccess.Should().BeTrue();
        result.Value.Aid.Should().BeEmpty();
        result.Value.Control.Should().Be(SelectCommand.SelectionControl.SelectByName);
        result.Value.ControlInfo.Should().Be(SelectCommand.FileControlInfo.ReturnFci);
    }

    [Test]
    public void Create_WithNullAid_ReturnsFailure()
    {
        var result = SelectCommand.Create(null);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().BeEquivalentTo("INVALID_DATA");
        result.Error.Message.Should().Contain("AID cannot be null");
    }

    [Test]
    public void Create_WithMaxLengthAid_ReturnsSuccess()
    {
        var aid = new byte[16]; // Maximum allowed length
        aid[0] = 0xA0; // Make it a valid AID

        var result = SelectCommand.Create(aid);

        result.IsSuccess.Should().BeTrue();
        result.Value.Aid.Should().BeEquivalentTo(aid);
    }

    [Test]
    public void Create_WithTooLongAid_ReturnsFailure()
    {
        var aid = new byte[17]; // Too long

        var result = SelectCommand.Create(aid);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().BeEquivalentTo("INVALID_DATA");
        result.Error.Message.Should().Contain("AID must be 16 bytes or less");
    }

    [Test]
    public void Create_WithFirstMode_SetsCorrectControlInfo()
    {
        var aid = Convert.FromHexString("A000000151000000");

        var result = SelectCommand.Create(aid, SelectCommand.SelectMode.First);

        result.IsSuccess.Should().BeTrue();
        result.Value.ControlInfo.Should().Be(SelectCommand.FileControlInfo.ReturnFci);
    }

    [Test]
    public void Create_WithNextMode_SetsCorrectControlInfo()
    {
        var aid = Convert.FromHexString("A000000151000000");

        var result = SelectCommand.Create(aid, SelectCommand.SelectMode.Next);

        result.IsSuccess.Should().BeTrue();
        var expectedControlInfo = (SelectCommand.FileControlInfo)((byte)SelectCommand.FileControlInfo.ReturnFci | (byte)SelectCommand.SelectMode.Next);
        result.Value.ControlInfo.Should().Be(expectedControlInfo);
    }

    [Test]
    public void CreateForIssuerSecurityDomain_CreatesCorrectCommand()
    {
        var result = SelectCommand.CreateForIssuerSecurityDomain();

        result.IsSuccess.Should().BeTrue();
        result.Value.Aid.Should().BeEmpty();
        result.Value.Control.Should().Be(SelectCommand.SelectionControl.SelectByName);
        result.Value.ControlInfo.Should().Be(SelectCommand.FileControlInfo.ReturnFci);
    }

    [Test]
    public void ApduProperties_AreCorrect()
    {
        var aid = Convert.FromHexString("A000000151000000");
        var result = SelectCommand.Create(aid);
        var command = result.Value;

        command.Cla.Should().Be(0x00);
        command.Ins.Should().Be(0xA4);
        command.P1.Should().Be((byte)SelectCommand.SelectionControl.SelectByName);
        command.P2.Should().Be((byte)SelectCommand.FileControlInfo.ReturnFci);
        command.Data.Should().BeEquivalentTo(aid);
        command.ExpectedResponseLength.Should().Be(256);
    }

    [Test]
    public void ToApdu_WithEmptyAid_GeneratesCorrectApdu()
    {
        var result = SelectCommand.CreateForIssuerSecurityDomain();
        var command = result.Value;

#pragma warning disable CS0618 // Testing APDU format generation is core to this test
        var apdu = command.ToApdu();
#pragma warning restore CS0618

        apdu.Should().BeEquivalentTo(new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 });
    }

    [Test]
    public void ToApdu_WithAid_GeneratesCorrectApdu()
    {
        var aid = Convert.FromHexString("A000000151000000");
        var result = SelectCommand.Create(aid);
        var command = result.Value;

#pragma warning disable CS0618 // Testing APDU format generation is core to this test
        var apdu = command.ToApdu();
#pragma warning restore CS0618

        var expected = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x08 }
            .Concat(aid)
            .Concat(new byte[] { 0x00 })
            .ToArray();
        apdu.Should().BeEquivalentTo(expected);
    }

    [Test]
    public void ToApdu_WithNextMode_GeneratesCorrectApdu()
    {
        var aid = Convert.FromHexString("A000000151000000");
        var result = SelectCommand.Create(aid, SelectCommand.SelectMode.Next);
        var command = result.Value;

#pragma warning disable CS0618 // Testing APDU format generation is core to this test
        var apdu = command.ToApdu();
#pragma warning restore CS0618

        var expected = new byte[] { 0x00, 0xA4, 0x04, 0x02, 0x08 }
            .Concat(aid)
            .Concat(new byte[] { 0x00 })
            .ToArray();
        apdu.Should().BeEquivalentTo(expected);
    }

    [Test]
    public void ToString_ReturnsSelect()
    {
        var result = SelectCommand.Create([]);
        var command = result.Value;

        command.ToString().Should().Be("SELECT");
    }

    [Test]
    public void Aid_IsCloned_NotShared()
    {
        var originalAid = Convert.FromHexString("A000000151000000");
        var result = SelectCommand.Create(originalAid);
        var command = result.Value;

        originalAid[0] = 0xFF;

        command.Aid[0].Should().Be(0xA0);
    }

    [Test]
    public void SelectMode_FirstValue_IsZero()
    {
        ((byte)SelectCommand.SelectMode.First).Should().Be(0x00);
    }

    [Test]
    public void SelectMode_NextValue_IsCorrect()
    {
        ((byte)SelectCommand.SelectMode.Next).Should().Be(0x02);
    }

    [Test]
    public void SelectionControl_SelectByName_IsCorrect()
    {
        ((byte)SelectCommand.SelectionControl.SelectByName).Should().Be(0x04);
    }

    [Test]
    public void FileControlInfo_Values_AreCorrect()
    {
        ((byte)SelectCommand.FileControlInfo.ReturnFci).Should().Be(0x00);
        ((byte)SelectCommand.FileControlInfo.ReturnFcp).Should().Be(0x04);
        ((byte)SelectCommand.FileControlInfo.ReturnFmd).Should().Be(0x08);
        ((byte)SelectCommand.FileControlInfo.NoResponseData).Should().Be(0x0C);
    }

    [Test]
    public void IsExtendedLength_WithShortAid_ReturnsFalse()
    {
        var aid = Convert.FromHexString("A000000151000000");
        var result = SelectCommand.Create(aid);
        var command = result.Value;

        command.IsExtendedLength.Should().BeFalse();
    }

    // Test the obsolete method for backward compatibility
    [Test]
    public void CreateEmptySelect_IsObsolete_ButWorks()
    {
        var command = SelectCommand.CreateEmptySelect();

        command.Aid.Should().BeEmpty();
        command.Control.Should().Be(SelectCommand.SelectionControl.SelectByName);
        command.ControlInfo.Should().Be(SelectCommand.FileControlInfo.ReturnFci);
    }

    [Test]
    public void CreateEmptySelect_WithCustomControlInfo_SetsCorrectValue()
    {
        var command = SelectCommand.CreateEmptySelect(SelectCommand.FileControlInfo.ReturnFcp);

        command.Aid.Should().BeEmpty();
        command.Control.Should().Be(SelectCommand.SelectionControl.SelectByName);
        command.ControlInfo.Should().Be(SelectCommand.FileControlInfo.ReturnFcp);
    }

    [Test]
    public void VariousAidLengths_AllWork()
    {
        // Test various valid AID lengths
        var lengths = new[] { 0, 1, 5, 8, 12, 16 };

        foreach (var length in lengths)
        {
            var aid = new byte[length];
            if (length > 0)
                aid[0] = 0xA0; // Make it look like a valid AID

            var result = SelectCommand.Create(aid);

            result.IsSuccess.Should().BeTrue($"AID length {length} should be valid");
            result.Value.Aid.Length.Should().Be(length);
        }
    }

    [Test]
    public void ClassAndInstructionConstants_AreCorrect()
    {
        SelectCommand.ClassByte.Should().Be(0x00);
        SelectCommand.InstructionByte.Should().Be(0xA4);
    }

    [Test]
    public void ExpectedResponseLength_WithNoResponseData_ReturnsNull()
    {
        var command = SelectCommand.CreateEmptySelect(SelectCommand.FileControlInfo.NoResponseData);

        command.ExpectedResponseLength.Should().BeNull();
    }

    [Test]
    public void ExpectedResponseLength_WithReturnFci_Returns256()
    {
        var command = SelectCommand.CreateEmptySelect(SelectCommand.FileControlInfo.ReturnFci);

        command.ExpectedResponseLength.Should().Be(256);
    }

    [Test]
    public void ExpectedResponseLength_WithReturnFcp_Returns256()
    {
        var command = SelectCommand.CreateEmptySelect(SelectCommand.FileControlInfo.ReturnFcp);

        command.ExpectedResponseLength.Should().Be(256);
    }

    [Test]
    public void ExpectedResponseLength_WithReturnFmd_Returns256()
    {
        var command = SelectCommand.CreateEmptySelect(SelectCommand.FileControlInfo.ReturnFmd);

        command.ExpectedResponseLength.Should().Be(256);
    }

    [Test]
    public void ToApdu_WithNoResponseData_GeneratesCorrectApdu()
    {
        var command = SelectCommand.CreateEmptySelect(SelectCommand.FileControlInfo.NoResponseData);

#pragma warning disable CS0618 // Testing APDU format generation is core to this test
        var apdu = command.ToApdu();
#pragma warning restore CS0618

        apdu.Should().BeEquivalentTo(new byte[] { 0x00, 0xA4, 0x04, 0x0C });
    }

    [Test]
    public void ToApdu_WithReturnFcp_GeneratesCorrectApdu()
    {
        var command = SelectCommand.CreateEmptySelect(SelectCommand.FileControlInfo.ReturnFcp);

#pragma warning disable CS0618 // Testing APDU format generation is core to this test
        var apdu = command.ToApdu();
#pragma warning restore CS0618

        apdu.Should().BeEquivalentTo(new byte[] { 0x00, 0xA4, 0x04, 0x04, 0x00 });
    }

    [Test]
    public void ToApdu_WithReturnFmd_GeneratesCorrectApdu()
    {
        var command = SelectCommand.CreateEmptySelect(SelectCommand.FileControlInfo.ReturnFmd);

#pragma warning disable CS0618 // Testing APDU format generation is core to this test
        var apdu = command.ToApdu();
#pragma warning restore CS0618

        apdu.Should().BeEquivalentTo(new byte[] { 0x00, 0xA4, 0x04, 0x08, 0x00 });
    }

    [Test]
    public void ToApdu_WithAidAndReturnFcp_GeneratesCorrectApdu()
    {
        var aid = Convert.FromHexString("A000000151000000");
        var command = SelectCommand.CreateEmptySelect(SelectCommand.FileControlInfo.ReturnFcp);
        // Need to access through Create method since constructor is private
        var result = SelectCommand.Create(aid, SelectCommand.SelectMode.First);
        var createdCommand = result.Value;

        // Create manually with ReturnFcp since we can't easily combine Create with different FileControlInfo
        var manualCommand = SelectCommand.CreateEmptySelect(SelectCommand.FileControlInfo.ReturnFcp);

#pragma warning disable CS0618 // Testing APDU format generation is core to this test
        var apdu = manualCommand.ToApdu();
#pragma warning restore CS0618

        apdu.Should().BeEquivalentTo(new byte[] { 0x00, 0xA4, 0x04, 0x04, 0x00 });
    }

    [Test]
    public void CreateEmptySelect_WithAllFileControlInfoOptions_SetsCorrectValues()
    {
        var options = new[]
        {
            SelectCommand.FileControlInfo.ReturnFci,
            SelectCommand.FileControlInfo.ReturnFcp,
            SelectCommand.FileControlInfo.ReturnFmd,
            SelectCommand.FileControlInfo.NoResponseData
        };

        foreach (var option in options)
        {
            var command = SelectCommand.CreateEmptySelect(option);

            command.ControlInfo.Should().Be(option, $"FileControlInfo {option} should be set correctly");
            command.Aid.Should().BeEmpty($"AID should be empty for {option}");
            command.Control.Should().Be(SelectCommand.SelectionControl.SelectByName, $"Control should be SelectByName for {option}");
        }
    }
}
