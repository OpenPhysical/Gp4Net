using System;
using System.Collections.Generic;
using AwesomeAssertions;
using Gp4Net.Domain.Commands;
using Gp4Net.Transport;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands;

[TestFixture]
[Category("Unit")]
public class GetStatusCommandTests
{

    [Test]
    [TestCase(GetStatusCommand.StatusSubset.IssuerSecurityDomain)]
    [TestCase(GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains)]
    [TestCase(GetStatusCommand.StatusSubset.ExecutableLoadFiles)]
    [TestCase(GetStatusCommand.StatusSubset.ExecutableLoadFilesAndModules)]
    public void Create_WithValidStatusSubset_ReturnsSuccessResult(GetStatusCommand.StatusSubset subset)
    {
        var result = GetStatusCommand.Create(subset);

        result.IsSuccess.Should().BeTrue();
        result.Value.Subset.Should().Be(subset);
        result.Value.Format.Should().Be(GetStatusCommand.ResponseFormat.None);
        result.Value.SearchCriteria.Should().BeEmpty();
    }

    [Test]
    [TestCase(GetStatusCommand.ResponseFormat.None)]
    [TestCase(GetStatusCommand.ResponseFormat.Tlv)]
    public void Create_WithValidResponseFormat_ReturnsSuccessResult(GetStatusCommand.ResponseFormat format)
    {
        var result = GetStatusCommand.Create(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
            format
        );

        result.IsSuccess.Should().BeTrue();
        result.Value.Format.Should().Be(format);
    }

    [Test]
    public void Create_WithValidSearchCriteria_ReturnsSuccessResult()
    {
        var aid = Convert.FromHexString("A0000000031010");

        var result = GetStatusCommand.Create(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
            GetStatusCommand.ResponseFormat.None,
            aid
        );

        result.IsSuccess.Should().BeTrue();
        result.Value.SearchCriteria.Should().BeEquivalentTo(aid);
    }

    [Test]
    [TestCase(4)]  // Too short
    [TestCase(17)] // Too long
    public void Create_WithInvalidSearchCriteriaLength_ReturnsFailureResult(int length)
    {
        var aid = new byte[length];

        var result = GetStatusCommand.Create(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
            GetStatusCommand.ResponseFormat.None,
            aid
        );

        result.IsFailure.Should().BeTrue();
        result.Error.Message.Should().Contain("Search criteria AID must be between 5 and 16 bytes");
    }

    [Test]
    [TestCase(5)]  // Minimum valid length
    [TestCase(10)] // Mid-range
    [TestCase(16)] // Maximum valid length
    public void Create_WithValidSearchCriteriaLengths_ReturnsSuccessResult(int length)
    {
        var aid = new byte[length];

        var result = GetStatusCommand.Create(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
            GetStatusCommand.ResponseFormat.None,
            aid
        );

        result.IsSuccess.Should().BeTrue();
        result.Value.SearchCriteria!.Length.Should().Be(length);
    }

    [Test]
    public void Create_WithInvalidStatusSubset_ReturnsFailureResult()
    {
        var invalidSubset = (GetStatusCommand.StatusSubset)0xFF;

        var result = GetStatusCommand.Create(invalidSubset);

        result.IsFailure.Should().BeTrue();
        result.Error.Message.Should().Contain("Invalid status subset");
    }

    [Test]
    public void Create_WithInvalidResponseFormat_ReturnsFailureResult()
    {
        var invalidFormat = (GetStatusCommand.ResponseFormat)0xFF;

        var result = GetStatusCommand.Create(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
            invalidFormat
        );

        result.IsFailure.Should().BeTrue();
        result.Error.Message.Should().Contain("Invalid response format");
    }

    [Test]
    public void SearchCriteria_IsImmutable()
    {
        var originalAid = Convert.FromHexString("A0000000031010");
        var result = GetStatusCommand.Create(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
            GetStatusCommand.ResponseFormat.None,
            originalAid
        );
        var command = result.Value;

        originalAid[0] = 0xFF;

        command.SearchCriteria![0].Should().Be(0xA0);
    }

    [Test]
    public void ToApdu_WithoutSearchCriteria_ReturnsCase2Apdu()
    {
        var result = GetStatusCommand.Create(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
            GetStatusCommand.ResponseFormat.None
        );
        var command = result.Value;

        var apdu = ApduBuilder.BuildApdu(command);

        apdu.Length.Should().Be(5); // CLA INS P1 P2 Le
        apdu[0].Should().Be(0x80); // CLA
        apdu[1].Should().Be(0xF2); // INS
        apdu[2].Should().Be(0x40); // P1 - Applications subset
        apdu[3].Should().Be(0x00); // P2 - No format
        apdu[4].Should().Be(0x00); // Le
    }

    [Test]
    public void ToApdu_WithSearchCriteria_ReturnsCase4Apdu()
    {
        var aid = Convert.FromHexString("A0000000031010");
        var result = GetStatusCommand.Create(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
            GetStatusCommand.ResponseFormat.None,
            aid
        );
        var command = result.Value;

        var apdu = ApduBuilder.BuildApdu(command);

        apdu.Length.Should().Be(5 + aid.Length + 1); // CLA INS P1 P2 Lc Data Le
        apdu[0].Should().Be(0x80); // CLA
        apdu[1].Should().Be(0xF2); // INS
        apdu[2].Should().Be(0x40); // P1
        apdu[3].Should().Be(0x00); // P2
        apdu[4].Should().Be((byte)aid.Length); // Lc
        apdu[5..(5 + aid.Length)].Should().BeEquivalentTo(aid); // Data
        apdu[5 + aid.Length].Should().Be(0x00); // Le
    }

    [Test]
    [TestCase(GetStatusCommand.StatusSubset.IssuerSecurityDomain, 0x80)]
    [TestCase(GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains, 0x40)]
    [TestCase(GetStatusCommand.StatusSubset.ExecutableLoadFiles, 0x20)]
    [TestCase(GetStatusCommand.StatusSubset.ExecutableLoadFilesAndModules, 0x10)]
    public void ToApdu_WithDifferentSubsets_SetsP1Correctly(GetStatusCommand.StatusSubset subset, byte expectedP1)
    {
        var result = GetStatusCommand.Create(subset);
        var command = result.Value;

        var apdu = ApduBuilder.BuildApdu(command);

        apdu[2].Should().Be(expectedP1);
    }

    [Test]
    [TestCase(GetStatusCommand.ResponseFormat.None, 0x00)]
    [TestCase(GetStatusCommand.ResponseFormat.Tlv, 0x02)]
    public void ToApdu_WithDifferentFormats_SetsP2Correctly(GetStatusCommand.ResponseFormat format, byte expectedP2)
    {
        var result = GetStatusCommand.Create(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
            format
        );
        var command = result.Value;

        var apdu = ApduBuilder.BuildApdu(command);

        apdu[3].Should().Be(expectedP2);
    }

    [Test]
    public void ToApdu_AlwaysReturnsNewArray()
    {
        var result = GetStatusCommand.Create(GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains);
        var command = result.Value;

        var apdu1 = command.ToApdu();
        var apdu2 = command.ToApdu();

        apdu1.Should().NotBeSameAs(apdu2);
        apdu2.Should().BeEquivalentTo(apdu1);
    }

    [Test]
    public void IApduCommand_Properties_ReturnCorrectValues()
    {
        var result = GetStatusCommand.Create(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
            GetStatusCommand.ResponseFormat.Tlv
        );
        var command = result.Value;
        var iApduCommand = (IApduCommand)command;

        iApduCommand.Cla.Should().Be(0x80);
        iApduCommand.Ins.Should().Be(0xF2);
        command.P1.Should().Be(0x40);
        command.P2.Should().Be(0x02);
        command.Data.Should().BeEmpty();
        command.ExpectedResponseLength.Should().Be(256);
        command.IsExtendedLength.Should().BeFalse();
    }

    [Test]
    public void IApduCommand_WithSearchCriteria_ReturnsCorrectData()
    {
        var aid = Convert.FromHexString("A0000000031010");
        var result = GetStatusCommand.Create(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
            GetStatusCommand.ResponseFormat.None,
            aid
        );
        var command = result.Value;

        command.Data.Should().BeEquivalentTo(aid);
    }

    [Test]
    public void GetStatusResponse_Parse_WithValidSingleEntry_ReturnsSuccess()
    {
        var response = Convert.FromHexString(
            "07" +               // AID length
            "A0000000031010" +   // AID
            "07" +               // Lifecycle state (Selectable)
            "01" +               // Privileges length
            "80"                 // Privileges
        );

        var result = GetStatusResponse.Parse(response);

        result.IsSuccess.Should().BeTrue();
        result.Value.Applications.Should().HaveCount(1);

        var app = result.Value.Applications[0];
        app.Aid.Should().BeEquivalentTo(Convert.FromHexString("A0000000031010"));
        app.State.Should().Be(ApplicationStatusEntry.LifecycleState.Selectable);
        app.Privileges.Should().BeEquivalentTo(new byte[] { 0x80 });
    }

    [Test]
    public void GetStatusResponse_Parse_WithMultipleEntries_ReturnsSuccess()
    {
        var response = Convert.FromHexString(
            "07" + "A0000000031010" + "07" + "01" + "80" +  // First app
            "08" + "A000000003101001" + "0F" + "02" + "C040" // Second app
        );

        var result = GetStatusResponse.Parse(response);

        result.IsSuccess.Should().BeTrue();
        result.Value.Applications.Should().HaveCount(2);

        var app1 = result.Value.Applications[0];
        app1.Aid.Should().BeEquivalentTo(Convert.FromHexString("A0000000031010"));
        app1.State.Should().Be(ApplicationStatusEntry.LifecycleState.Selectable);

        var app2 = result.Value.Applications[1];
        app2.Aid.Should().BeEquivalentTo(Convert.FromHexString("A000000003101001"));
        app2.State.Should().Be(ApplicationStatusEntry.LifecycleState.Personalized);
        app2.Privileges.Should().BeEquivalentTo(Convert.FromHexString("C040"));
    }

    [Test]
    [TestCase(0x03, ApplicationStatusEntry.LifecycleState.Installed)]
    [TestCase(0x07, ApplicationStatusEntry.LifecycleState.Selectable)]
    [TestCase(0x0F, ApplicationStatusEntry.LifecycleState.Personalized)]
    [TestCase(0x83, ApplicationStatusEntry.LifecycleState.Blocked)]
    [TestCase(0x87, ApplicationStatusEntry.LifecycleState.Locked)]
    public void GetStatusResponse_Parse_WithDifferentLifecycleStates_ParsesCorrectly(
        byte stateValue,
        ApplicationStatusEntry.LifecycleState expectedState)
    {
        var response = new List<byte>();
        response.Add(0x07); // AID length
        response.AddRange(Convert.FromHexString("A0000000031010")); // AID
        response.Add(stateValue); // Lifecycle state
        response.Add(0x00); // No privileges

        var result = GetStatusResponse.Parse(response.ToArray());

        result.IsSuccess.Should().BeTrue();
        result.Value.Applications[0].State.Should().Be(expectedState);
    }

    [Test]
    public void GetStatusResponse_Parse_WithInvalidLifecycleState_ReturnsFailure()
    {
        var response = Convert.FromHexString(
            "07" +               // AID length
            "A0000000031010" +   // AID
            "FF" +               // Invalid lifecycle state
            "01" +               // Privileges length
            "80"                 // Privileges
        );

        var result = GetStatusResponse.Parse(response);

        result.IsFailure.Should().BeTrue();
        result.Error.Message.Should().Contain("Invalid lifecycle state: 0xFF");
    }

    [Test]
    public void GetStatusResponse_Parse_WithEmptyResponse_ReturnsEmptyList()
    {
        var response = new byte[0];

        var result = GetStatusResponse.Parse(response);

        result.IsSuccess.Should().BeTrue();
        result.Value.Applications.Should().HaveCount(0);
    }

    [Test]
    public void GetStatusResponse_Parse_WithNullResponse_ReturnsFailure()
    {
        var result = GetStatusResponse.Parse(null);

        result.IsFailure.Should().BeTrue();
        result.Error.Message.Should().Contain("Response data cannot be null");
    }

    [Test]
    public void GetStatusResponse_Parse_WithTruncatedData_StopsGracefully()
    {
        var response = Convert.FromHexString(
            "07" +               // AID length
            "A0000000031010" +   // AID
            "07"                 // Lifecycle state - missing privileges
        );

        var result = GetStatusResponse.Parse(response);

        result.IsSuccess.Should().BeTrue();
        result.Value.Applications.Should().HaveCount(0);
    }

    [Test]
    public void GetStatusResponse_Parse_WithZeroLengthAid_StopsGracefully()
    {
        var response = new byte[] { 0x00 }; // Zero AID length

        var result = GetStatusResponse.Parse(response);

        result.IsSuccess.Should().BeTrue();
        result.Value.Applications.Should().HaveCount(0);
    }

    [Test]
    public void GetStatusResponse_Parse_WithNoPrivileges_ParsesCorrectly()
    {
        var response = Convert.FromHexString(
            "07" +               // AID length
            "A0000000031010" +   // AID
            "07" +               // Lifecycle state
            "00"                 // No privileges
        );

        var result = GetStatusResponse.Parse(response);

        result.IsSuccess.Should().BeTrue();
        result.Value.Applications.Should().HaveCount(1);
        result.Value.Applications[0].Privileges.Should().BeEmpty();
    }

    [Test]
    public void ApplicationStatusEntry_Constructor_CreatesImmutableCopies()
    {
        var originalAid = Convert.FromHexString("A0000000031010");
        var originalPrivileges = new byte[] { 0x80, 0x40 };

        var entry = new ApplicationStatusEntry(
            originalAid,
            ApplicationStatusEntry.LifecycleState.Selectable,
            originalPrivileges
        );

        originalAid[0] = 0xFF;
        originalPrivileges[0] = 0xFF;

        entry.Aid[0].Should().Be(0xA0);
        entry.Privileges[0].Should().Be(0x80);
    }

    [Test]
    public void ToString_ReturnsDescriptiveString()
    {
        var result = GetStatusCommand.Create(GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains);
        var command = result.Value;

        var str = command.ToString();

        str.Should().Be("GET STATUS");
    }

    [Test]
    public void Constants_HaveCorrectValues()
    {
        GetStatusCommand.Cla.Should().Be(0x80);
        GetStatusCommand.Ins.Should().Be(0xF2);
    }

    [Test]
    public void GetStatusResponse_Applications_ReturnsReadOnlyList()
    {
        var apps = new List<ApplicationStatusEntry>
        {
            new ApplicationStatusEntry(
                Convert.FromHexString("A0000000031010"),
                ApplicationStatusEntry.LifecycleState.Selectable,
                new byte[] { 0x80 }
            )
        };

        var response = new GetStatusResponse(apps);

        response.Applications.Should().NotBeSameAs(apps);
        response.Applications.Should().HaveCount(1);
    }

}