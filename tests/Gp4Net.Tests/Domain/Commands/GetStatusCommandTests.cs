using System;
using System.Collections.Generic;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
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
    public void Create_WithValidStatusSubset_ReturnsSuccessResult(
        GetStatusCommand.StatusSubset subset
    )
    {
        Result<GetStatusCommand, SmartCardError> result = GetStatusCommand.Create(subset);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Subset.Should().Be(subset);
        _ = result.Value.Format.Should().Be(GetStatusCommand.ResponseFormat.None);
        _ = result.Value.SearchCriteria.Should().BeEmpty();
    }

    [Test]
    [TestCase(GetStatusCommand.ResponseFormat.None)]
    [TestCase(GetStatusCommand.ResponseFormat.Tlv)]
    public void Create_WithValidResponseFormat_ReturnsSuccessResult(
        GetStatusCommand.ResponseFormat format
    )
    {
        Result<GetStatusCommand, SmartCardError> result = GetStatusCommand.Create(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
            format
        );

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Format.Should().Be(format);
    }

    [Test]
    public void Create_WithValidSearchCriteria_ReturnsSuccessResult()
    {
        byte[] aid = Convert.FromHexString("A0000000031010");

        Result<GetStatusCommand, SmartCardError> result = GetStatusCommand.Create(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
            GetStatusCommand.ResponseFormat.None,
            aid
        );

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.SearchCriteria.Should().BeEquivalentTo(aid);
    }

    [Test]
    [TestCase(4)] // Too short
    [TestCase(17)] // Too long
    public void Create_WithInvalidSearchCriteriaLength_ReturnsFailureResult(int length)
    {
        byte[] aid = new byte[length];

        Result<GetStatusCommand, SmartCardError> result = GetStatusCommand.Create(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
            GetStatusCommand.ResponseFormat.None,
            aid
        );

        _ = result.IsFailure.Should().BeTrue();
        _ = result
            .Error.Message.Should()
            .Contain("Search criteria AID must be between 5 and 16 bytes");
    }

    [Test]
    [TestCase(5)] // Minimum valid length
    [TestCase(10)] // Mid-range
    [TestCase(16)] // Maximum valid length
    public void Create_WithValidSearchCriteriaLengths_ReturnsSuccessResult(int length)
    {
        byte[] aid = new byte[length];

        Result<GetStatusCommand, SmartCardError> result = GetStatusCommand.Create(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
            GetStatusCommand.ResponseFormat.None,
            aid
        );

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.SearchCriteria!.Length.Should().Be(length);
    }

    [Test]
    public void Create_WithInvalidStatusSubset_ReturnsFailureResult()
    {
        var invalidSubset = (GetStatusCommand.StatusSubset)0xFF;

        Result<GetStatusCommand, SmartCardError> result = GetStatusCommand.Create(invalidSubset);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("Invalid status subset");
    }

    [Test]
    public void Create_WithInvalidResponseFormat_ReturnsFailureResult()
    {
        var invalidFormat = (GetStatusCommand.ResponseFormat)0xFF;

        Result<GetStatusCommand, SmartCardError> result = GetStatusCommand.Create(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
            invalidFormat
        );

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("Invalid response format");
    }

    [Test]
    public void SearchCriteria_IsImmutable()
    {
        byte[] originalAid = Convert.FromHexString("A0000000031010");
        Result<GetStatusCommand, SmartCardError> result = GetStatusCommand.Create(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
            GetStatusCommand.ResponseFormat.None,
            originalAid
        );
        var command = result.Value;

        originalAid[0] = 0xFF;

        _ = command.SearchCriteria![0].Should().Be(0xA0);
    }

    [Test]
    public void ToApdu_WithoutSearchCriteria_ReturnsCase2Apdu()
    {
        Result<GetStatusCommand, SmartCardError> result = GetStatusCommand.Create(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains
        );

        _ = result.IsSuccess.Should().BeTrue();
        Assert.That(result.IsSuccess, Is.True);
        var command = result.Value;

        Result<byte[], SmartCardError> apduResult = ApduBuilder.BuildApdu(
            Maybe<IApduCommand>.From(command)
        );
        _ = apduResult.IsSuccess.Should().BeTrue();
        Assert.That(apduResult.IsSuccess, Is.True);
        byte[] apdu = apduResult.Value;

        _ = apdu.Length.Should().Be(5); // CLA INS P1 P2 Le
        _ = apdu[0].Should().Be(0x80); // CLA
        _ = apdu[1].Should().Be(0xF2); // INS
        _ = apdu[2].Should().Be(0x40); // P1 - Applications subset
        _ = apdu[3].Should().Be(0x00); // P2 - No format
        _ = apdu[4].Should().Be(0x00); // Le
    }

    [Test]
    public void ToApdu_WithSearchCriteria_ReturnsCase4Apdu()
    {
        byte[] aid = Convert.FromHexString("A0000000031010");
        Result<GetStatusCommand, SmartCardError> result = GetStatusCommand.Create(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
            GetStatusCommand.ResponseFormat.None,
            aid
        );

        _ = result.IsSuccess.Should().BeTrue();
        Assert.That(result.IsSuccess, Is.True);
        var command = result.Value;

        Result<byte[], SmartCardError> apduResult = ApduBuilder.BuildApdu(
            Maybe<IApduCommand>.From(command)
        );
        _ = apduResult.IsSuccess.Should().BeTrue();
        Assert.That(apduResult.IsSuccess, Is.True);
        byte[] apdu = apduResult.Value;

        _ = apdu.Length.Should().Be(5 + aid.Length + 1); // CLA INS P1 P2 Lc Data Le
        _ = apdu[0].Should().Be(0x80); // CLA
        _ = apdu[1].Should().Be(0xF2); // INS
        _ = apdu[2].Should().Be(0x40); // P1
        _ = apdu[3].Should().Be(0x00); // P2
        _ = apdu[4].Should().Be((byte)aid.Length); // Lc
        _ = apdu[5..(5 + aid.Length)].Should().BeEquivalentTo(aid); // Data
        _ = apdu[5 + aid.Length].Should().Be(0x00); // Le
    }

    [Test]
    [TestCase(GetStatusCommand.StatusSubset.IssuerSecurityDomain, 0x80)]
    [TestCase(GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains, 0x40)]
    [TestCase(GetStatusCommand.StatusSubset.ExecutableLoadFiles, 0x20)]
    [TestCase(GetStatusCommand.StatusSubset.ExecutableLoadFilesAndModules, 0x10)]
    public void ToApdu_WithDifferentSubsets_SetsP1Correctly(
        GetStatusCommand.StatusSubset subset,
        byte expectedP1
    )
    {
        Result<GetStatusCommand, SmartCardError> result = GetStatusCommand.Create(subset);

        _ = result.IsSuccess.Should().BeTrue();
        Assert.That(result.IsSuccess, Is.True);
        var command = result.Value;

        Result<byte[], SmartCardError> apduResult = ApduBuilder.BuildApdu(
            Maybe<IApduCommand>.From(command)
        );
        _ = apduResult.IsSuccess.Should().BeTrue();
        Assert.That(apduResult.IsSuccess, Is.True);
        byte[] apdu = apduResult.Value;

        _ = apdu[2].Should().Be(expectedP1);
    }

    [Test]
    [TestCase(GetStatusCommand.ResponseFormat.None, 0x00)]
    [TestCase(GetStatusCommand.ResponseFormat.Tlv, 0x02)]
    public void ToApdu_WithDifferentFormats_SetsP2Correctly(
        GetStatusCommand.ResponseFormat format,
        byte expectedP2
    )
    {
        Result<GetStatusCommand, SmartCardError> result = GetStatusCommand.Create(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
            format
        );

        _ = result.IsSuccess.Should().BeTrue();
        Assert.That(result.IsSuccess, Is.True);
        var command = result.Value;

        Result<byte[], SmartCardError> apduResult = ApduBuilder.BuildApdu(
            Maybe<IApduCommand>.From(command)
        );
        _ = apduResult.IsSuccess.Should().BeTrue();
        Assert.That(apduResult.IsSuccess, Is.True);
        byte[] apdu = apduResult.Value;

        _ = apdu[3].Should().Be(expectedP2);
    }

    [Test]
    public void ToApdu_AlwaysReturnsNewArray()
    {
        Result<GetStatusCommand, SmartCardError> result = GetStatusCommand.Create(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains
        );

        result.Match(
            command =>
            {
                Result<byte[], SmartCardError> apduResult1 = ApduBuilder.BuildApdu(
                    Maybe<IApduCommand>.From(command)
                );
                Result<byte[], SmartCardError> apduResult2 = ApduBuilder.BuildApdu(
                    Maybe<IApduCommand>.From(command)
                );

                apduResult1.Match(
                    apdu1 =>
                        apduResult2.Match(
                            apdu2 =>
                            {
                                _ = apdu1.Should().NotBeSameAs(apdu2);
                                _ = apdu2.Should().BeEquivalentTo(apdu1);
                            },
                            error2 =>
                                _ = apduResult2
                                    .IsSuccess.Should()
                                    .BeTrue($"Second APDU build failed: {error2}")
                        ),
                    error1 =>
                        _ = apduResult1
                            .IsSuccess.Should()
                            .BeTrue($"First APDU build failed: {error1}")
                );
            },
            error => _ = result.IsSuccess.Should().BeTrue($"Command creation failed: {error}")
        );
    }

    [Test]
    public void IApduCommand_Properties_ReturnCorrectValues()
    {
        Result<GetStatusCommand, SmartCardError> result = GetStatusCommand.Create(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
            GetStatusCommand.ResponseFormat.Tlv
        );
        var command = result.Value;
        IApduCommand? iApduCommand = command;

        _ = iApduCommand.Cla.Should().Be(0x80);
        _ = iApduCommand.Ins.Should().Be(0xF2);
        _ = command.P1.Should().Be(0x40);
        _ = command.P2.Should().Be(0x02);
        _ = command.Data.Should().BeEmpty();
        _ = command.ExpectedResponseLength.Should().Be(256);
        _ = command.IsExtendedLength.Should().BeFalse();
    }

    [Test]
    public void IApduCommand_WithSearchCriteria_ReturnsCorrectData()
    {
        byte[] aid = Convert.FromHexString("A0000000031010");
        Result<GetStatusCommand, SmartCardError> result = GetStatusCommand.Create(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
            GetStatusCommand.ResponseFormat.None,
            aid
        );
        var command = result.Value;

        _ = command.Data.Should().BeEquivalentTo(aid);
    }

    [Test]
    public void GetStatusResponse_Parse_WithValidSingleEntry_ReturnsSuccess()
    {
        // TLV: E3 (template) containing 4F (AID), 9F70 (state), C5 (privileges 3 bytes)
        byte[] aid = Convert.FromHexString("A0000000031010");
        List<byte> tlv = [];
        List<byte> inner = [0x4F, (byte)aid.Length];
        inner.AddRange(aid);
        inner.Add(0x9F);
        inner.Add(0x70);
        inner.Add(0x01);
        inner.Add(0x07);
        inner.Add(0xC5);
        inner.Add(0x03);
        inner.AddRange([0x80, 0x00, 0x00]);
        tlv.Add(0xE3);
        tlv.Add((byte)inner.Count);
        tlv.AddRange(inner);
        byte[] response = [.. tlv];

        Result<GetStatusResponse, SmartCardError> result = GetStatusResponse.Parse(response);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Applications.Should().HaveCount(1);

        var app = result.Value.Applications[0];
        _ = app.Aid.Should().BeEquivalentTo(Convert.FromHexString("A0000000031010"));
        _ = app.State.Should().Be(ApplicationStatusEntry.LifecycleState.Selectable);
        _ = app.Privileges.Should().BeEquivalentTo(new byte[] { 0x80, 0x00, 0x00 });
    }

    [Test]
    public void GetStatusResponse_Parse_WithMultipleEntries_ReturnsSuccess()
    {
        byte[] aid1 = Convert.FromHexString("A0000000031010");
        byte[] aid2 = Convert.FromHexString("A000000003101001");
        byte[] e31 = BuildAppEntry(aid1, 0x07, [0x80, 0x00, 0x00]);
        byte[] e32 = BuildAppEntry(aid2, 0x0F, [0xC0, 0x40, 0x00]);
        byte[] response = [.. e31, .. e32];

        Result<GetStatusResponse, SmartCardError> result = GetStatusResponse.Parse(response);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Applications.Should().HaveCount(2);

        var app1 = result.Value.Applications[0];
        _ = app1.Aid.Should().BeEquivalentTo(Convert.FromHexString("A0000000031010"));
        _ = app1.State.Should().Be(ApplicationStatusEntry.LifecycleState.Selectable);

        var app2 = result.Value.Applications[1];
        _ = app2.Aid.Should().BeEquivalentTo(Convert.FromHexString("A000000003101001"));
        _ = app2.State.Should().Be(ApplicationStatusEntry.LifecycleState.Personalized);
        _ = app2.Privileges.Should().BeEquivalentTo(new byte[] { 0xC0, 0x40, 0x00 });
    }

    [Test]
    [TestCase(0x03, ApplicationStatusEntry.LifecycleState.Installed)]
    [TestCase(0x07, ApplicationStatusEntry.LifecycleState.Selectable)]
    [TestCase(0x0F, ApplicationStatusEntry.LifecycleState.Personalized)]
    [TestCase(0x83, ApplicationStatusEntry.LifecycleState.Blocked)]
    [TestCase(0x87, ApplicationStatusEntry.LifecycleState.Locked)]
    public void GetStatusResponse_Parse_WithDifferentLifecycleStates_ParsesCorrectly(
        byte stateValue,
        ApplicationStatusEntry.LifecycleState expectedState
    )
    {
        byte[] aid = Convert.FromHexString("A0000000031010");
        byte[] e3 = BuildAppEntry(aid, stateValue, [0x00, 0x00, 0x00]);
        Result<GetStatusResponse, SmartCardError> result = GetStatusResponse.Parse(e3);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Applications[0].State.Should().Be(expectedState);
    }

    [Test]
    public void GetStatusResponse_Parse_WithInvalidLifecycleState_ReturnsFailure()
    {
        byte[] aid = Convert.FromHexString("A0000000031010");
        byte[] e3 = BuildAppEntry(aid, 0xFF, [0x80, 0x00, 0x00]);

        Result<GetStatusResponse, SmartCardError> result = GetStatusResponse.Parse(e3);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("Invalid lifecycle state: 0xFF");
    }

    [Test]
    public void GetStatusResponse_Parse_WithEmptyResponse_ReturnsEmptyList()
    {
        byte[] response = [];

        Result<GetStatusResponse, SmartCardError> result = GetStatusResponse.Parse(response);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Applications.Should().HaveCount(0);
    }

    [Test]
    public void GetStatusResponse_Parse_WithNullResponse_ReturnsFailure()
    {
        Result<GetStatusResponse, SmartCardError> result = GetStatusResponse.Parse(null);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("Response data cannot be null");
    }

    [Test]
    public void GetStatusResponse_Parse_WithTruncatedData_StopsGracefully()
    {
        byte[] response = Convert.FromHexString(
            "07"
                + // AID length
                "A0000000031010"
                + // AID
                "07" // Lifecycle state - missing privileges
        );

        Result<GetStatusResponse, SmartCardError> result = GetStatusResponse.Parse(response);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Applications.Should().HaveCount(0);
    }

    [Test]
    public void GetStatusResponse_Parse_WithZeroLengthAid_StopsGracefully()
    {
        byte[] response = [0x00]; // Zero AID length

        Result<GetStatusResponse, SmartCardError> result = GetStatusResponse.Parse(response);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Applications.Should().HaveCount(0);
    }

    [Test]
    public void GetStatusResponse_Parse_WithNoPrivileges_ParsesCorrectly()
    {
        // Omit C5 to represent no privileges per spec allowance
        byte[] aid = Convert.FromHexString("A0000000031010");
        List<byte> inner = [0x4F, (byte)aid.Length];
        inner.AddRange(aid);
        inner.Add(0x9F);
        inner.Add(0x70);
        inner.Add(0x01);
        inner.Add(0x07);
        List<byte> tlv = [0xE3, (byte)inner.Count];
        tlv.AddRange(inner);
        byte[] response = [.. tlv];

        Result<GetStatusResponse, SmartCardError> result = GetStatusResponse.Parse(response);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Applications.Should().HaveCount(1);
        _ = result.Value.Applications[0].Privileges.Should().BeEmpty();
    }

    private static byte[] BuildAppEntry(byte[] aid, byte lifecycleState, byte[] privileges3)
    {
        List<byte> inner = [0x4F, (byte)aid.Length];
        inner.AddRange(aid);
        inner.Add(0x9F);
        inner.Add(0x70);
        inner.Add(0x01);
        inner.Add(lifecycleState);
        if (privileges3 != null)
        {
            inner.Add(0xC5);
            inner.Add(0x03);
            inner.AddRange(privileges3);
        }
        List<byte> e3 = [0xE3, (byte)inner.Count];
        e3.AddRange(inner);
        return [.. e3];
    }

    [Test]
    public void ApplicationStatusEntry_Constructor_CreatesImmutableCopies()
    {
        byte[] originalAid = Convert.FromHexString("A0000000031010");
        byte[] originalPrivileges = [0x80, 0x40];

        var entry = new ApplicationStatusEntry(
            originalAid,
            ApplicationStatusEntry.LifecycleState.Selectable,
            originalPrivileges
        );

        originalAid[0] = 0xFF;
        originalPrivileges[0] = 0xFF;

        _ = entry.Aid[0].Should().Be(0xA0);
        _ = entry.Privileges[0].Should().Be(0x80);
    }

    [Test]
    public void ToString_ReturnsDescriptiveString()
    {
        Result<GetStatusCommand, SmartCardError> result = GetStatusCommand.Create(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains
        );
        var command = result.Value;

        string? str = command.ToString();

        _ = str.Should().Be("GET STATUS");
    }

    [Test]
    public void Constants_HaveCorrectValues()
    {
        var command = GetStatusCommand
            .Create(GetStatusCommand.StatusSubset.IssuerSecurityDomain)
            .Value;
        _ = command.Cla.Should().Be(0x80);
        _ = command.Ins.Should().Be(0xF2);
    }

    [Test]
    public void GetStatusResponse_Applications_ReturnsReadOnlyList()
    {
        List<ApplicationStatusEntry> apps =
        [
            new ApplicationStatusEntry(
                Convert.FromHexString("A0000000031010"),
                ApplicationStatusEntry.LifecycleState.Selectable,
                [0x80]
            ),
        ];

        var response = new GetStatusResponse(apps);

        _ = response.Applications.Should().NotBeSameAs(apps);
        _ = response.Applications.Should().HaveCount(1);
    }
}
