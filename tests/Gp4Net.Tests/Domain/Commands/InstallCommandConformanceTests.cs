using System;
using AwesomeAssertions;
using Gp4Net.Domain.Commands;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands;

[TestFixture]
[Category("Unit")]
public class InstallCommandConformanceTests
{
    private static readonly byte[] ApplicationAid = Convert.FromHexString("A0000001510000");
    private static readonly byte[] SecurityDomainAid = Convert.FromHexString("A0000001510001");

    [Test]
    public void MakeSelectable_Should_Encode_Table_11_44()
    {
        // GP Card Specification v2.3.1, Tables 11-41 and 11-44.
        var command = InstallCommand
            .InstallForManagementCommand.CreateForMakeSelectable(ApplicationAid, [0x00])
            .Value;

        _ = command.P1.Should().Be(0x08);
        _ = command.P2.Should().Be(0x00);
        _ = command.Data.Should().Equal(Convert.FromHexString("000007A000000151000001000000"));
    }

    [Test]
    public void Extradition_Should_Encode_Table_11_45()
    {
        // GP Card Specification v2.3.1, Tables 11-41 and 11-45.
        var command = InstallCommand
            .InstallForManagementCommand.CreateForExtradition(SecurityDomainAid, ApplicationAid)
            .Value;

        _ = command.P1.Should().Be(0x10);
        _ = command
            .Data.Should()
            .Equal(Convert.FromHexString("07A00000015100010007A0000001510000000000"));
    }

    [Test]
    public void RegistryUpdate_Should_Encode_Table_11_46()
    {
        // GP Card Specification v2.3.1, Tables 11-41 and 11-46.
        var command = InstallCommand
            .InstallForManagementCommand.CreateForRegistryUpdate(
                applicationAid: ApplicationAid,
                privileges: new byte[] { 0x00 }
            )
            .Value;

        _ = command.P1.Should().Be(0x40);
        _ = command.Data.Should().Equal(Convert.FromHexString("000007A000000151000001000000"));
    }

    [Test]
    public void Personalization_Should_Encode_Table_11_47()
    {
        // GP Card Specification v2.3.1, Tables 11-41 and 11-47.
        var command = InstallCommand
            .InstallForManagementCommand.CreateForPersonalization(ApplicationAid)
            .Value;

        _ = command.P1.Should().Be(0x20);
        _ = command.Data.Should().Equal(Convert.FromHexString("000007A0000001510000000000"));
    }

    [Test]
    public void CombinedOperation_Should_Encode_P1_And_P2()
    {
        // GP Card Specification v2.3.1, Table 11-41 and section 11.5.2.2.
        var first = InstallCommand.InstallForLoadCommand.CreateCombined(ApplicationAid).Value;
        var last = InstallCommand
            .InstallForInstallCommand.CreateCombinedFinal(
                ApplicationAid,
                ApplicationAid,
                ApplicationAid,
                [0x00]
            )
            .Value;

        _ = first.P1.Should().Be(0x0E);
        _ = first.P2.Should().Be(0x01);
        _ = last.P1.Should().Be(0x0C);
        _ = last.P2.Should().Be(0x03);
    }

    [Test]
    public void MoreComponents_Should_Set_P1_B8()
    {
        // GP Card Specification v2.3.1, Table 11-41: b8 indicates more INSTALL commands.
        var command = InstallCommand
            .InstallForManagementCommand.CreateForPersonalization(
                ApplicationAid,
                moreCommands: true
            )
            .Value;

        _ = command.P1.Should().Be(0xA0);
    }
}
