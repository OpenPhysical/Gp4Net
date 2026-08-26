using System;
using System.Collections.Immutable;
using AwesomeAssertions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.Domain.Commands;
using Gp4Net.Tests.TestHelpers;
using NUnit.Framework;
using static Gp4Net.Constants.Constants.GlobalPlatform;

namespace Gp4Net.Tests.Integration;

[TestFixture]
[Category("Integration")]
[Category("SecurityDomain")]
[Category("VirtualCard")]
public class IssuerSecurityDomainSelectionTests
{
    private VirtualCard _virtualCard = CreateCard();

    [SetUp]
    public void SetUp()
    {
        _virtualCard = CreateCard();
    }

    [Test]
    public void InitializeUpdate_WithImplicitIsdSelection_ShouldSucceed()
    {
        var response = _virtualCard.ExecuteCommand(CreateInitializeUpdate());

        response.StatusWord.Should().Be(StatusWords.SUCCESS);
        response.Data.Should().HaveCountGreaterThanOrEqualTo(28);
    }

    [Test]
    public void InitializeUpdate_WithExplicitIsdSelection_ShouldSucceed()
    {
        _virtualCard
            .ExecuteCommand([0x00, 0xA4, 0x04, 0x00, 0x00])
            .StatusWord.Should()
            .Be(StatusWords.SUCCESS);

        _virtualCard
            .ExecuteCommand(CreateInitializeUpdate())
            .StatusWord.Should()
            .Be(StatusWords.SUCCESS);
    }

    [Test]
    public void InitializeUpdate_AfterCardReset_ShouldSucceedWithImplicitIsd()
    {
        _virtualCard.Reset();

        _virtualCard
            .ExecuteCommand(CreateInitializeUpdate())
            .StatusWord.Should()
            .Be(StatusWords.SUCCESS);
    }

    private static VirtualCard CreateCard() =>
        VirtualCardTestBuilder.CreateWithSecureRng(CardConfiguration.P71().Value);

    private static byte[] CreateInitializeUpdate() =>
        [0x80, 0x50, 0x00, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
}

[TestFixture]
[Category("Integration")]
[Category("SecurityDomain")]
[Category("VirtualCard")]
public sealed class SecurityDomainManagementTests
{
    [Test]
    public void CreateSsdAndExtradite_UpdatesOwnershipAtomically()
    {
        byte[] packageAid = Convert.FromHexString("A0000001515350");
        byte[] moduleAid = Convert.FromHexString("A000000151535041");
        byte[] ssdAid = Convert.FromHexString("A0000001515350D3");
        byte[] appAid = Convert.FromHexString("A000000308000010000100");
        CardState state = CardState.Create().Value
            .WithApplication(Convert.ToHexString(ssdAid), new InstalledApplication(
                ssdAid, moduleAid, 0x07, Privilege.SecurityDomain,
                ImmutableDictionary<string, byte[]>.Empty))
            .WithApplication(Convert.ToHexString(appAid), new InstalledApplication(
                appAid, moduleAid, 0x07, Privilege.None,
                ImmutableDictionary<string, byte[]>.Empty));

        var extradite = InstallCommand.InstallForManagementCommand.CreateForExtradition(
            ssdAid, appAid).Value;
        var result = VirtualCard.ProcessInstallForExtradition(extradite.Data, state);
        result.IsSuccess.Should().BeTrue();
        result.Value.Item1.StatusWord.Should().Be(StatusWords.SUCCESS);
        result.Value.Item2.Applications[Convert.ToHexString(appAid)].ApplicationData[
            "AssociatedSecurityDomainAid"].Should().Equal(ssdAid);
    }

    [Test]
    public void ExtraditeToUnknownDomain_DoesNotChangeApplication()
    {
        byte[] moduleAid = Convert.FromHexString("A000000151535041");
        byte[] appAid = Convert.FromHexString("A000000308000010000100");
        CardState state = CardState.Create().Value.WithApplication(
            Convert.ToHexString(appAid), new InstalledApplication(
                appAid, moduleAid, 0x07, Privilege.None,
                ImmutableDictionary<string, byte[]>.Empty));

        var extradite = InstallCommand.InstallForManagementCommand.CreateForExtradition(
            Convert.FromHexString("A0000001515350FF"), appAid).Value;
        var result = VirtualCard.ProcessInstallForExtradition(extradite.Data, state);

        result.IsFailure.Should().BeTrue();
        state.Applications[Convert.ToHexString(appAid)].ApplicationData
            .Should().NotContainKey("AssociatedSecurityDomainAid");
    }
}
