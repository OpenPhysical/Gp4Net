using AwesomeAssertions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Functional;
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
