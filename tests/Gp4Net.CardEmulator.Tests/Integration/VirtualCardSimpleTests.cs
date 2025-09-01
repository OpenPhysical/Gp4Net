using System;
using System.Collections.Immutable;
using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Keys;
using NUnit.Framework;
using static Gp4Net.Constants.Constants;

namespace Gp4Net.CardEmulator.Tests.Integration;

/// <summary>
/// Simple integration tests to verify virtual card functionality and debug cryptogram issues.
/// </summary>
[TestFixture]
[Category("Integration")]
[Category("VirtualCard")]
public class VirtualCardSimpleTests
{
    private VirtualCard _virtualCard;

    private static readonly ImmutableArray<byte> CardEntropy = ImmutableArray.Create<byte>(
        [
            0x12,
            0x34,
            0x56,
            0x78,
            0x9A,
            0xBC,
            0xDE,
            0xF0,
            0x23,
            0x45,
            0x67,
            0x89,
            0xAB,
            0xCD,
            0xEF,
            0x01,
            0x34,
            0x56,
            0x78,
            0x9A,
            0xBC,
            0xDE,
            0xF0,
            0x12,
        ]
    );

    private static readonly ImmutableArray<byte> TestEntropy = ImmutableArray.Create<byte>(
        [
            0xFE,
            0xDC,
            0xBA,
            0x98,
            0x76,
            0x54,
            0x32,
            0x10,
            0xED,
            0xCB,
            0xA9,
            0x87,
            0x65,
            0x43,
            0x21,
            0x0F,
            0xDC,
            0xBA,
            0x98,
            0x76,
            0x54,
            0x32,
            0x10,
            0xFE,
        ]
    );

    private static VirtualCard CreateTestVirtualCard() =>
        VirtualCardTestBuilder
            .CreateWithEntropy(CardConfiguration.P71(), [.. CardEntropy])
            .GetValueOrDefault(VirtualCardTestBuilder.CreateWithSecureRng(CardConfiguration.P71()));

    // Removed CryptographicService - using UnifiedCryptoService.Cryptogram instead

    [SetUp]
    public void SetUp()
    {
        _virtualCard = CreateTestVirtualCard();
    }

    [Test]
    public void VirtualCard_ShouldHaveCorrectInitialState()
    {
        // Per GP Card Spec v2.3.1 Section 6.4.1: ISD is implicitly selected by default
        VirtualCard virtualCard = CreateTestVirtualCard();

        _ = virtualCard
            .IsSelected.Should()
            .BeTrue("ISD is implicitly selected by default per GP Card Spec v2.3.1");
        _ = virtualCard.IsSecureChannelEstablished.Should().BeFalse();
        _ = virtualCard.Configuration.CardType.Should().Be("NXP P71");
    }

    [Test]
    public void VirtualCard_SelectIsd_ShouldSucceed()
    {
        VirtualCard virtualCard = CreateTestVirtualCard();
        ImmutableArray<byte> selectCmd = ImmutableArray.Create<byte>(
            [0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00]
        );

        ApduResponse response = virtualCard.ProcessCommand([.. selectCmd]);

        _ = response.StatusWord.Should().Be(StatusWords.Success.Normal);
        _ = virtualCard.IsSelected.Should().BeTrue();

        TestContext.Out.WriteLine(
            $"✅ SELECT ISD succeeded: {Convert.ToHexString(response.Data)}9000"
        );
    }

    [Test]
    public void VirtualCard_InitializeUpdate_ShouldReturnValidResponse()
    {
        VirtualCard virtualCard = CreateTestVirtualCard();

        // First SELECT ISD
        ImmutableArray<byte> selectCmd = ImmutableArray.Create<byte>(
            [0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00]
        );
        _ = virtualCard.ProcessCommand([.. selectCmd]);

        // Then INITIALIZE UPDATE
        ImmutableArray<byte> hostChallenge = ImmutableArray.Create<byte>(
            [0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10]
        );
        ImmutableArray<byte> initCmd = ImmutableArray.Create<byte>(
            [0x80, 0x50, 0x00, 0x00, 0x08, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10]
        );

        ApduResponse response = virtualCard.ProcessCommand([.. initCmd]);

        _ = response.StatusWord.Should().Be(StatusWords.Success.Normal);
        _ = response
            .Data.Length.Should()
            .BeGreaterThanOrEqualTo(28, "INIT UPDATE response must be at least 28 bytes");

        byte keyVersion = response.Data[10];
        byte scpId = response.Data[11];
        byte[] cardChallenge = response.Data[12..20];
        byte[] cardCryptogram = response.Data[20..28];

        TestContext.Out.WriteLine($"🔍 Key Version: 0x{keyVersion:X2}");
        TestContext.Out.WriteLine($"🔍 SCP ID: 0x{scpId:X2}");
        TestContext.Out.WriteLine(
            $"🔍 Host Challenge: {Convert.ToHexString([.. hostChallenge])}"
        );
        TestContext.Out.WriteLine($"🔍 Card Challenge: {Convert.ToHexString(cardChallenge)}");
        TestContext.Out.WriteLine($"🔍 Card Cryptogram: {Convert.ToHexString(cardCryptogram)}");

        _ = keyVersion.Should().BeOneOf(0x01, 0xFF);
        _ = scpId.Should().Be(0x02, "P71 should use SCP02");
        _ = cardChallenge.Length.Should().Be(8);
        _ = cardCryptogram.Length.Should().Be(8);

        TestContext.Out.WriteLine("✅ INITIALIZE UPDATE returned valid response structure");
    }

    [Test]
    public void CryptographicService_ShouldCalculateMatchingCryptograms()
    {
        // First SELECT and INIT UPDATE to get real challenges
        byte[] selectCmd =
        [
            0x00,
            0xA4,
            0x04,
            0x00,
            0x08,
            0xA0,
            0x00,
            0x00,
            0x01,
            0x51,
            0x00,
            0x00,
            0x00,
        ];
        _ = _virtualCard.ProcessCommand(selectCmd);

        byte[] hostChallenge = [0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
        byte[] initCmd =
        [
            0x80,
            0x50,
            0x00,
            0x00,
            0x08,
            0xFE,
            0xDC,
            0xBA,
            0x98,
            0x76,
            0x54,
            0x32,
            0x10,
        ];
        ApduResponse response = _virtualCard.ProcessCommand(initCmd);

        byte keyVersion = response.Data[10];
        byte[] cardChallenge = response.Data[12..20];
        byte[] cardCryptogramFromCard = response.Data[20..28];

        // Get key set and calculate cryptogram using UnifiedCryptoService
        Maybe<IKeySet> keySetMaybe = _virtualCard.Configuration.StaticKeys.TryGetValue(
            keyVersion,
            out IKeySet value
        )
            ? Maybe<IKeySet>.From(value)
            : Maybe<IKeySet>.None;

        keySetMaybe.Match(
            keySet =>
            {
                string keysetVersion = keySet is Scp02KeySet ? "02" : "03";
                TestContext.Out.WriteLine(
                    $"🔍 Using {keySet.GetType().Name} version 0x{keysetVersion}"
                );

                Result<byte[], SmartCardError> expectedCryptogramResult =
                    CryptoService.Cryptogram.CalculateCardCryptogram(
                        hostChallenge.ToArray(),
                        cardChallenge,
                        keySet,
                        0x02,
                        0x00,
                        Maybe<byte[]>.From(cardChallenge[..2])
                    );

                expectedCryptogramResult.Match(
                    onSuccess: expectedCryptogram =>
                    {
                        TestContext.Out.WriteLine(
                            $"🔍 Expected Cryptogram: {Convert.ToHexString(expectedCryptogram[..8])}"
                        );
                        TestContext.Out.WriteLine(
                            $"🔍 Card Cryptogram:     {Convert.ToHexString(cardCryptogramFromCard)}"
                        );

                        expectedCryptogram[..8].Should().BeEquivalentTo(cardCryptogramFromCard);
                    },
                    onFailure: error =>
                    {
                        Assert.Fail($"Cryptogram calculation should succeed: {error}");
                    }
                );
            },
            () =>
            {
                Assert.Fail($"Key set not found for version 0x{keyVersion:X2}");
            }
        );
    }
}
