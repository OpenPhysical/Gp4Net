using System;
using System.Reflection;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Functional;
using static Gp4Net.Constants.Constants;
using Gp4Net.Cryptography;
using static Gp4Net.Cryptography.CryptoService;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Constants;
using Gp4Net.Transport;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
//using CSharpFunctionalExtensions.AwesomeAssertions;
//using static CSharpFunctionalExtensions.Result;
using ApduResponse = Gp4Net.CardEmulator.Core.ApduResponse;

namespace Gp4Net.CardEmulator.Tests.Functional;

/// <summary>
/// Demonstrates the testability of the functional virtual card architecture.
/// These tests show how pure functions can be tested in isolation with predictable results.
/// </summary>
[TestFixture]
public class VirtualCardTests
{
    [Test]
    public void P71Card_ShouldHaveCorrectAtr()
    {
        // Arrange
        VirtualCard card = VirtualCardTestBuilder.CreateWithSecureRng(CardConfiguration.P71());

        // Act
        byte[] atr = card.GetAtr();

        // Assert
        _ = atr.Should().BeEquivalentTo(Convert.FromHexString("3BD518FF8191FE1FC38073C821100A"));
    }

    [Test]
    public void ProcessSelect_WithValidCommand_ShouldSelectCard()
    {
        // Arrange
        VirtualCard card = VirtualCardTestBuilder.CreateWithSecureRng(CardConfiguration.P71());
        byte[] selectCommand = [0x00, 0xA4, 0x04, 0x00, 0x00]; // SELECT with no AID

        // Act
        ApduResponse response = card.ProcessCommand(selectCommand);

        // Assert
        _ = response.StatusWord.Should().Be(StatusWords.Success.Normal);
        _ = card.IsSelected.Should().BeTrue();
        _ = response.Data.Length.Should().BeGreaterThan(0); // Should return FCI
    }

    [Test]
    public void ProcessSelect_WithUnsupportedInstruction_ShouldReturnError()
    {
        // Arrange
        VirtualCard card = VirtualCardTestBuilder.CreateWithSecureRng(CardConfiguration.Minimal()); // Only supports SELECT and GET DATA
        byte[] unsupportedCommand =
        [
            0x80,
            0x50,
            0x00,
            0x00,
            0x08,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
        ];

        // Act
        ApduResponse response = card.ProcessCommand(unsupportedCommand);

        // Assert
        _ = response.StatusWord.Should().Be(StatusWords.InstructionErrors.InstructionNotSupported);
    }

    [Test]
    public void ProcessIdentify_OnP71Card_ShouldReturnP71Data()
    {
        // Arrange
        VirtualCard card = VirtualCardTestBuilder.CreateWithSecureRng(CardConfiguration.P71());
        byte[] identifyCommand = [0x80, 0xCA, 0x00, 0xFE, 0x02, 0xDF, 0x28, 0x00];

        // Act
        ApduResponse response = card.ProcessCommand(identifyCommand);

        // Assert
        _ = response.StatusWord.Should().Be(StatusWords.Success.Normal);
        _ = response.Data.Should().NotBeEmpty();
        // Should contain DF28 tag and P71-specific identification data
        _ = response.Data[0].Should().Be(0xDF);
        _ = response.Data[1].Should().Be(0x28);
    }

    [Test]
    public void ProcessInitializeUpdate_WithValidCommand_ShouldReturnCryptogram()
    {
        // Arrange
        VirtualCard card = VirtualCardTestBuilder.CreateWithSecureRng(CardConfiguration.P71());
        byte[] selectCommand = [0x00, 0xA4, 0x04, 0x00, 0x00];
        byte[] initUpdateCommand =
        [
            0x80,
            0x50,
            0x00,
            0x00,
            0x08,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08, // Host challenge
        ];

        // Act
        _ = card.ProcessCommand(selectCommand); // Select first
        ApduResponse response = card.ProcessCommand(initUpdateCommand);

        // Assert
        _ = response.StatusWord.Should().Be(StatusWords.Success.Normal);
        _ = response.Data.Length.Should().BeGreaterThanOrEqualTo(28); // Minimum INITIALIZE UPDATE response
        // Response should contain key version, SCP info, card challenge, and cryptogram
    }

    [Test]
    public void ProcessCommand_WithFailingCrypto_ShouldHandleErrors()
    {
        // Arrange
        VirtualCard card = VirtualCardTestBuilder.CreateWithLimitedEntropy(CardConfiguration.P71(), 8).GetValueOrDefault(VirtualCardTestBuilder.CreateWithSecureRng(CardConfiguration.P71()));
        byte[] selectCommand = [0x00, 0xA4, 0x04, 0x00, 0x00];
        byte[] initUpdateCommand =
        [
            0x80,
            0x50,
            0x00,
            0x00,
            0x08,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
        ];

        // Act
        ApduResponse selectResponse = card.ProcessCommand(selectCommand); // This should work (no crypto needed)
        TestContext.Out.WriteLine(
            $"SELECT response: {Convert.ToHexString(selectResponse.Data)} {selectResponse.StatusWord:X4}"
        );

        ApduResponse response = card.ProcessCommand(initUpdateCommand); // This should fail
        TestContext.Out.WriteLine(
            $"INITIALIZE UPDATE response: {Convert.ToHexString(response.Data)} {response.StatusWord:X4}"
        );
        TestContext.Out.WriteLine($"Expected: NOT 0x9000, Actual: 0x{response.StatusWord:X4}");

        // Assert
        _ = response.StatusWord.Should().NotBe(StatusWords.Success.Normal);
    }

    [Test]
    public void CardState_ShouldBeImmutable()
    {
        // Arrange
        VirtualCard card = VirtualCardTestBuilder.CreateWithSecureRng(CardConfiguration.P71());
        CardState initialState = card.CurrentState;
        byte[] selectCommand = [0x00, 0xA4, 0x04, 0x00, 0x00];

        // Act
        _ = card.ProcessCommand(selectCommand);
        CardState newState = card.CurrentState;

        // Assert
        // Per GP Card Spec v2.3.1 Section 6.4.1: ISD is implicitly selected initially
        _ = initialState
            .IsSelected.Should()
            .BeTrue("ISD is implicitly selected by default per GP Card Spec v2.3.1");
        _ = newState.IsSelected.Should().BeTrue();

        // Test immutability: original state object should be unchanged (reference immutability)
        // Even if values are the same, the card should have created a new state instance
        _ = ReferenceEquals(initialState, newState)
            .Should()
            .BeFalse("Card should create new state instances to ensure immutability");

        // Values can be equal, but objects must be different instances
        _ = initialState
            .IsSelected.Should()
            .Be(newState.IsSelected, "State values should be preserved correctly");
    }

    [Test]
    public void ProcessCommand_DeleteApplication_RemovesFromCardState()
    {
        // Arrange - Create card with established secure channel for DELETE command testing
        VirtualCard card = CreateCardWithSecureChannel();

        // Create DELETE command for a test application
        byte[] testAid = Convert.FromHexString("A00000030800001000");
        var deleteResult = DeleteCommand
            .CreateForApplication(testAid, deleteRelated: true);

        // Act
        var response = deleteResult
            .Map(deleteCommand => deleteCommand.ToBytes())
            .Match(
                apduBytes => card.ProcessCommand(apduBytes),
                error => new ApduResponse([], 0x6F00) // Generic failure response
            );

        // Assert
        _ = response.StatusWord.Should().Be(StatusWords.Success.Normal);
        // Per GlobalPlatform Card Specification v2.3.1 Table 11-26,
        // DELETE Response should contain one byte (00) indicating success
        _ = response.Data.Should().BeEquivalentTo(new byte[] { 0x00 });
    }

    [Test]
    public void ProcessCommand_InstallForLoad_PreparesForCapFileLoading()
    {
        // Arrange - Create card with established secure channel for INSTALL command testing
        VirtualCard card = CreateCardWithSecureChannel();

        // GlobalPlatform Card Specification v2.3.1 Section 11.5.2.1 INSTALL [for load]
        byte[] packageAid = Convert.FromHexString("A000000308000010");
        var installForLoadResult = InstallCommandBuilder
            .CreateForLoad(packageAid: packageAid, securityDomainAid: card.Configuration.IsdAid);

        // Act
        var response = installForLoadResult
            .Bind(installCommand => installCommand.ToCommandApdu())
            .Match(
                commandApdu => card.ProcessCommand(commandApdu.BinaryCommand),
                error => new ApduResponse([], 0x6F00) // Generic failure response
            );

        // Assert
        _ = response.StatusWord.Should().Be(StatusWords.Success.Normal);
        // Per GlobalPlatform Card Specification v2.3.1 Table 11-13,
        // INSTALL Response should contain application specific data or one byte (00)
        _ = response.Data.Should().BeEquivalentTo(new byte[] { 0x00 });
    }

    /// <summary>
    /// Creates a virtual card with an established secure channel state for unit testing.
    /// Applies proper security level required for DELETE and INSTALL commands.
    /// </summary>
    private VirtualCard CreateCardWithSecureChannel()
    {
        VirtualCard card = VirtualCardTestBuilder.CreateWithSecureRng(CardConfiguration.P71());

        // First SELECT the ISD to put the card in selected state
        byte[] selectCommand = [0x00, 0xA4, 0x04, 0x00, 0x00];
        _ = card.ProcessCommand(selectCommand);

        // Create test session keys for secure channel (deterministic for unit testing)
        SessionKeys sessionKeys = new SessionKeys(
            sEnc: new byte[16],
            sMac: new byte[16],
            sRMac: new byte[16],
            dek: new byte[16]
        );

        // Create secure channel state with C-MAC security level (required for DELETE/INSTALL)
        var secureChannelResult = SecureChannelState.Create(
            sessionKeys: sessionKeys,
            securityLevel: SecurityLevel.CMac, // 0x01 - Command MAC required
            protocolVersion: ScpVersion.Scp02, // SCP02 for P71 cards
            initialMacChainingValue: new byte[8],
            implementationParameter: 0x00
        );

        // Create new card instance with secure channel established (functional approach)
        if (secureChannelResult.IsSuccess)
        {
            CardState currentState = card.CurrentState;
            CardState newState = currentState.WithSecureChannel(secureChannelResult.Value);
            
            return new VirtualCard(
                card.Configuration,
                CryptoService.Rng.CreateSecureContext(),
                newState,
                new LoggingService(Maybe<ILogger>.None)
            );
        }

        return card;
    }

    [Test]
    public void ProcessCommandFunctionally_ShouldProcessSelectCommand()
    {
        // Arrange
        CardConfiguration config = CardConfiguration.P71();
        IRngContext rng = CryptoService.Rng.CreateSecureContext();
        byte[] selectCommand = [0x00, 0xA4, 0x04, 0x00, 0x00];
        var initialState = CardState.Create();

        // Act
        var result = initialState.Bind(state =>
            VirtualCard
                .ProcessCommandFunctionally(
                    selectCommand,
                    state,
                    config,
                    rng,
                    LoggingService.None
                )
                .Map(x => x.Item1)
        ); // Extract just the response

        // Assert
        result.IsSuccess.Should().BeTrue();
    }

    [Test]
    public void Builder_ShouldCreateCustomConfigurations()
    {
        // Arrange & Act
        VirtualCard card = VirtualCardTestBuilder.CreateWithSecureRng(
            CardConfiguration.P71() with
            {
                DefaultScpVersion = 0x03,
                DefaultScpImplementation = ScpImplementation.Scp03I70
            }
        );

        // Assert
        _ = card.Configuration.CardType.Should().Contain("P71");
        _ = card.Configuration.DefaultScpVersion.Should().Be(0x03);
        _ = card.Configuration.DefaultScpImplementation.Should().Be(ScpImplementation.Scp03I70);
    }

    [Test]
    public void Reset_ShouldRestoreInitialState()
    {
        // Arrange
        VirtualCard card = VirtualCardTestBuilder.CreateWithSecureRng(CardConfiguration.P71());
        byte[] selectCommand = [0x00, 0xA4, 0x04, 0x00, 0x00];

        // Act
        _ = card.ProcessCommand(selectCommand); // Change state
        _ = card.IsSelected.Should().BeTrue();

        card.Reset(); // Reset state

        // Assert
        // Per GP Card Spec v2.3.1 Section 6.4.2.1.1: ISD remains implicitly selected after reset
        _ = card
            .IsSelected.Should()
            .BeTrue("ISD remains implicitly selected after reset per GP Card Spec v2.3.1");
        _ = card.IsSecureChannelEstablished.Should().BeFalse();
    }
}
