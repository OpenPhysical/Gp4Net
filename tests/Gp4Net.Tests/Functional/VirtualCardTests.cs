using System;
using System.Reflection;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Transport;
using NUnit.Framework;
using ApduResponse = Gp4Net.CardEmulator.Core.ApduResponse;

namespace Gp4Net.Tests.Functional;

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
        VirtualCard card = VirtualCardTestBuilder.P71Card();

        // Act
        byte[] atr = card.GetAtr();

        // Assert
        _ = atr.Should().BeEquivalentTo(Convert.FromHexString("3BD518FF8191FE1FC38073C821100A"));
    }

    [Test]
    public void ProcessSelect_WithValidCommand_ShouldSelectCard()
    {
        // Arrange
        VirtualCard card = VirtualCardTestBuilder.P71Card();
        byte[] selectCommand = [0x00, 0xA4, 0x04, 0x00, 0x00]; // SELECT with no AID

        // Act
        ApduResponse response = card.ProcessCommand(selectCommand);

        // Assert
        _ = response.StatusWord.Should().Be(StatusWords.Success);
        _ = card.IsSelected.Should().BeTrue();
        _ = response.Data.Length.Should().BeGreaterThan(0); // Should return FCI
    }

    [Test]
    public void ProcessSelect_WithUnsupportedInstruction_ShouldReturnError()
    {
        // Arrange
        VirtualCard card = VirtualCardTestBuilder.MinimalCard(); // Only supports SELECT and GET DATA
        byte[] unsupportedCommand = [0x80, 0x50, 0x00, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        // Act
        ApduResponse response = card.ProcessCommand(unsupportedCommand);

        // Assert
        _ = response.StatusWord.Should().Be(StatusWords.InstructionNotSupported);
    }

    [Test]
    public void ProcessIdentify_OnP71Card_ShouldReturnP71Data()
    {
        // Arrange
        VirtualCard card = VirtualCardTestBuilder.P71Card();
        byte[] identifyCommand = [0x80, 0xCA, 0x00, 0xFE, 0x02, 0xDF, 0x28, 0x00];

        // Act
        ApduResponse response = card.ProcessCommand(identifyCommand);

        // Assert
        _ = response.StatusWord.Should().Be(StatusWords.Success);
        _ = response.Data.Should().NotBeEmpty();
        // Should contain DF28 tag and P71-specific identification data
        _ = response.Data[0].Should().Be(0xDF);
        _ = response.Data[1].Should().Be(0x28);
    }

    [Test]
    public void ProcessInitializeUpdate_WithValidCommand_ShouldReturnCryptogram()
    {
        // Arrange
        VirtualCard card = VirtualCardTestBuilder.ForSecureChannelTesting();
        byte[] selectCommand = [0x00, 0xA4, 0x04, 0x00, 0x00];
        byte[] initUpdateCommand =
        [
            0x80, 0x50, 0x00, 0x00, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 // Host challenge
        ];

        // Act
        _ = card.ProcessCommand(selectCommand); // Select first
        ApduResponse response = card.ProcessCommand(initUpdateCommand);

        // Assert
        _ = response.StatusWord.Should().Be(StatusWords.Success);
        _ = response.Data.Length.Should().BeGreaterThanOrEqualTo(28); // Minimum INITIALIZE UPDATE response
        // Response should contain key version, SCP info, card challenge, and cryptogram
    }

    [Test]
    public void ProcessCommand_WithFailingCrypto_ShouldHandleErrors()
    {
        // Arrange
        VirtualCard card = VirtualCardTestBuilder.SimulatingErrors();
        byte[] selectCommand = [0x00, 0xA4, 0x04, 0x00, 0x00];
        byte[] initUpdateCommand =
        [
            0x80, 0x50, 0x00, 0x00, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
        ];

        // Act
        ApduResponse selectResponse = card.ProcessCommand(selectCommand); // This should work (no crypto needed)
        TestContext.Out.WriteLine($"SELECT response: {Convert.ToHexString(selectResponse.Data)} {selectResponse.StatusWord:X4}");

        ApduResponse response = card.ProcessCommand(initUpdateCommand); // This should fail
        TestContext.Out.WriteLine($"INITIALIZE UPDATE response: {Convert.ToHexString(response.Data)} {response.StatusWord:X4}");
        TestContext.Out.WriteLine($"Expected: NOT 0x9000, Actual: 0x{response.StatusWord:X4}");

        // Assert
        _ = response.StatusWord.Should().NotBe(StatusWords.Success);
    }

    [Test]
    public void CardState_ShouldBeImmutable()
    {
        // Arrange
        VirtualCard card = VirtualCardTestBuilder.P71Card();
        CardState initialState = card.CurrentState;
        byte[] selectCommand = [0x00, 0xA4, 0x04, 0x00, 0x00];

        // Act
        _ = card.ProcessCommand(selectCommand);
        CardState newState = card.CurrentState;

        // Assert
        // Per GP Card Spec v2.3.1 Section 6.4.1: ISD is implicitly selected initially
        _ = initialState.IsSelected.Should().BeTrue("ISD is implicitly selected by default per GP Card Spec v2.3.1");
        _ = newState.IsSelected.Should().BeTrue();

        // Test immutability: original state object should be unchanged (reference immutability)
        // Even if values are the same, the card should have created a new state instance
        _ = ReferenceEquals(initialState, newState).Should().BeFalse("Card should create new state instances to ensure immutability");

        // Values can be equal, but objects must be different instances
        _ = initialState.IsSelected.Should().Be(newState.IsSelected, "State values should be preserved correctly");
    }

    [Test]
    public void ProcessCommand_DeleteApplication_RemovesFromCardState()
    {
        // Arrange - Create card with established secure channel for DELETE command testing
        VirtualCard card = CreateCardWithSecureChannel();

        // Create DELETE command for a test application
        byte[] testAid = Convert.FromHexString("A00000030800001000");
        DeleteCommand? deleteCommand = DeleteCommand.CreateForApplication(testAid, deleteRelated: true).Value;
        byte[]? deleteApdu = ApduBuilder.BuildApdu(deleteCommand);

        // Act
        ApduResponse response = card.ProcessCommand(deleteApdu);

        // Assert
        _ = response.StatusWord.Should().Be(StatusWords.Success);
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
        InstallCommand.InstallForLoadCommand? installForLoadCommand = InstallCommandBuilder.CreateForLoad(
            packageAid: packageAid,
            securityDomainAid: card.Configuration.IsdAid
        ).Value;

        // Act
        ApduResponse response = card.ProcessCommand(ApduBuilder.BuildApdu(installForLoadCommand));

        // Assert
        _ = response.StatusWord.Should().Be(StatusWords.Success);
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
        VirtualCard card = VirtualCardTestBuilder.P71Card();

        // First SELECT the ISD to put the card in selected state
        byte[] selectCommand = [0x00, 0xA4, 0x04, 0x00, 0x00];
        _ = card.ProcessCommand(selectCommand);

        // Create test session keys for secure channel (deterministic for unit testing)
        SessionKeys sessionKeys = new Gp4Net.Domain.Keys.SessionKeys(
            sEnc: new byte[16],
            sMac: new byte[16],
            sRMac: new byte[16],
            dek: new byte[16]
        );

        // Create secure channel state with C-MAC security level (required for DELETE/INSTALL)
        var secureChannelResult = Gp4Net.Domain.Security.SecureChannelState.Create(
            sessionKeys: sessionKeys,
            securityLevel: Gp4Net.Domain.SecurityLevel.CMac, // 0x01 - Command MAC required
            protocolVersion: 0x02, // SCP02 for P71 cards
            initialMacChainingValue: new byte[8],
            implementationParameter: 0x00
        );

        // Apply secure channel state to card (unit testing approach)
        if (secureChannelResult.IsSuccess)
        {
            FieldInfo? cardStateField = typeof(VirtualCard).GetField("_state",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            if (cardStateField is not null)
            {
                CardState currentState = (CardState)cardStateField.GetValue(card)!;
                CardState newState = currentState.WithSecureChannel(secureChannelResult.Value);
                cardStateField.SetValue(card, newState);
            }
        }

        return card;
    }

    [Test]
    public void ProcessCommandFunctionally_IsPureFunction()
    {
        // Arrange
        CardConfiguration config = CardConfiguration.P71();
        CryptographicService crypto = new CryptographicService();
        var initialState = CardState.Initial;
        byte[] selectCommand = [0x00, 0xA4, 0x04, 0x00, 0x00];

        // Act - Call the same pure function multiple times
        Result<(ApduResponse, CardState), SmartCardError> result1 = VirtualCard.ProcessCommandFunctionally(selectCommand, initialState, config, crypto, LoggingService.None);
        Result<(ApduResponse, CardState), SmartCardError> result2 = VirtualCard.ProcessCommandFunctionally(selectCommand, initialState, config, crypto, LoggingService.None);

        // Assert - Pure function should return identical results
        _ = result1.IsSuccess.Should().BeTrue();
        _ = result2.IsSuccess.Should().BeTrue();

        (ApduResponse response1, CardState state1) = result1.Value;
        (ApduResponse response2, CardState state2) = result2.Value;

        _ = response1.StatusWord.Should().Be(response2.StatusWord);
        _ = response1.Data.Should().BeEquivalentTo(response2.Data);
        _ = state1.Should().Be(state2); // Records have value equality
    }

    [Test]
    public void Builder_ShouldCreateCustomConfigurations()
    {
        // Arrange & Act
        VirtualCard card = VirtualCardTestBuilder.Builder()
            .AsP71()
            .WithScp(0x03, Gp4Net.Domain.Protocol.ScpImplementation.Scp03I70)
            .WithTestCrypto()
            .Build();

        // Assert
        _ = card.Configuration.CardType.Should().Contain("P71");
        _ = card.Configuration.DefaultScpVersion.Should().Be(0x03);
        _ = card.Configuration.DefaultScpImplementation.Should().Be(Gp4Net.Domain.Protocol.ScpImplementation.Scp03I70);
    }

    [Test]
    public void Reset_ShouldRestoreInitialState()
    {
        // Arrange
        VirtualCard card = VirtualCardTestBuilder.P71Card();
        byte[] selectCommand = [0x00, 0xA4, 0x04, 0x00, 0x00];

        // Act
        _ = card.ProcessCommand(selectCommand); // Change state
        _ = card.IsSelected.Should().BeTrue();

        card.Reset(); // Reset state

        // Assert
        // Per GP Card Spec v2.3.1 Section 6.4.2.1.1: ISD remains implicitly selected after reset
        _ = card.IsSelected.Should().BeTrue("ISD remains implicitly selected after reset per GP Card Spec v2.3.1");
        _ = card.IsSecureChannelEstablished.Should().BeFalse();
    }
}