using System;
using System.Linq;
using System.Reflection;
using AwesomeAssertions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.Constants;
using Gp4Net.Domain.Commands;
using Gp4Net.Transport;
using NUnit.Framework;

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
        var card = VirtualCardTestBuilder.P71Card();
            
        // Act
        var atr = card.GetAtr();

        // Assert
        _ = atr.Should().BeEquivalentTo(Convert.FromHexString("3BD518FF8191FE1FC38073C821100A"));
    }

    [Test]
    public void ProcessSelect_WithValidCommand_ShouldSelectCard()
    {
        // Arrange
        var card = VirtualCardTestBuilder.P71Card();
        var selectCommand = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 }; // SELECT with no AID
            
        // Act
        var response = card.ProcessCommand(selectCommand);

        // Assert
        _ = response.StatusWord.Should().Be(StatusWords.Success);
        _ = card.IsSelected.Should().BeTrue();
        _ = response.Data.Length.Should().BeGreaterThan(0); // Should return FCI
    }

    [Test]
    public void ProcessSelect_WithUnsupportedInstruction_ShouldReturnError()
    {
        // Arrange
        var card = VirtualCardTestBuilder.MinimalCard(); // Only supports SELECT and GET DATA
        var unsupportedCommand = new byte[] { 0x80, 0x50, 0x00, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
            
        // Act
        var response = card.ProcessCommand(unsupportedCommand);

        // Assert
        _ = response.StatusWord.Should().Be(StatusWords.InstructionNotSupported);
    }

    [Test]
    public void ProcessIdentify_OnP71Card_ShouldReturnP71Data()
    {
        // Arrange
        var card = VirtualCardTestBuilder.P71Card();
        var identifyCommand = new byte[] { 0x80, 0xCA, 0x00, 0xFE, 0x02, 0xDF, 0x28, 0x00 };
            
        // Act
        var response = card.ProcessCommand(identifyCommand);

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
        var card = VirtualCardTestBuilder.ForSecureChannelTesting();
        var selectCommand = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 };
        var initUpdateCommand = new byte[] 
        { 
            0x80, 0x50, 0x00, 0x00, 0x08, 
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 // Host challenge
        };

        // Act
        _ = card.ProcessCommand(selectCommand); // Select first
        var response = card.ProcessCommand(initUpdateCommand);

        // Assert
        _ = response.StatusWord.Should().Be(StatusWords.Success);
        _ = response.Data.Length.Should().BeGreaterThanOrEqualTo(28); // Minimum INITIALIZE UPDATE response
        // Response should contain key version, SCP info, card challenge, and cryptogram
    }

    [Test]
    public void ProcessCommand_WithFailingCrypto_ShouldHandleErrors()
    {
        // Arrange
        var card = VirtualCardTestBuilder.SimulatingErrors();
        var selectCommand = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 };
        var initUpdateCommand = new byte[] 
        { 
            0x80, 0x50, 0x00, 0x00, 0x08, 
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
        };

        // Act
        _ = card.ProcessCommand(selectCommand); // This should work (no crypto needed)
        var response = card.ProcessCommand(initUpdateCommand); // This should fail

        // Assert
        _ = response.StatusWord.Should().NotBe(StatusWords.Success);
    }

    [Test]
    public void CardState_ShouldBeImmutable()
    {
        // Arrange
        var card = VirtualCardTestBuilder.P71Card();
        var initialState = card.CurrentState;
        var selectCommand = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 };

        // Act
        _ = card.ProcessCommand(selectCommand);
        var newState = card.CurrentState;

        // Assert
        _ = initialState.IsSelected.Should().BeFalse();
        _ = newState.IsSelected.Should().BeTrue();
        // Original state should be unchanged (immutability)
        _ = initialState.Should().NotBe(newState);
    }

    [Test]
    public void ProcessCommand_DeleteApplication_RemovesFromCardState()
    {
        // Arrange - Create card with established secure channel for DELETE command testing
        var card = CreateCardWithSecureChannel();
        
        // Create DELETE command for a test application
        var testAid = Convert.FromHexString("A00000030800001000");
        var deleteCommand = DeleteCommand.CreateForApplication(testAid, deleteRelated: true).Value;
        var deleteApdu = ApduBuilder.BuildApdu(deleteCommand);
        
        // Act
        var response = card.ProcessCommand(deleteApdu);

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
        var card = CreateCardWithSecureChannel();
        
        // GlobalPlatform Card Specification v2.3.1 Section 11.5.2.1 INSTALL [for load]
        var packageAid = Convert.FromHexString("A000000308000010");
        var installForLoadCommand = InstallCommandBuilder.CreateForLoad(
            packageAid: packageAid,
            securityDomainAid: card.Configuration.IsdAid
        ).Value;
        
        // Act
        var response = card.ProcessCommand(ApduBuilder.BuildApdu(installForLoadCommand));

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
        var card = VirtualCardTestBuilder.P71Card();
        
        // First SELECT the ISD to put the card in selected state
        var selectCommand = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 };
        _ = card.ProcessCommand(selectCommand);
        
        // Create test session keys for secure channel (deterministic for unit testing)
        var sessionKeys = new Gp4Net.Domain.Keys.SessionKeys(
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
            var cardStateField = typeof(VirtualCard).GetField("_state", 
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            if (cardStateField is not null)
            {
                var currentState = (CardState)cardStateField.GetValue(card)!;
                var newState = currentState.WithSecureChannel(secureChannelResult.Value);
                cardStateField.SetValue(card, newState);
            }
        }
        
        return card;
    }

    [Test]
    public void ProcessCommandFunctionally_IsPureFunction()
    {
        // Arrange
        var config = CardConfiguration.P71();
        var crypto = new TestCryptographicService();
        var initialState = CardState.Initial;
        var selectCommand = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 };
            
        // Act - Call the same pure function multiple times
        var result1 = VirtualCard.ProcessCommandFunctionally(selectCommand, initialState, config, crypto, LoggingService.None);
        var result2 = VirtualCard.ProcessCommandFunctionally(selectCommand, initialState, config, crypto, LoggingService.None);

        // Assert - Pure function should return identical results
        _ = result1.IsSuccess.Should().BeTrue();
        _ = result2.IsSuccess.Should().BeTrue();
            
        var (response1, state1) = result1.Value;
        var (response2, state2) = result2.Value;

        _ = response1.StatusWord.Should().Be(response2.StatusWord);
        _ = response1.Data.Should().BeEquivalentTo(response2.Data);
        _ = state1.Should().Be(state2); // Records have value equality
    }

    [Test]
    public void Builder_ShouldCreateCustomConfigurations()
    {
        // Arrange & Act
        var card = VirtualCardTestBuilder.Builder()
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
        var card = VirtualCardTestBuilder.P71Card();
        var selectCommand = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 };

        // Act
        _ = card.ProcessCommand(selectCommand); // Change state
        _ = card.IsSelected.Should().BeTrue();
            
        card.Reset(); // Reset state

        // Assert
        _ = card.IsSelected.Should().BeFalse();
        _ = card.IsSecureChannelEstablished.Should().BeFalse();
    }
}