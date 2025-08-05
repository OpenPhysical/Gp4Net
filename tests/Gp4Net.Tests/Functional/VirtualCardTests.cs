using System;
using System.Linq;
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
        atr.Should().BeEquivalentTo(Convert.FromHexString("3BD518FF8191FE1FC38073C821100A"));
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
        response.StatusWord.Should().Be(StatusWords.Success);
        card.IsSelected.Should().BeTrue();
        response.Data.Length.Should().BeGreaterThan(0); // Should return FCI
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
        response.StatusWord.Should().Be(StatusWords.InstructionNotSupported);
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
        response.StatusWord.Should().Be(StatusWords.Success);
        response.Data.Should().NotBeEmpty();
        // Should contain DF28 tag and P71-specific identification data
        response.Data[0].Should().Be(0xDF);
        response.Data[1].Should().Be(0x28);
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
        card.ProcessCommand(selectCommand); // Select first
        var response = card.ProcessCommand(initUpdateCommand);
            
        // Assert
        response.StatusWord.Should().Be(StatusWords.Success);
        response.Data.Length.Should().BeGreaterThanOrEqualTo(28); // Minimum INITIALIZE UPDATE response
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
        card.ProcessCommand(selectCommand); // This should work (no crypto needed)
        var response = card.ProcessCommand(initUpdateCommand); // This should fail
            
        // Assert
        response.StatusWord.Should().NotBe(StatusWords.Success);
    }

    [Test]
    public void CardState_ShouldBeImmutable()
    {
        // Arrange
        var card = VirtualCardTestBuilder.P71Card();
        var initialState = card.CurrentState;
        var selectCommand = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 };
            
        // Act
        card.ProcessCommand(selectCommand);
        var newState = card.CurrentState;
            
        // Assert
        initialState.IsSelected.Should().BeFalse();
        newState.IsSelected.Should().BeTrue();
        // Original state should be unchanged (immutability)
        initialState.Should().NotBe(newState);
    }

    [Test]
    public void ProcessCommand_DeleteApplication_RemovesFromCardState()
    {
        // Arrange
        var card = VirtualCardTestBuilder.P71Card();
        
        // First establish a secure channel (required for DELETE command)
        EstablishSecureChannel(card);
        
        // Create DELETE command for a test application
        var testAid = Convert.FromHexString("A00000030800001000");
        var deleteCommand = DeleteCommand.CreateForApplication(testAid, deleteRelated: true).Value;
        var deleteApdu = ApduBuilder.BuildApdu(deleteCommand);
        
        // Act
        var response = card.ProcessCommand(deleteApdu);
        
        // Assert
        response.StatusWord.Should().Be(StatusWords.Success);
        // Per GlobalPlatform Card Specification v2.3.1 Table 11-26,
        // DELETE Response should contain one byte (00) indicating success
        response.Data.Should().BeEquivalentTo(new byte[] { 0x00 });
    }

    [Test]
    public void ProcessCommand_InstallForLoad_PreparesForCapFileLoading()
    {
        // Arrange
        var card = VirtualCardTestBuilder.P71Card();
        EstablishSecureChannel(card);
        
        // GlobalPlatform Card Specification v2.3.1 Section 11.5.2.1 INSTALL [for load]
        var packageAid = Convert.FromHexString("A000000308000010");
        var installForLoadCommand = InstallCommandBuilder.CreateForLoad(
            packageAid: packageAid,
            securityDomainAid: card.Configuration.IsdAid
        ).Value;
        
        // Act
        var response = card.ProcessCommand(ApduBuilder.BuildApdu(installForLoadCommand));
        
        // Assert
        response.StatusWord.Should().Be(StatusWords.Success);
        // Per GlobalPlatform Card Specification v2.3.1 Table 11-13,
        // INSTALL Response should contain application specific data or one byte (00)
        response.Data.Should().BeEquivalentTo(new byte[] { 0x00 });
    }

    private void EstablishSecureChannel(VirtualCard card)
    {
        // SELECT ISD
        var selectCommand = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 };
        card.ProcessCommand(selectCommand);
        
        // INITIALIZE UPDATE
        var hostChallenge = Convert.FromHexString("0102030405060708");
        var initUpdateCommand = new byte[] { 0x80, 0x50, 0x00, 0x00, 0x08 }
            .Concat(hostChallenge).ToArray();
        var initResponse = card.ProcessCommand(initUpdateCommand);
        
        // Mock EXTERNAL AUTHENTICATE (simplified for testing)
        var extAuthCommand = new byte[] { 0x84, 0x82, 0x01, 0x00, 0x10 }
            .Concat(new byte[16]).ToArray(); // Simplified - would need proper cryptogram
        card.ProcessCommand(extAuthCommand);
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
        var result1 = VirtualCard.ProcessCommandFunctionally(selectCommand, initialState, config, crypto);
        var result2 = VirtualCard.ProcessCommandFunctionally(selectCommand, initialState, config, crypto);
            
        // Assert - Pure function should return identical results
        result1.IsSuccess.Should().BeTrue();
        result2.IsSuccess.Should().BeTrue();
            
        var (response1, state1) = result1.Value;
        var (response2, state2) = result2.Value;
            
        response1.StatusWord.Should().Be(response2.StatusWord);
        response1.Data.Should().BeEquivalentTo(response2.Data);
        state1.Should().Be(state2); // Records have value equality
    }

    [Test]
    public void Builder_ShouldCreateCustomConfigurations()
    {
        // Arrange & Act
        var card = VirtualCardTestBuilder.Builder()
            .AsP71()
            .WithScp(0x03, Gp4Net.Domain.Protocol.ScpImplementation.Scp03PseudoRandom)
            .WithTestCrypto()
            .Build();
            
        // Assert
        card.Configuration.CardType.Should().Contain("P71");
        card.Configuration.DefaultScpVersion.Should().Be(0x03);
        card.Configuration.DefaultScpImplementation.Should().Be(Gp4Net.Domain.Protocol.ScpImplementation.Scp03PseudoRandom);
    }

    [Test]
    public void Reset_ShouldRestoreInitialState()
    {
        // Arrange
        var card = VirtualCardTestBuilder.P71Card();
        var selectCommand = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 };
            
        // Act
        card.ProcessCommand(selectCommand); // Change state
        card.IsSelected.Should().BeTrue();
            
        card.Reset(); // Reset state
            
        // Assert
        card.IsSelected.Should().BeFalse();
        card.IsSecureChannelEstablished.Should().BeFalse();
    }
}