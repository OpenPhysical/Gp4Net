using System;
using System.Linq;
using AwesomeAssertions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.Constants;
using NUnit.Framework;

namespace Gp4Net.Tests.Functional
{
    /// <summary>
    /// Demonstrates the testability of the functional virtual card architecture.
    /// These tests show how pure functions can be tested in isolation with predictable results.
    /// </summary>
    [TestFixture]
    public class FunctionalVirtualCardTests
    {
        [Test]
        public void P71Card_ShouldHaveCorrectAtr()
        {
            // Arrange
            var card = VirtualCardTestBuilder.P71Card();
            
            // Act
            var atr = card.GetAtr();
            
            // Assert
            atr.Should().Equal(Convert.FromHexString("3BD518FF8191FE1FC38073C821100A"));
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
            response.StatusWord.Should().Be(StatusWords.SUCCESS);
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
            response.StatusWord.Should().Be(StatusWords.INSTRUCTION_NOT_SUPPORTED);
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
            response.StatusWord.Should().Be(StatusWords.SUCCESS);
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
            response.StatusWord.Should().Be(StatusWords.SUCCESS);
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
            response.StatusWord.Should().NotBe(StatusWords.SUCCESS);
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
        public void ProcessCommandFunctionally_IsPureFunction()
        {
            // Arrange
            var config = CardConfiguration.P71();
            var crypto = new TestCryptographicService();
            var initialState = CardState.Initial;
            var selectCommand = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 };
            
            // Act - Call the same pure function multiple times
            var result1 = FunctionalVirtualCard.ProcessCommandFunctionally(selectCommand, initialState, config, crypto);
            var result2 = FunctionalVirtualCard.ProcessCommandFunctionally(selectCommand, initialState, config, crypto);
            
            // Assert - Pure function should return identical results
            result1.IsSuccess.Should().BeTrue();
            result2.IsSuccess.Should().BeTrue();
            
            var (response1, state1) = result1.Value;
            var (response2, state2) = result2.Value;
            
            response1.StatusWord.Should().Be(response2.StatusWord);
            response1.Data.Should().Equal(response2.Data);
            state1.Should().Be(state2); // Records have value equality
        }

        [Test]
        public void Builder_ShouldCreateCustomConfigurations()
        {
            // Arrange & Act
            var card = VirtualCardTestBuilder.Builder()
                .AsP71()
                .WithScp(0x03, 0x70)
                .WithTestCrypto()
                .Build();
            
            // Assert
            card.Configuration.CardType.Should().Contain("P71");
            card.Configuration.DefaultScpVersion.Should().Be(0x03);
            card.Configuration.DefaultScpImplementation.Should().Be(0x70);
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
}