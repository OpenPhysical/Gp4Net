using System;
using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.CardEmulator.Services;
using Gp4Net.CardEmulator.Tests.TestHelpers;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using WSCT.ISO7816;
using static Gp4Net.Constants.Constants;
using static Gp4Net.Cryptography.CryptoOperations;
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
        var configResult = CardConfiguration.P71();
        CardConfiguration config = default!;
        if (configResult.IsSuccess)
        {
            config = configResult.Value;
        }
        else
        {
            Assert.Fail($"Failed to load P71 configuration: {configResult.Error}");
        }
        var card = VirtualCardTestBuilder.CreateWithSecureRng(config);

        // Act
        byte[] atr = card.GetAtr();

        // Assert
        _ = atr.Should().BeEquivalentTo(Convert.FromHexString("3BD518FF8191FE1FC38073C821100A"));
    }

    [Test]
    public void ProcessSelect_WithValidCommand_ShouldSelectCard()
    {
        // Arrange
        var configResult = CardConfiguration.P71();
        CardConfiguration config = default!;
        if (configResult.IsSuccess)
        {
            config = configResult.Value;
        }
        else
        {
            Assert.Fail($"Failed to load P71 configuration: {configResult.Error}");
        }
        var card = VirtualCardTestBuilder.CreateWithSecureRng(config);
        byte[] selectCommand = [0x00, 0xA4, 0x04, 0x00, 0x00]; // SELECT with no AID

        // Act
        var response = card.ExecuteCommand(selectCommand);

        // Assert
        _ = response.StatusWord.Should().Be(StatusWords.Success);
        _ = card.IsSelected.Should().BeTrue();
        _ = response.Data.Length.Should().BeGreaterThan(0); // Should return FCI
    }

    [Test]
    public void ProcessSelect_WithUnsupportedInstruction_ShouldReturnError()
    {
        // Arrange
        var configResult = CardConfiguration.P71();
        CardConfiguration config = default!;
        if (configResult.IsSuccess)
        {
            config = configResult.Value;
        }
        else
        {
            Assert.Fail($"Failed to load P71 configuration: {configResult.Error}");
        }
        var card = VirtualCardTestBuilder.CreateWithSecureRng(config);
        // Use an invalid instruction that's not in GlobalPlatform spec
        byte[] unsupportedCommand =
        [
            0x80,
            0xFF, // Invalid instruction - not in GP spec
            0x00,
            0x00,
            0x00,
        ];

        // Act
        var response = card.ExecuteCommand(unsupportedCommand);

        // Assert
        _ = response.StatusWord.Should().Be(StatusWords.InstructionErrors.InstructionNotSupported);
    }

    [Test]
    public void ProcessIdentify_OnP71Card_ShouldReturnP71Data()
    {
        // Arrange
        var configResult = CardConfiguration.P71();
        CardConfiguration config = default!;
        if (configResult.IsSuccess)
        {
            config = configResult.Value;
        }
        else
        {
            Assert.Fail($"Failed to load P71 configuration: {configResult.Error}");
        }
        var card = VirtualCardTestBuilder.CreateWithSecureRng(config);

        // Test both implicit and explicit select - ISD should be implicitly selected per GP spec
        // but we can also explicitly select it
        byte[] selectCommand = new byte[]
        {
            0x00,
            Gp4Net.Constants.Apdu.Instructions.SELECT,
            0x04,
            0x00,
            (byte)config.IsdAid.Length,
        }
            .Concat(config.IsdAid)
            .Concat(new byte[] { 0x00 })
            .ToArray();
        var selectResponse = card.ExecuteCommand(selectCommand);
        TestContext.Out.WriteLine($"SELECT response: 0x{selectResponse.StatusWord:X4}");

        // Build IDENTIFY command using constants - GET DATA for P71 IDENTIFY tag
        // The P1P2 combination (0x00FE) specifies the data object to retrieve
        byte[] identifyCommand =
        [
            0x80, // GlobalPlatform CLA
            Gp4Net.Constants.Apdu.Instructions.GET_DATA,
            0x00, // P1 - high byte of data object identifier
            Constants.Constants.Tlv.VendorSpecific.NXP_P71_IDENTIFY, // P2 - low byte (0xFE)
            0x00, // Le - expect any length response
        ];

        // Debug: Check configuration
        TestContext.Out.WriteLine($"Config DataObjects count: {config.DefaultDataObjects.Count}");
        TestContext.Out.WriteLine(
            $"Config has 0x00FE: {config.DefaultDataObjects.ContainsKey(0x00FE)}"
        );
        if (config.DefaultDataObjects.ContainsKey(0x00FE))
        {
            var identifyData = config.DefaultDataObjects[0x00FE];
            TestContext.Out.WriteLine($"0x00FE data length in config: {identifyData.Length} bytes");
        }

        // Act
        var result = card.ProcessCommand(identifyCommand);

        // Assert
        result.Match(
            success =>
            {
                var response = success.Response;
                TestContext.Out.WriteLine($"Response Status: 0x{response.StatusWord:X4}");
                TestContext.Out.WriteLine($"Response Data Length: {response.Data.Length}");
                if (response.Data.Length > 0)
                {
                    TestContext.Out.WriteLine(
                        $"Response Data: {Convert.ToHexString(response.Data)}"
                    );
                }

                _ = response.StatusWord.Should().Be(StatusWords.Success);
                _ = response.Data.Should().NotBeEmpty();
                // GET DATA returns complete TLV structure: FE (tag) + length + DF28 (inner tag) + data
                _ = response.Data[0].Should().Be(0xFE); // Outer tag (P71 IDENTIFY)
                _ = response.Data[1].Should().Be(0x45); // Length (69 bytes)
                _ = response.Data[2].Should().Be(0xDF); // Inner tag high byte
                _ = response.Data[3].Should().Be(0x28); // Inner tag low byte
                return UnitResult.Success<SmartCardError>();
            },
            error =>
            {
                TestContext.Out.WriteLine($"Command failed: {error.Message}");
                Assert.Fail($"ProcessCommand failed: {error.Message}");
                return UnitResult.Failure<SmartCardError>(error);
            }
        );
    }

    [Test]
    public void ProcessInitializeUpdate_WithValidCommand_ShouldReturnCryptogram()
    {
        // Arrange
        var configResult = CardConfiguration.P71();
        CardConfiguration config = default!;
        if (configResult.IsSuccess)
        {
            config = configResult.Value;
        }
        else
        {
            Assert.Fail($"Failed to load P71 configuration: {configResult.Error}");
        }
        var card = VirtualCardTestBuilder.CreateWithSecureRng(config);
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
        var result = card.ProcessCommand(initUpdateCommand);

        // Assert
        result.Match(
            success =>
            {
                var (response, _) = success;
                _ = response.StatusWord.Should().Be(StatusWords.Success);
                _ = response.Data.Length.Should().BeGreaterThanOrEqualTo(28); // Minimum INITIALIZE UPDATE response
            },
            error => Assert.Fail($"INITIALIZE UPDATE failed: {error}")
        );
        // Response should contain key version, SCP info, card challenge, and cryptogram
    }

    [Test]
    public void ProcessCommand_WithFailingCrypto_ShouldHandleErrors()
    {
        // Arrange
        var configResult = CardConfiguration.P71();
        CardConfiguration config = default!;
        if (configResult.IsSuccess)
        {
            config = configResult.Value;
        }
        else
        {
            Assert.Fail($"Failed to load P71 configuration: {configResult.Error}");
        }
        var card = VirtualCardTestBuilder
            .CreateWithLimitedEntropy(config, 8)
            .GetValueOrDefault(VirtualCardTestBuilder.CreateWithSecureRng(config));
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
        var selectResponse = card.ExecuteCommand(selectCommand); // This should work (no crypto needed)
        TestContext.Out.WriteLine(
            $"SELECT response: {Convert.ToHexString(selectResponse.Data)} {selectResponse.StatusWord:X4}"
        );

        var response = card.ExecuteCommand(initUpdateCommand); // This should fail
        TestContext.Out.WriteLine(
            $"INITIALIZE UPDATE response: {Convert.ToHexString(response.Data)} {response.StatusWord:X4}"
        );
        TestContext.Out.WriteLine($"Expected: NOT 0x9000, Actual: 0x{response.StatusWord:X4}");

        // Assert
        _ = response.StatusWord.Should().NotBe(StatusWords.Success);
    }

    [Test]
    public void CardState_ShouldBeImmutable()
    {
        // Arrange
        var configResult = CardConfiguration.P71();
        CardConfiguration config = default!;
        if (configResult.IsSuccess)
        {
            config = configResult.Value;
        }
        else
        {
            Assert.Fail($"Failed to load P71 configuration: {configResult.Error}");
        }
        var card = VirtualCardTestBuilder.CreateWithSecureRng(config);
        var initialState = card.CurrentState;
        byte[] selectCommand = [0x00, 0xA4, 0x04, 0x00, 0x00];

        // Act
        var result = card.ProcessCommand(selectCommand);
        var updatedCard = result.IsSuccess ? (VirtualCard)result.Value.UpdatedCard : card;
        var newState = updatedCard.CurrentState;

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

        // Test immutability: original card's state should be unchanged
        _ = ReferenceEquals(card.CurrentState, initialState)
            .Should()
            .BeTrue("Original card's state should never be mutated");

        // Values can be equal, but objects must be different instances
        _ = initialState
            .IsSelected.Should()
            .Be(newState.IsSelected, "State values should be preserved correctly");
    }

    [Test]
    public void ProcessCommand_DeleteApplication_RemovesFromCardState()
    {
        // Arrange - Create card with established secure channel for DELETE command testing
        var card = CreateCardWithSecureChannel(SecurityLevel.CDecryption);

        // Create DELETE command for a test application
        byte[] testAid = Convert.FromHexString("A00000030800001000");
        var deleteResult = DeleteCommand.CreateForApplication(testAid, deleteRelated: true);

        // Act
        var response = deleteResult
            .Map(deleteCommand => deleteCommand.ToBytes())
            .Match(
                apduBytes =>
                {
                    var result = card.ProcessCommand(SecureCommand(card, apduBytes));
                    return result.IsSuccess ? result.Value.Response : new ApduResponse([], 0x6F00);
                },
                error => new ApduResponse([], 0x6F00) // Generic failure response
            );

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
        byte[] packageAid = Convert.FromHexString("A000000308000010");
        var installForLoadResult = InstallCommandBuilder.CreateForLoad(
            packageAid: packageAid,
            securityDomainAid: Maybe<byte[]>.From(card.Configuration.IsdAid)
        );

        // Act
        var response = installForLoadResult
            .Bind(installCommand => installCommand.ToCommandApdu())
            .Match(
                commandApdu =>
                {
                    var result = card.ProcessCommand(
                        SecureCommand(card, commandApdu.BinaryCommand)
                    );
                    return result.IsSuccess ? result.Value.Response : new ApduResponse([], 0x6F00);
                },
                error => new ApduResponse([], 0x6F00) // Generic failure response
            );

        // Assert
        _ = response.StatusWord.Should().Be(StatusWords.Success);
        // Per GlobalPlatform Card Specification v2.3.1 Table 11-13,
        // INSTALL Response should contain application specific data or one byte (00)
        _ = response.Data.Should().BeEquivalentTo(new byte[] { 0x00 });
    }

    [Test]
    public void ProcessCommand_PutKey_InstallsNamedVersion_WithoutChangingDefaultVersion()
    {
        // GP Card Specification v2.3.1, Tables 11-65 through 11-67: P1=00 adds
        // a KVN, and P2 carries the supplied first Key Identifier from 00 through 7F.
        var card = CreateCardWithSecureChannel();
        byte[] enc = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
        byte[] mac = Convert.FromHexString("102132435465768798A9BACBDCEDFE0F");
        byte[] dek = Convert.FromHexString("2031425364758697A8B9CADBECFD0E1F");
        var newKeys = Scp02KeySet.Create(enc, mac, dek, keyVersion: 0x01, keyId: 0x05).Value;
        var channel = card.CurrentState.SecureChannel.Value;
        var command = global::Gp4Net
            .Services.GlobalPlatform.KeyChange.CreateCommand(
                newKeys,
                channel,
                replacedKeyVersion: 0x00
            )
            .Value;
        _ = command.FirstKeyIdentifier.Should().Be(0x05);

        var result = card.ProcessCommand(SecureCommand(card, command.ToApdu().BinaryCommand));

        _ = result
            .IsSuccess.Should()
            .BeTrue(result.IsFailure ? result.Error.Message : string.Empty);
        _ = result.Value.Response.StatusWord.Should().Be(StatusWords.Success);
        _ = result.Value.Response.Data.Should().HaveCount(10);
        _ = result.Value.Response.Data[0].Should().Be(0x01);
        var updatedCard = (VirtualCard)result.Value.UpdatedCard;
        _ = updatedCard.CurrentState.InstalledKeys.Should().ContainKey(0x01);
        _ = updatedCard.CurrentState.InstalledKeys[0x01].KeyId.Should().Be(0x05);
        _ = updatedCard.CurrentState.DefaultKeyVersion.Should().Be(0xFF);
    }

    [Test]
    public void ProcessCommand_PutKey_InstallsOneKeyAtIdentifierZero()
    {
        // GP Card Specification v2.3.1, Tables 11-66 and 11-67: a PUT KEY data
        // field may contain one key and its Key Identifier may be 00 through 7F.
        var card = CreateCardWithSecureChannel();
        var newKeys = Scp02KeySet
            .Create(
                Convert.FromHexString("00112233445566778899AABBCCDDEEFF"),
                Convert.FromHexString("102132435465768798A9BACBDCEDFE0F"),
                Convert.FromHexString("2031425364758697A8B9CADBECFD0E1F"),
                keyVersion: 0x01
            )
            .Value;
        var complete = global::Gp4Net
            .Services.GlobalPlatform.KeyChange.CreateCommand(
                newKeys,
                card.CurrentState.SecureChannel.Value,
                replacedKeyVersion: 0x00,
                firstKeyIdentifier: 0x00
            )
            .Value;
        var command = PutKeyCommand
            .CreateReplacement(0x00, 0x02, 0x00, [complete.KeyDataBlocks[0]])
            .Value;

        var result = card.ProcessCommand(SecureCommand(card, command.ToApdu().BinaryCommand));

        _ = result
            .IsSuccess.Should()
            .BeTrue(result.IsFailure ? result.Error.Message : string.Empty);
        _ = result.Value.Response.Data.Should().HaveCount(4);
        var updatedCard = (VirtualCard)result.Value.UpdatedCard;
        _ = updatedCard
            .CurrentState.InstalledKeyComponents.Should()
            .ContainKey(new KeyReference(0x02, 0x00));
        _ = updatedCard.CurrentState.DefaultKeyVersion.Should().Be(0xFF);
    }

    [Test]
    public void ProcessCommand_PutKey_CommitsChainedKeysAtomically()
    {
        // GP Card Specification v2.3.1, Table 11-65 and 11.8.2.3.3: P1.b8
        // indicates another PUT KEY command, and the chain is committed atomically.
        var card = CreateCardWithSecureChannel();
        var keys = Scp02KeySet
            .Create(
                Convert.FromHexString("00112233445566778899AABBCCDDEEFF"),
                Convert.FromHexString("102132435465768798A9BACBDCEDFE0F"),
                Convert.FromHexString("2031425364758697A8B9CADBECFD0E1F"),
                keyVersion: 0x01
            )
            .Value;
        var complete = global::Gp4Net
            .Services.GlobalPlatform.KeyChange.CreateCommand(
                keys,
                card.CurrentState.SecureChannel.Value,
                replacedKeyVersion: 0x00,
                firstKeyIdentifier: 0x05
            )
            .Value;
        byte[] first = PutKeyCommand
            .CreateReplacement(0x00, 0x01, 0x05, [complete.KeyDataBlocks[0]])
            .Value.ToApdu()
            .BinaryCommand;
        first[2] |= 0x80;

        var firstResult = card.ProcessCommand(SecureCommand(card, first));

        _ = firstResult.IsSuccess.Should().BeTrue();
        var pendingCard = (VirtualCard)firstResult.Value.UpdatedCard;
        _ = pendingCard.CurrentState.InstalledKeyComponents.Should().BeEmpty();
        _ = pendingCard.CurrentState.PendingPutKey.HasValue.Should().BeTrue();

        byte[] last = PutKeyCommand
            .CreateReplacement(0x00, 0x01, 0x06, [complete.KeyDataBlocks[1]])
            .Value.ToApdu()
            .BinaryCommand;
        var lastResult = pendingCard.ProcessCommand(SecureCommand(pendingCard, last));

        _ = lastResult.IsSuccess.Should().BeTrue();
        var updatedCard = (VirtualCard)lastResult.Value.UpdatedCard;
        _ = updatedCard.CurrentState.PendingPutKey.HasValue.Should().BeFalse();
        _ = updatedCard
            .CurrentState.InstalledKeyComponents.Should()
            .ContainKey(new KeyReference(0x01, 0x05));
        _ = updatedCard
            .CurrentState.InstalledKeyComponents.Should()
            .ContainKey(new KeyReference(0x01, 0x06));
    }

    [Test]
    public void ProcessCommand_CommandMacFailure_AbortsSecureChannelUntilReinitialization()
    {
        // GP Card Specification v2.3.1, Section 10.2 and Appendix E.1.6: a
        // cryptographic protection error aborts the session, sets the Current Security
        // Level to NO_SECURITY, and persists until the session is terminated.
        var card = CreateCardWithSecureChannel();
        byte[] securedCommand = SecureCommand(card, Convert.FromHexString("80CA006600"));
        securedCommand[^2] ^= 0x01;

        var firstResult = card.ProcessCommand(securedCommand);

        _ = firstResult.IsSuccess.Should().BeTrue();
        _ = firstResult.Value.Response.StatusWord.Should().Be((StatusWord)0x6982);
        var abortedCard = (VirtualCard)firstResult.Value.UpdatedCard;
        _ = abortedCard.CurrentState.IsSecureChannelAborted.Should().BeTrue();
        _ = abortedCard.CurrentState.SecurityLevel.Should().Be((byte)SecurityLevel.None);
        _ = abortedCard.CurrentState.SecureChannel.HasValue.Should().BeTrue();

        var rejectedResult = abortedCard.ProcessCommand(Convert.FromHexString("80CA006600"));

        _ = rejectedResult.IsSuccess.Should().BeTrue();
        _ = rejectedResult.Value.Response.StatusWord.Should().Be((StatusWord)0x6982);
        var stillAbortedCard = (VirtualCard)rejectedResult.Value.UpdatedCard;
        _ = stillAbortedCard.CurrentState.IsSecureChannelAborted.Should().BeTrue();

        byte[] initializeUpdate = Convert.FromHexString("8050000008010203040506070800");
        var restartResult = stillAbortedCard.ProcessCommand(initializeUpdate);

        _ = restartResult.IsSuccess.Should().BeTrue();
        _ = restartResult.Value.Response.StatusWord.Should().Be(StatusWords.Success);
        var restartedCard = (VirtualCard)restartResult.Value.UpdatedCard;
        _ = restartedCard.CurrentState.IsSecureChannelAborted.Should().BeFalse();
        _ = restartedCard.CurrentState.SecureChannel.HasValue.Should().BeFalse();
    }

    /// <summary>
    /// Creates a virtual card with an established secure channel state for unit testing.
    /// Applies proper security level required for DELETE and INSTALL commands.
    /// </summary>
    private VirtualCard CreateCardWithSecureChannel(
        SecurityLevel securityLevel = SecurityLevel.CMac
    )
    {
        var configResult = CardConfiguration.P71();
        CardConfiguration config = default!;
        if (configResult.IsSuccess)
        {
            config = configResult.Value;
        }
        else
        {
            Assert.Fail($"Failed to load P71 configuration: {configResult.Error}");
        }
        var card = VirtualCardTestBuilder.CreateWithSecureRng(config);

        // First SELECT the ISD to put the card in selected state
        byte[] selectCommand = [0x00, 0xA4, 0x04, 0x00, 0x00];
        _ = card.ProcessCommand(selectCommand);

        // Create test session keys for secure channel (deterministic for unit testing)
        byte[] sessionKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var sessionKeys = new SessionKeys(
            sEnc: sessionKey,
            sMac: sessionKey,
            sRMac: sessionKey,
            dek: sessionKey
        );

        // Create secure channel state with C-MAC security level (required for DELETE/INSTALL)
        var secureChannelResult = SecureChannelState.Create(
            sessionKeys: sessionKeys,
            securityLevel: securityLevel,
            protocolVersion: ScpVersion.Scp02, // SCP02 for P71 cards
            initialMacChainingValue: new byte[8],
            implementationParameter: 0x15
        );

        // Create new card instance with secure channel established (functional approach)
        if (secureChannelResult.IsSuccess)
        {
            var currentState = card.CurrentState;
            var newState = currentState.WithSecureChannel(secureChannelResult.Value);

            return new VirtualCard(
                card.Configuration,
                Rng.CreateSecureContext(),
                newState,
                new CardLogging(Maybe<ILogger>.None),
                new EmulatorCapFiles(),
                new CardStateTransitions(Maybe<ILogger>.None),
                Maybe<CardState>.From(currentState)
            );
        }

        return card;
    }

    private static byte[] SecureCommand(VirtualCard card, byte[] command)
    {
        // GP Card Specification v2.3.1, E.3.3 and E.4.4: an authenticated SCP02
        // command carries an 8-byte C-MAC and the secure-messaging CLA indication.
        return card.CurrentState.SecureChannel.Match(
            channel =>
                global::Gp4Net
                    .Services.ScpOperations.Security.ApplyCommandSecurity(
                        new CommandAPDU(command),
                        channel
                    )
                    .Match(
                        secured => secured.securedCommand.BinaryCommand,
                        error => throw new AssertionException(error.Message)
                    ),
            () => throw new AssertionException("Secure channel is not established")
        );
    }

    [Test]
    public void ProcessCommandFunctionally_ShouldProcessSelectCommand()
    {
        // Arrange
        var configResult = CardConfiguration.P71();
        CardConfiguration config = default!;
        if (configResult.IsSuccess)
        {
            config = configResult.Value;
        }
        else
        {
            Assert.Fail($"Failed to load P71 configuration: {configResult.Error}");
        }
        var rng = Rng.CreateSecureContext();
        byte[] selectCommand = [0x00, 0xA4, 0x04, 0x00, 0x00];
        var initialState = CardState.Create();

        // Act
        var result = initialState.Bind(state =>
            VirtualCard
                .ProcessCommandFunctionally(selectCommand, state, config, rng, CardLogging.None)
                .Map(x => x.Item1)
        ); // Extract just the response

        // Assert
        result.IsSuccess.Should().BeTrue();
    }

    [Test]
    public void Builder_ShouldCreateCustomConfigurations()
    {
        // Arrange & Act
        var configResult = CardConfiguration.P71();
        CardConfiguration config = default!;
        if (configResult.IsSuccess)
        {
            config = configResult.Value;
        }
        else
        {
            Assert.Fail($"Failed to load P71 configuration: {configResult.Error}");
        }
        var card = VirtualCardTestBuilder.CreateWithSecureRng(
            config with
            {
                DefaultScpVersion = 0x03,
                DefaultScpImplementation = ScpImplementation.Scp03I70,
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
        var configResult = CardConfiguration.P71();
        CardConfiguration config = default!;
        if (configResult.IsSuccess)
        {
            config = configResult.Value;
        }
        else
        {
            Assert.Fail($"Failed to load P71 configuration: {configResult.Error}");
        }
        var card = VirtualCardTestBuilder.CreateWithSecureRng(config);
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
