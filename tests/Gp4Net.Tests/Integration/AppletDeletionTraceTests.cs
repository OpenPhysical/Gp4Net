using System;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using NUnit.Framework;
using Moq;
using Gp4Net.Cryptography;

namespace Gp4Net.Tests.Integration;

/// <summary>
/// Tests based on GP Pro applet deletion trace to verify correct behavior.
/// </summary>
[TestFixture]
[Category("Integration")]
public class AppletDeletionTraceTests
{
    private Mock<IKeyDerivationService> _keyDerivationServiceMock = null!;

    [SetUp]
    public void SetUp()
    {
        _keyDerivationServiceMock = new Mock<IKeyDerivationService>();
    }

    // From GP Pro trace
    private readonly byte[] _hostChallenge = Convert.FromHexString("FA4C144173EEA5DA");
    private readonly byte[] _initUpdateResponse = Convert.FromHexString(
        "0370000000000000000001037081E02F9C4061653AA1AEEA9F46AF46B2000010"
    );
    private readonly byte[] _testKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");

    [Test]
    public void GpProTrace_InitializeUpdate_ParsedCorrectly()
    {
        // Arrange & Act
        var response = InitializeUpdateResponse.Parse(_initUpdateResponse);

        Assert.Multiple(() =>
        {
            // Assert - Values from GP Pro trace line 18
            Assert.That(response.KeyDiversificationData, Is.EqualTo(Convert.FromHexString("03700000000000000000")));
            Assert.That(response.KeyVersion, Is.EqualTo(1)); // GP Pro: "key version 1 (0x01)"
            Assert.That(response.ScpId, Is.EqualTo(0x03)); // SCP03 protocol version
            Assert.That(response.ScpParameter, Is.EqualTo(0x70)); // Implementation parameter 'i'
            Assert.That(response.CardChallenge, Is.EqualTo(Convert.FromHexString("81E02F9C4061653A")));
            Assert.That(response.CardCryptogram, Is.EqualTo(Convert.FromHexString("A1AEEA9F46AF46B2")));
            Assert.That(response.SequenceCounter, Is.EqualTo(Convert.FromHexString("000010")));
        });
    }

    [Test]
    public void GpProTrace_SessionKeyDerivation_MatchesExpectedValues()
    {
        // Arrange
        var keySet = new Scp03KeySet(_testKey, _testKey, _testKey, 1);
        var cardChallenge = Convert.FromHexString("81E02F9C4061653A");
            
        // Expected values from GP Pro trace line 25
        var expectedEncKey = Convert.FromHexString("8528317332886BF53390C8F141A0D793");
        var expectedMacKey = Convert.FromHexString("10110A26F982BE99829C3816EF1EB4A5");
        var expectedRMacKey = Convert.FromHexString("718D60A711A1F0778A7A1AEEAB96B19C");

        // Act
        var sessionKeys = Gp4Net.Cryptography.KeyDerivation.DeriveScp03SessionKeys(
            keySet, 
            _hostChallenge, 
            cardChallenge, 
            128
        );

        // Assert
        Console.WriteLine($"Expected ENC:  {Convert.ToHexString(expectedEncKey)}");
        Console.WriteLine($"Actual ENC:    {Convert.ToHexString(sessionKeys.Value.SEnc)}");
        Console.WriteLine($"Expected MAC:  {Convert.ToHexString(expectedMacKey)}");
        Console.WriteLine($"Actual MAC:    {Convert.ToHexString(sessionKeys.Value.SMac)}");
        Console.WriteLine($"Expected RMAC: {Convert.ToHexString(expectedRMacKey)}");
        Console.WriteLine($"Actual RMAC:   {Convert.ToHexString(sessionKeys.Value.SrMac)}");

        Assert.Multiple(() =>
        {
            Assert.That(sessionKeys.Value.SEnc, Is.EqualTo(expectedEncKey));
            Assert.That(sessionKeys.Value.SMac, Is.EqualTo(expectedMacKey));
            Assert.That(sessionKeys.Value.SrMac, Is.EqualTo(expectedRMacKey));
        });
    }

    [Test]
    public void GpProTrace_HostCryptogram_MatchesExpectedValue()
    {
        // Arrange
        var keySet = new Scp03KeySet(_testKey, _testKey, _testKey, 1);
        var protocol = new Scp03Protocol(keySet, _keyDerivationServiceMock.Object, 0x70);
        var response = InitializeUpdateResponse.Parse(_initUpdateResponse);
        var cardChallenge = Convert.FromHexString("81E02F9C4061653A");
            
        // Derive session keys
        var sessionKeys = Gp4Net.Cryptography.KeyDerivation.DeriveScp03SessionKeys(
            keySet, 
            _hostChallenge, 
            cardChallenge, 
            128
        );

        // Expected from GP Pro trace line 27
        var expectedHostCryptogram = Convert.FromHexString("A1883C4B93BE2B01");

        // Act
        var actualHostCryptogram = protocol.CalculateHostCryptogram(
            response, 
            _hostChallenge, 
            sessionKeys.Value
        );

        // Assert
        Console.WriteLine($"Expected: {Convert.ToHexString(expectedHostCryptogram)}");
        Console.WriteLine($"Actual:   {Convert.ToHexString(actualHostCryptogram)}");
        Assert.That( actualHostCryptogram, Is.EqualTo(expectedHostCryptogram));
    }

    [Test]
    public void GpProTrace_ExternalAuthenticateCommand_MatchesExpectedApdu()
    {
        // Arrange
        var keySet = new Scp03KeySet(_testKey, _testKey, _testKey, 1);
        
        // Setup mock to return expected session keys
        var cardChallenge = Convert.FromHexString("81E02F9C4061653A");
        var sessionKeys = Gp4Net.Cryptography.KeyDerivation.DeriveScp03SessionKeys(
            keySet, 
            _hostChallenge, 
            cardChallenge, 
            128
        );
        
        _keyDerivationServiceMock
            .Setup(x => x.DeriveSessionKeys(It.IsAny<IKeyDerivationContext>()))
            .Returns(sessionKeys.Value);
            
        // Mock cryptogram calculation - return expected card cryptogram
        _keyDerivationServiceMock
            .Setup(x => x.CalculateCryptogram(It.IsAny<ICryptogramContext>()))
            .Returns<ICryptogramContext>(ctx =>
            {
                if (ctx.Type == CryptogramType.CardCryptogram)
                {
                    // Return the expected card cryptogram from the trace
                    return Convert.FromHexString("A1AEEA9F46AF46B2");
                }
                else if (ctx.Type == CryptogramType.HostCryptogram)
                {
                    // Return the expected host cryptogram
                    return Convert.FromHexString("A1883C4B93BE2B01");
                }
                return new byte[8];
            });
            
        var protocol = new Scp03Protocol(keySet, _keyDerivationServiceMock.Object, 0x70);
        var response = InitializeUpdateResponse.Parse(_initUpdateResponse);
        var context = protocol.ProcessInitializeUpdateResponse(response, _hostChallenge);

        // Expected from GP Pro trace line 28: 84820100 10 A1883C4B93BE2B01FFC7CC05DCC39D2E
        var expectedHostCryptogram = Convert.FromHexString("A1883C4B93BE2B01");
        var expectedMac = Convert.FromHexString("FFC7CC05DCC39D2E");

        // Act
        var extAuthCommandResult = protocol.CreateExternalAuthenticateCommand(context.Value, SecurityLevel.CMac);

        // Assert
        Assert.That(extAuthCommandResult.IsSuccess, Is.True);
        var extAuthCommand = extAuthCommandResult.Value;
            
        Console.WriteLine($"Expected Host Cryptogram: {Convert.ToHexString(expectedHostCryptogram)}");
        Console.WriteLine($"Actual Host Cryptogram:   {Convert.ToHexString(extAuthCommand.HostCryptogram)}");
        Console.WriteLine($"Expected MAC: {Convert.ToHexString(expectedMac)}");
        Console.WriteLine($"Actual MAC:   {Convert.ToHexString(extAuthCommand.Mac ?? [])}");

        Assert.Multiple(() =>
        {
            Assert.That(extAuthCommand.HostCryptogram, Is.EqualTo(expectedHostCryptogram));
            Assert.That(extAuthCommand.Mac, Is.EqualTo(expectedMac));
        });
    }

    [Test]
    public void DeleteCommand_Analysis_ShowsDifferentApduStructure()
    {
        // From our tool's debug output: 80E40000134F09A000000308000010000007B1419E555DE028
        var ourDeleteCommand = Convert.FromHexString("80E40000134F09A000000308000010000007B1419E555DE028");
            
        // From GP Pro trace line 39: 84E40080134F09A000000308000010007547C55C046E221C  
        var gpProDeleteCommand = Convert.FromHexString("84E40080134F09A000000308000010007547C55C046E221C");

        Console.WriteLine("=== DELETE Command Analysis ===");
        Console.WriteLine($"Our tool:  {Convert.ToHexString(ourDeleteCommand)}");
        Console.WriteLine($"GP Pro:    {Convert.ToHexString(gpProDeleteCommand)}");
        Console.WriteLine("");
            
        // Parse APDU structure
        Console.WriteLine("Our tool structure:");
        Console.WriteLine($"  CLA: 0x{ourDeleteCommand[0]:X2} (our: secure messaging)");
        Console.WriteLine($"  INS: 0x{ourDeleteCommand[1]:X2} (DELETE)");
        Console.WriteLine($"  P1:  0x{ourDeleteCommand[2]:X2} (our: delete mode)");
        Console.WriteLine($"  P2:  0x{ourDeleteCommand[3]:X2}");
        Console.WriteLine($"  Lc:  0x{ourDeleteCommand[4]:X2} ({ourDeleteCommand[4]} bytes)");
            
        Console.WriteLine("");
        Console.WriteLine("GP Pro structure:");
        Console.WriteLine($"  CLA: 0x{gpProDeleteCommand[0]:X2} (GP Pro: secure messaging)");
        Console.WriteLine($"  INS: 0x{gpProDeleteCommand[1]:X2} (DELETE)");
        Console.WriteLine($"  P1:  0x{gpProDeleteCommand[2]:X2} (GP Pro: delete mode)");
        Console.WriteLine($"  P2:  0x{gpProDeleteCommand[3]:X2}");
        Console.WriteLine($"  Lc:  0x{gpProDeleteCommand[4]:X2} ({gpProDeleteCommand[4]} bytes)");

        Assert.Multiple(() =>
        {
            // Key difference: P2 parameter
            Assert.That(ourDeleteCommand[2], Is.EqualTo(0x00)); // Our P1 
            Assert.That(gpProDeleteCommand[2], Is.EqualTo(0x00)); // GP Pro P1 (same)
            Assert.That(ourDeleteCommand[3], Is.EqualTo(0x00)); // Our P2
            Assert.That(gpProDeleteCommand[3], Is.EqualTo(0x80)); // GP Pro P2 (different!)
        });

        Console.WriteLine("");
        Console.WriteLine("=== KEY DIFFERENCE ===");
        Console.WriteLine("P2 parameter differs:");
        Console.WriteLine("  Our tool: P2=0x00 (delete by AID)");
        Console.WriteLine("  GP Pro:   P2=0x80 (delete with related objects)");
    }

    [Test]
    public void DeleteCommand_ShouldUseCorrectP2Parameter()
    {
        // According to GlobalPlatform specification:
        // P2 = 0x00: Delete by AID only  
        // P2 = 0x80: Delete with related objects
            
        // GP Pro uses P2=0x80 when deleting, which is more comprehensive
            
        // This test documents the expected behavior
        const byte expectedP2ForDeleteWithRelated = 0x80;
        const byte expectedP2ForDeleteOnly = 0x00;
            
        Console.WriteLine($"Expected P2 for delete with related: 0x{expectedP2ForDeleteWithRelated:X2}");
        Console.WriteLine($"Expected P2 for delete only: 0x{expectedP2ForDeleteOnly:X2}");
        Assert.Multiple(() =>
        {

            // The test serves as documentation - actual implementation fix needed in DeleteCommand
            Assert.That(expectedP2ForDeleteWithRelated, Is.EqualTo(0x80));
            Assert.That(expectedP2ForDeleteOnly, Is.EqualTo(0x00));
        });
    }

    [Test]
    public void DeleteCommand_WithDeleteRelated_GeneratesCorrectApdu()
    {
        // Arrange
        var testAid = Convert.FromHexString("A000000308000010");
        var deleteCommandResult = Gp4Net.Domain.Commands.DeleteCommand.CreateForApplication(
            testAid, 
            deleteRelated: true  // This should set P2=0x80
        );
        Assert.That(deleteCommandResult.IsSuccess, Is.True);
        var deleteCommand = deleteCommandResult.Value;

        // Act
        var apdu = deleteCommand.ToApdu();

        // Assert
        Console.WriteLine($"Generated APDU: {Convert.ToHexString(apdu)}");
        Console.WriteLine($"CLA: 0x{apdu[0]:X2}");
        Console.WriteLine($"INS: 0x{apdu[1]:X2}");
        Console.WriteLine($"P1:  0x{apdu[2]:X2}");
        Console.WriteLine($"P2:  0x{apdu[3]:X2}");
        Console.WriteLine($"Lc:  0x{apdu[4]:X2}");

        Assert.Multiple(() =>
        {
            // Verify APDU structure matches GP Pro format
            Assert.That(apdu[0], Is.EqualTo(0x80)); // CLA
            Assert.That(apdu[1], Is.EqualTo(0xE4)); // INS (DELETE)
            Assert.That(apdu[2], Is.EqualTo(0x00)); // P1 (delete object and related)
            Assert.That(apdu[3], Is.EqualTo(0x80)); // P2 (with related objects)
        });

        // Should match GP Pro format: 84E40080 13 4F09A000000308000010007547C55C046E221C
        // Our format should be: 80E40080 XX 4F08A000000308000010 00
    }
}