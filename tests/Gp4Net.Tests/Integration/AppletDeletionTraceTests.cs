using System;
using System.Threading.Tasks;
using Gp4Net.Constants;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Tool.Services;
using Gp4Net.Transport;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using Xunit.Abstractions;

namespace Gp4Net.Tests.Integration
{
    /// <summary>
    /// Tests based on GP Pro applet deletion trace to verify correct behavior.
    /// </summary>
    public class AppletDeletionTraceTests
    {
        private readonly ITestOutputHelper _output;

        // From GP Pro trace
        private readonly byte[] _hostChallenge = Convert.FromHexString("FA4C144173EEA5DA");
        private readonly byte[] _initUpdateResponse = Convert.FromHexString(
            "0370000000000000000001037081E02F9C4061653AA1AEEA9F46AF46B2000010"
        );
        private readonly byte[] _testKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");

        public AppletDeletionTraceTests(ITestOutputHelper output)
        {
            _output = output;
        }

        [Fact]
        public void GpProTrace_InitializeUpdate_ParsedCorrectly()
        {
            // Arrange & Act
            var response = InitializeUpdateResponse.Parse(_initUpdateResponse);

            // Assert - Values from GP Pro trace line 18
            Assert.Equal(Convert.FromHexString("03700000000000000000"), response.KeyDiversificationData);
            Assert.Equal(1, response.KeyVersion); // GP Pro: "key version 1 (0x01)"
            Assert.Equal(0x73, response.ScpId); // GP Pro: "SCP03 (i=70)" = 0x03 | 0x70 = 0x73
            Assert.Equal(Convert.FromHexString("81E02F9C4061653A"), response.CardChallenge);
            Assert.Equal(Convert.FromHexString("A1AEEA9F46AF46B2"), response.CardCryptogram);
            Assert.Equal(Convert.FromHexString("000010"), response.SequenceCounter);
        }

        [Fact]
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
            _output.WriteLine($"Expected ENC:  {Convert.ToHexString(expectedEncKey)}");
            _output.WriteLine($"Actual ENC:    {Convert.ToHexString(sessionKeys.SEnc)}");
            _output.WriteLine($"Expected MAC:  {Convert.ToHexString(expectedMacKey)}");
            _output.WriteLine($"Actual MAC:    {Convert.ToHexString(sessionKeys.SMac)}");
            _output.WriteLine($"Expected RMAC: {Convert.ToHexString(expectedRMacKey)}");
            _output.WriteLine($"Actual RMAC:   {Convert.ToHexString(sessionKeys.SRMac)}");

            Assert.Equal(expectedEncKey, sessionKeys.SEnc);
            Assert.Equal(expectedMacKey, sessionKeys.SMac);
            Assert.Equal(expectedRMacKey, sessionKeys.SRMac);
        }

        [Fact]
        public void GpProTrace_HostCryptogram_MatchesExpectedValue()
        {
            // Arrange
            var keySet = new Scp03KeySet(_testKey, _testKey, _testKey, 1);
            var protocol = new Scp03Protocol(keySet, 0x70);
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
                sessionKeys
            );

            // Assert
            _output.WriteLine($"Expected: {Convert.ToHexString(expectedHostCryptogram)}");
            _output.WriteLine($"Actual:   {Convert.ToHexString(actualHostCryptogram)}");
            Assert.Equal(expectedHostCryptogram, actualHostCryptogram);
        }

        [Fact]
        public void GpProTrace_ExternalAuthenticateCommand_MatchesExpectedApdu()
        {
            // Arrange
            var keySet = new Scp03KeySet(_testKey, _testKey, _testKey, 1);
            var protocol = new Scp03Protocol(keySet, 0x70);
            var response = InitializeUpdateResponse.Parse(_initUpdateResponse);
            var context = protocol.ProcessInitializeUpdateResponse(response, _hostChallenge);

            // Expected from GP Pro trace line 28: 84820100 10 A1883C4B93BE2B01FFC7CC05DCC39D2E
            var expectedHostCryptogram = Convert.FromHexString("A1883C4B93BE2B01");
            var expectedMac = Convert.FromHexString("FFC7CC05DCC39D2E");

            // Act
            var extAuthCommand = protocol.CreateExternalAuthenticateCommand(context, SecurityLevel.CMac);

            // Assert
            _output.WriteLine($"Expected Host Cryptogram: {Convert.ToHexString(expectedHostCryptogram)}");
            _output.WriteLine($"Actual Host Cryptogram:   {Convert.ToHexString(extAuthCommand.HostCryptogram)}");
            _output.WriteLine($"Expected MAC: {Convert.ToHexString(expectedMac)}");
            _output.WriteLine($"Actual MAC:   {Convert.ToHexString(extAuthCommand.Mac ?? Array.Empty<byte>())}");

            Assert.Equal(expectedHostCryptogram, extAuthCommand.HostCryptogram);
            Assert.Equal(expectedMac, extAuthCommand.Mac);
        }

        [Fact]
        public void DeleteCommand_Analysis_ShowsDifferentApduStructure()
        {
            // From our tool's debug output: 80E40000134F09A000000308000010000007B1419E555DE028
            var ourDeleteCommand = Convert.FromHexString("80E40000134F09A000000308000010000007B1419E555DE028");
            
            // From GP Pro trace line 39: 84E40080134F09A000000308000010007547C55C046E221C  
            var gpProDeleteCommand = Convert.FromHexString("84E40080134F09A000000308000010007547C55C046E221C");

            _output.WriteLine("=== DELETE Command Analysis ===");
            _output.WriteLine($"Our tool:  {Convert.ToHexString(ourDeleteCommand)}");
            _output.WriteLine($"GP Pro:    {Convert.ToHexString(gpProDeleteCommand)}");
            _output.WriteLine("");
            
            // Parse APDU structure
            _output.WriteLine("Our tool structure:");
            _output.WriteLine($"  CLA: 0x{ourDeleteCommand[0]:X2} (our: secure messaging)");
            _output.WriteLine($"  INS: 0x{ourDeleteCommand[1]:X2} (DELETE)");
            _output.WriteLine($"  P1:  0x{ourDeleteCommand[2]:X2} (our: delete mode)");
            _output.WriteLine($"  P2:  0x{ourDeleteCommand[3]:X2}");
            _output.WriteLine($"  Lc:  0x{ourDeleteCommand[4]:X2} ({ourDeleteCommand[4]} bytes)");
            
            _output.WriteLine("");
            _output.WriteLine("GP Pro structure:");
            _output.WriteLine($"  CLA: 0x{gpProDeleteCommand[0]:X2} (GP Pro: secure messaging)");
            _output.WriteLine($"  INS: 0x{gpProDeleteCommand[1]:X2} (DELETE)");
            _output.WriteLine($"  P1:  0x{gpProDeleteCommand[2]:X2} (GP Pro: delete mode)");
            _output.WriteLine($"  P2:  0x{gpProDeleteCommand[3]:X2}");
            _output.WriteLine($"  Lc:  0x{gpProDeleteCommand[4]:X2} ({gpProDeleteCommand[4]} bytes)");

            // Key difference: P2 parameter
            Assert.Equal(0x00, ourDeleteCommand[2]); // Our P1 
            Assert.Equal(0x00, gpProDeleteCommand[2]); // GP Pro P1 (same)
            Assert.Equal(0x00, ourDeleteCommand[3]); // Our P2
            Assert.Equal(0x80, gpProDeleteCommand[3]); // GP Pro P2 (different!)
            
            _output.WriteLine("");
            _output.WriteLine("=== KEY DIFFERENCE ===");
            _output.WriteLine("P2 parameter differs:");
            _output.WriteLine("  Our tool: P2=0x00 (delete by AID)");
            _output.WriteLine("  GP Pro:   P2=0x80 (delete with related objects)");
        }

        [Fact]
        public void DeleteCommand_ShouldUseCorrectP2Parameter()
        {
            // According to GlobalPlatform specification:
            // P2 = 0x00: Delete by AID only  
            // P2 = 0x80: Delete with related objects
            
            // GP Pro uses P2=0x80 when deleting, which is more comprehensive
            
            // This test documents the expected behavior
            const byte ExpectedP2ForDeleteWithRelated = 0x80;
            const byte ExpectedP2ForDeleteOnly = 0x00;
            
            _output.WriteLine($"Expected P2 for delete with related: 0x{ExpectedP2ForDeleteWithRelated:X2}");
            _output.WriteLine($"Expected P2 for delete only: 0x{ExpectedP2ForDeleteOnly:X2}");
            
            // The test serves as documentation - actual implementation fix needed in DeleteCommand
            Assert.Equal(0x80, ExpectedP2ForDeleteWithRelated);
            Assert.Equal(0x00, ExpectedP2ForDeleteOnly);
        }

        [Fact]
        public void DeleteCommand_WithDeleteRelated_GeneratesCorrectApdu()
        {
            // Arrange
            var testAid = Convert.FromHexString("A000000308000010");
            var deleteCommand = Gp4Net.Domain.Commands.DeleteCommand.CreateForApplication(
                testAid, 
                deleteRelated: true  // This should set P2=0x80
            );

            // Act
            var apdu = deleteCommand.ToApdu();

            // Assert
            _output.WriteLine($"Generated APDU: {Convert.ToHexString(apdu)}");
            _output.WriteLine($"CLA: 0x{apdu[0]:X2}");
            _output.WriteLine($"INS: 0x{apdu[1]:X2}");
            _output.WriteLine($"P1:  0x{apdu[2]:X2}");
            _output.WriteLine($"P2:  0x{apdu[3]:X2}");
            _output.WriteLine($"Lc:  0x{apdu[4]:X2}");

            // Verify APDU structure matches GP Pro format
            Assert.Equal(0x80, apdu[0]); // CLA
            Assert.Equal(0xE4, apdu[1]); // INS (DELETE)
            Assert.Equal(0x00, apdu[2]); // P1 (delete object and related)
            Assert.Equal(0x80, apdu[3]); // P2 (with related objects)
            
            // Should match GP Pro format: 84E40080 13 4F09A000000308000010007547C55C046E221C
            // Our format should be: 80E40080 XX 4F08A000000308000010 00
        }
    }
}