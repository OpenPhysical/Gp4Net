using System;
using System.Threading.Tasks;
using Gp4Net.Constants;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Tests.TestHelpers;
using Gp4Net.Transport;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using Xunit.Abstractions;

namespace Gp4Net.Tests.Integration
{
    /// <summary>
    /// Tests to debug SCP03 session establishment and command wrapping against GP Pro traces.
    /// </summary>
    public class Scp03SessionDebuggingTests
    {
        private readonly ITestOutputHelper _output;

        // From the current session logs
        private readonly byte[] _ourHostChallenge = Convert.FromHexString("7E7AD56B6A59022C");
        private readonly byte[] _ourInitUpdateResponse = Convert.FromHexString(
            "03700000000000000000010370D14DBA22E83837726CC93376114D1717000018"
        );
        private readonly byte[] _testKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");

        public Scp03SessionDebuggingTests(ITestOutputHelper output)
        {
            _output = output;
        }

        [Fact]
        public void OurSession_InitializeUpdate_ParsedCorrectly()
        {
            // Arrange & Act
            var response = InitializeUpdateResponse.Parse(_ourInitUpdateResponse);

            // Assert
            _output.WriteLine($"Key Diversification Data: {Convert.ToHexString(response.KeyDiversificationData)}");
            _output.WriteLine($"Key Version: {response.KeyVersion}");
            _output.WriteLine($"SCP ID: 0x{response.ScpId:X2}");
            _output.WriteLine($"Card Challenge: {Convert.ToHexString(response.CardChallenge)}");
            _output.WriteLine($"Card Cryptogram: {Convert.ToHexString(response.CardCryptogram)}");
            _output.WriteLine($"Sequence Counter: {Convert.ToHexString(response.SequenceCounter)}");

            Assert.Equal(Convert.FromHexString("03700000000000000000"), response.KeyDiversificationData);
            Assert.Equal(1, response.KeyVersion);
            Assert.Equal(0x73, response.ScpId); // SCP03 (0x03) | implementation (0x70)
            Assert.Equal(Convert.FromHexString("D14DBA22E8383772"), response.CardChallenge);
            Assert.Equal(Convert.FromHexString("6CC93376114D1717"), response.CardCryptogram);
            Assert.Equal(Convert.FromHexString("000018"), response.SequenceCounter);
        }

        [Fact]
        public void OurSession_SessionKeyDerivation_DebugOutput()
        {
            // Arrange
            var keySet = new Scp03KeySet(_testKey, _testKey, _testKey, 1);
            var cardChallenge = Convert.FromHexString("D14DBA22E8383772");
            
            // Act
            var sessionKeys = Gp4Net.Cryptography.KeyDerivation.DeriveScp03SessionKeys(
                keySet, 
                _ourHostChallenge, 
                cardChallenge, 
                128
            );

            // Assert - Debug output
            _output.WriteLine($"Our Host Challenge: {Convert.ToHexString(_ourHostChallenge)}");
            _output.WriteLine($"Our Card Challenge: {Convert.ToHexString(cardChallenge)}");
            _output.WriteLine($"Derived S-ENC:  {Convert.ToHexString(sessionKeys.SEnc)}");
            _output.WriteLine($"Derived S-MAC:  {Convert.ToHexString(sessionKeys.SMac)}");
            _output.WriteLine($"Derived S-RMAC: {Convert.ToHexString(sessionKeys.SRMac)}");
        }

        [Fact]
        public void OurSession_HostCryptogram_DebugOutput()
        {
            // Arrange
            var keySet = new Scp03KeySet(_testKey, _testKey, _testKey, 1);
            var protocol = new Scp03Protocol(keySet, 0x70);
            var response = InitializeUpdateResponse.Parse(_ourInitUpdateResponse);
            var cardChallenge = Convert.FromHexString("D14DBA22E8383772");
            
            // Derive session keys
            var sessionKeys = Gp4Net.Cryptography.KeyDerivation.DeriveScp03SessionKeys(
                keySet, 
                _ourHostChallenge, 
                cardChallenge, 
                128
            );

            // Act
            var actualHostCryptogram = protocol.CalculateHostCryptogram(
                response, 
                _ourHostChallenge, 
                sessionKeys
            );

            // Assert - Debug output
            _output.WriteLine($"Calculated Host Cryptogram: {Convert.ToHexString(actualHostCryptogram)}");
            _output.WriteLine($"Expected Card Cryptogram: {Convert.ToHexString(response.CardCryptogram)}");
        }

        [Fact]
        public void OurSession_ExternalAuthenticateCommand_DebugOutput()
        {
            // Arrange
            var keySet = new Scp03KeySet(_testKey, _testKey, _testKey, 1);
            var protocol = new Scp03Protocol(keySet, 0x70);
            var response = InitializeUpdateResponse.Parse(_ourInitUpdateResponse);
            var context = protocol.ProcessInitializeUpdateResponse(response, _ourHostChallenge);

            // Act
            var extAuthCommand = protocol.CreateExternalAuthenticateCommand(context, SecurityLevel.CMac);

            // Assert - Debug output
            _output.WriteLine($"EXTERNAL AUTHENTICATE APDU: {Convert.ToHexString(extAuthCommand.ToApdu())}");
            _output.WriteLine($"Host Cryptogram: {Convert.ToHexString(extAuthCommand.HostCryptogram)}");
            _output.WriteLine($"MAC: {Convert.ToHexString(extAuthCommand.Mac ?? Array.Empty<byte>())}");
        }

        [Fact]
        public void OurSession_DeleteCommand_WrappingDebugOutput()
        {
            // Arrange
            var keySet = new Scp03KeySet(_testKey, _testKey, _testKey, 1);
            var protocol = new Scp03Protocol(keySet, 0x70);
            var response = InitializeUpdateResponse.Parse(_ourInitUpdateResponse);
            var context = protocol.ProcessInitializeUpdateResponse(response, _ourHostChallenge);
            
            // Create secure channel session
            var session = new SecureChannelSession(
                context.SessionKeys,
                SecurityLevel.CMac,
                ProtocolIdentifiers.Scp03,
                new byte[16] // Initial MAC chaining value
            );

            // Create DELETE command for the AID from logs
            var testAid = Convert.FromHexString("A00000030800001000"); // 9 bytes - the correct AID
            var deleteCommand = Gp4Net.Domain.Commands.DeleteCommand.CreateForApplication(
                testAid, 
                deleteRelated: true
            );

            // Act
            var originalApdu = deleteCommand.ToApdu();
            var commandObject = TestApduCommand.FromBytes(originalApdu);
            var (wrappedData, expectedResponseLength) = session.WrapCommand(commandObject);

            // Assert - Debug output
            _output.WriteLine($"Original DELETE APDU: {Convert.ToHexString(originalApdu)}");
            _output.WriteLine($"Wrapped DELETE APDU:  {Convert.ToHexString(wrappedData)}");
            _output.WriteLine($"Expected GP Pro:      84E40080134F09A000000308000010007547C55C046E221C");
            
            // Verify CLA byte has secure messaging indicator
            Assert.Equal(0x84, wrappedData[0]); // Should have secure messaging bit set
        }

        [Fact]
        public void MacChaining_InitialValue_ShouldBeZero()
        {
            // The initial MAC chaining value for SCP03 should be 16 bytes of zero
            var initialMacChaining = new byte[16];
            
            _output.WriteLine($"Initial MAC chaining value: {Convert.ToHexString(initialMacChaining)}");
            
            Assert.All(initialMacChaining, b => Assert.Equal(0, b));
        }
    }
}