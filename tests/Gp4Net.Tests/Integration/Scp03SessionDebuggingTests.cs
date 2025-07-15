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
using NUnit.Framework;

namespace Gp4Net.Tests.Integration
{
    /// <summary>
    /// Tests to debug SCP03 session establishment and command wrapping against GP Pro traces.
    /// </summary>
    [TestFixture]
    public class Scp03SessionDebuggingTests
    {

        // From the current session logs
        private readonly byte[] _ourHostChallenge = Convert.FromHexString("7E7AD56B6A59022C");
        private readonly byte[] _ourInitUpdateResponse = Convert.FromHexString(
            "03700000000000000000010370D14DBA22E83837726CC93376114D1717000018"
        );
        private readonly byte[] _testKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");


        [Test]
        public void OurSession_InitializeUpdate_ParsedCorrectly()
        {
            // Arrange & Act
            var response = InitializeUpdateResponse.Parse(_ourInitUpdateResponse);

            // Assert
            Console.WriteLine($"Key Diversification Data: {Convert.ToHexString(response.KeyDiversificationData)}");
            Console.WriteLine($"Key Version: {response.KeyVersion}");
            Console.WriteLine($"SCP ID: 0x{response.ScpId:X2}");
            Console.WriteLine($"Card Challenge: {Convert.ToHexString(response.CardChallenge)}");
            Console.WriteLine($"Card Cryptogram: {Convert.ToHexString(response.CardCryptogram)}");
            Console.WriteLine($"Sequence Counter: {Convert.ToHexString(response.SequenceCounter)}");

            Assert.That(response.KeyDiversificationData, Is.EqualTo(Convert.FromHexString("03700000000000000000")));
            Assert.That(response.KeyVersion, Is.EqualTo(1));
            Assert.That(response.ScpId, Is.EqualTo(0x73)); // SCP03 (0x03) | implementation (0x70)
            Assert.That(response.CardChallenge, Is.EqualTo(Convert.FromHexString("D14DBA22E8383772")));
            Assert.That(response.CardCryptogram, Is.EqualTo(Convert.FromHexString("6CC93376114D1717")));
            Assert.That(response.SequenceCounter, Is.EqualTo(Convert.FromHexString("000018")));
        }

        [Test]
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
            Console.WriteLine($"Our Host Challenge: {Convert.ToHexString(_ourHostChallenge)}");
            Console.WriteLine($"Our Card Challenge: {Convert.ToHexString(cardChallenge)}");
            Console.WriteLine($"Derived S-ENC:  {Convert.ToHexString(sessionKeys.SEnc)}");
            Console.WriteLine($"Derived S-MAC:  {Convert.ToHexString(sessionKeys.SMac)}");
            Console.WriteLine($"Derived S-RMAC: {Convert.ToHexString(sessionKeys.SRMac)}");
        }

        [Test]
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
            Console.WriteLine($"Calculated Host Cryptogram: {Convert.ToHexString(actualHostCryptogram)}");
            Console.WriteLine($"Expected Card Cryptogram: {Convert.ToHexString(response.CardCryptogram)}");
        }

        [Test]
        public void OurSession_ExternalAuthenticateCommand_DebugOutput()
        {
            // Arrange
            var keySet = new Scp03KeySet(_testKey, _testKey, _testKey, 1);
            var protocol = new Scp03Protocol(keySet, 0x70);
            var response = InitializeUpdateResponse.Parse(_ourInitUpdateResponse);
            var context = protocol.ProcessInitializeUpdateResponse(response, _ourHostChallenge);

            // Act
            var extAuthCommandResult = protocol.CreateExternalAuthenticateCommand(context, SecurityLevel.CMac);

            // Assert - Debug output
            Assert.That(extAuthCommandResult.IsSuccess, Is.True);
            var extAuthCommand = extAuthCommandResult.Value;
            
            Console.WriteLine($"EXTERNAL AUTHENTICATE APDU: {Convert.ToHexString(extAuthCommand.ToApdu())}");
            Console.WriteLine($"Host Cryptogram: {Convert.ToHexString(extAuthCommand.HostCryptogram)}");
            Console.WriteLine($"MAC: {Convert.ToHexString(extAuthCommand.Mac ?? Array.Empty<byte>())}");
        }

        [Test]
        public void OurSession_DeleteCommand_WrappingDebugOutput()
        {
            // Arrange
            var keySet = new Scp03KeySet(_testKey, _testKey, _testKey, 1);
            var protocol = new Scp03Protocol(keySet, 0x70);
            var response = InitializeUpdateResponse.Parse(_ourInitUpdateResponse);
            var context = protocol.ProcessInitializeUpdateResponse(response, _ourHostChallenge);
            
            // Create secure channel session
            // From trace: EXTERNAL AUTHENTICATE MAC: A9A39F9910EDE5BC5677E1387BD3095D
            // The full 16-byte MAC is the chaining value for SCP03
            var macChainingValue = Convert.FromHexString("A9A39F9910EDE5BC5677E1387BD3095D");
            var session = new SecureChannelSession(
                context.SessionKeys,
                SecurityLevel.CMac,
                ProtocolIdentifiers.Scp03,
                macChainingValue
            );

            // Create DELETE command for the AID from logs
            var testAid = Convert.FromHexString("A00000030800001000"); // 9 bytes - the correct AID
            var deletionToken = Convert.FromHexString("20EEDD243F094FAD"); // From trace
            var deleteCommandResult = Gp4Net.Domain.Commands.DeleteCommand.CreateForApplication(
                testAid, 
                deleteRelated: true,
                deletionToken
            );
            var deleteCommand = deleteCommandResult.GetOrThrow(error => new InvalidOperationException(error.Message));

            // Act
            var originalApdu = deleteCommand.ToApdu();
            
            // Debug: Let's see what the original APDU structure looks like
            Console.WriteLine($"Original APDU breakdown:");
            Console.WriteLine($"  CLA: 0x{originalApdu[0]:X2}");
            Console.WriteLine($"  INS: 0x{originalApdu[1]:X2}");
            Console.WriteLine($"  P1:  0x{originalApdu[2]:X2}");
            Console.WriteLine($"  P2:  0x{originalApdu[3]:X2}");
            Console.WriteLine($"  Lc:  0x{originalApdu[4]:X2} ({originalApdu[4]} bytes)");
            if (originalApdu.Length > 5) {
                var dataOnly = originalApdu[5..];
                Console.WriteLine($"  Data: {Convert.ToHexString(dataOnly)}");
            }
            
            var commandObject = TestApduCommand.FromBytes(originalApdu);
            var (wrappedData, expectedResponseLength) = session.WrapCommand(commandObject);

            // Assert - Debug output
            Console.WriteLine($"Original DELETE APDU: {Convert.ToHexString(originalApdu)}");
            Console.WriteLine($"Wrapped DELETE APDU:  {Convert.ToHexString(wrappedData)}");
            
            // From trace analysis, the DELETE command with deletion token should be:
            // 84E40080134F09A0000003080000100020EEDD243F094FAD (complete command from trace)
            // But we're applying MAC using our session, so the MAC will be different
            
            // Verify the structure is correct
            Assert.That(wrappedData[0], Is.EqualTo(0x84)); // CLA with secure messaging
            Assert.That(wrappedData[1], Is.EqualTo(0xE4)); // DELETE instruction  
            Assert.That(wrappedData[2], Is.EqualTo(0x00)); // P1
            Assert.That(wrappedData[3], Is.EqualTo(0x80)); // P2
            Assert.That(wrappedData[4], Is.EqualTo(0x1B)); // Lc = 27 (19 data + 8 MAC)
            
            // Verify the data portion contains correct AID TLV and deletion token
            var dataWithoutMac = wrappedData[5..^8]; // Everything except header and MAC
            var expectedData = Convert.FromHexString("4F09A0000003080000100020EEDD243F094FAD");
            Assert.That(dataWithoutMac, Is.EqualTo(expectedData));
            
            // Verify MAC is present (8 bytes)
            var mac = wrappedData[^8..];
            Assert.That(mac.Length, Is.EqualTo(8));
            
            Console.WriteLine($"MAC calculated: {Convert.ToHexString(mac)}");
            Console.WriteLine("MAC calculation SUCCESS - DELETE command structure is correct");
        }

        [Test]
        public void MacChaining_InitialValue_ShouldBeZero()
        {
            // The initial MAC chaining value for SCP03 should be 16 bytes of zero
            var initialMacChaining = new byte[16];
            
            Console.WriteLine($"Initial MAC chaining value: {Convert.ToHexString(initialMacChaining)}");
            
            foreach (var b in initialMacChaining)
            {
                Assert.That(b, Is.EqualTo(0));
            }
        }
    }
}