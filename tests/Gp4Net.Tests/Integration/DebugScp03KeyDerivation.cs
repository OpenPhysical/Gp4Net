using System;
using Gp4Net.Constants;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using NUnit.Framework;

namespace Gp4Net.Tests.Integration
{
    [TestFixture]
    public class DebugScp03KeyDerivation
    {

        [Test]
        public void Debug_Scp03_KeyDerivation_WithGpProTrace()
        {
            // Exact data from GP Pro trace
            var staticKeys = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
            var hostChallenge = Convert.FromHexString("FE0530CF61BAA9F3");
            var cardChallenge = Convert.FromHexString("83FA042C5C10F778");
            
            // Expected session keys from GP Pro
            var expectedSEnc = Convert.FromHexString("7392646744DF8721131C4A995A845BAE");
            var expectedSMac = Convert.FromHexString("CD9F750E543E0CF862B0EA73E3812113");
            var expectedSRMac = Convert.FromHexString("D1B695D89DE01992B6CB238BDFB006D9");
            
            // Expected cryptograms from GP Pro
            var expectedHostCryptogram = Convert.FromHexString("7B54E3B21E27DA5F");
            var expectedCardCryptogram = Convert.FromHexString("148C0CAF84B0E110");
            
            Console.WriteLine("=== SCP03 Key Derivation Debug ===");
            Console.WriteLine($"Static keys: {Convert.ToHexString(staticKeys)}");
            Console.WriteLine($"Host challenge: {Convert.ToHexString(hostChallenge)}");
            Console.WriteLine($"Card challenge: {Convert.ToHexString(cardChallenge)}");
            Console.WriteLine("");
            
            // Create SCP03 key set
            var keySet = new Scp03KeySet(staticKeys, staticKeys, staticKeys, 1);
            
            // Derive session keys using our implementation
            var sessionKeys = KeyDerivation.DeriveScp03SessionKeys(keySet, hostChallenge, cardChallenge, 128);
            
            Console.WriteLine("Expected:");
            Console.WriteLine($"S-ENC:  {Convert.ToHexString(expectedSEnc)}");
            Console.WriteLine($"S-MAC:  {Convert.ToHexString(expectedSMac)}");
            Console.WriteLine($"S-RMAC: {Convert.ToHexString(expectedSRMac)}");
            Console.WriteLine("");
            
            Console.WriteLine("Actual:");
            Console.WriteLine($"S-ENC:  {Convert.ToHexString(sessionKeys.SEnc)}");
            Console.WriteLine($"S-MAC:  {Convert.ToHexString(sessionKeys.SMac)}");
            Console.WriteLine($"S-RMAC: {Convert.ToHexString(sessionKeys.SRMac)}");
            Console.WriteLine("");
            
            Console.WriteLine("Match:");
            Console.WriteLine($"S-ENC:  {Convert.ToHexString(sessionKeys.SEnc) == Convert.ToHexString(expectedSEnc)}");
            Console.WriteLine($"S-MAC:  {Convert.ToHexString(sessionKeys.SMac) == Convert.ToHexString(expectedSMac)}");
            Console.WriteLine($"S-RMAC: {Convert.ToHexString(sessionKeys.SRMac) == Convert.ToHexString(expectedSRMac)}");
            Console.WriteLine("");
            
            // Test cryptogram calculation
            var protocol = new Scp03Protocol(keySet, 0x70);
            var initUpdateResponseBytes = Convert.FromHexString("0370000000000000000001037083FA042C5C10F778148C0CAF84B0E110000002");
            var response = InitializeUpdateResponse.Parse(initUpdateResponseBytes);
            
            var actualHostCryptogram = protocol.CalculateHostCryptogram(response, hostChallenge, sessionKeys);
            var cardCryptogramValid = protocol.VerifyCardCryptogram(response, hostChallenge, sessionKeys);
            
            Console.WriteLine("Host cryptogram:");
            Console.WriteLine($"Expected: {Convert.ToHexString(expectedHostCryptogram)}");
            Console.WriteLine($"Actual:   {Convert.ToHexString(actualHostCryptogram)}");
            Console.WriteLine($"Match: {Convert.ToHexString(actualHostCryptogram) == Convert.ToHexString(expectedHostCryptogram)}");
            Console.WriteLine("");
            
            Console.WriteLine("Card cryptogram:");
            Console.WriteLine($"Expected: {Convert.ToHexString(expectedCardCryptogram)}");
            Console.WriteLine($"From card: {Convert.ToHexString(response.CardCryptogram)}");
            Console.WriteLine($"Valid: {cardCryptogramValid}");
            Console.WriteLine("");
            
            // Test EXTERNAL AUTHENTICATE command creation
            var context = new SecureChannelContext(
                hostChallenge,
                response,
                sessionKeys,
                0x03,
                keySet
            );
            var extAuthCommandResult = protocol.CreateExternalAuthenticateCommand(context, SecurityLevel.CMac);
            Assert.That(extAuthCommandResult.IsSuccess, Is.True);
            var extAuthCommand = extAuthCommandResult.Value;
            var expectedMac = Convert.FromHexString("FCA958062C7CA0C5");
            
            Console.WriteLine("EXTERNAL AUTHENTICATE MAC:");
            Console.WriteLine($"Expected: {Convert.ToHexString(expectedMac)}");
            Console.WriteLine($"Actual:   {Convert.ToHexString(extAuthCommand.Mac ?? new byte[0])}");
            Console.WriteLine($"Match: {Convert.ToHexString(extAuthCommand.Mac ?? new byte[0]) == Convert.ToHexString(expectedMac)}");
            
            // Context analysis
            var contextBytes = new byte[16];
            Array.Copy(hostChallenge, 0, contextBytes, 0, 8);
            Array.Copy(cardChallenge, 0, contextBytes, 8, 8);
            Console.WriteLine("");
            Console.WriteLine($"Context: {Convert.ToHexString(contextBytes)}");
            
            // This test will fail - we're just using it for debugging
            // Assert.That(sessionKeys.SEnc, Is.EqualTo(expectedSEnc));
        }
    }
}