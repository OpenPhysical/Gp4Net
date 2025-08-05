using System;
using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using NUnit.Framework;

namespace Gp4Net.Tests.Conformance;

/// <summary>
/// Verifies SCP02 cryptogram calculation against reference test vectors
/// </summary>
[TestFixture]
[Category("Conformance")]
public class Scp02CryptogramVerificationTest
{
    [Test]
    public void SCP02_Cryptogram_Should_Match_Reference_Vector()
    {
        // Test Vector 1: SCP02 i=15 Static MAC with GP Test Keys
        var staticEncKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var staticMacKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var staticDekKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");

        var hostChallenge = Convert.FromHexString("1122334455667788");
        var cardChallenge = Convert.FromHexString("AABBCCDDEE11");
        var sequenceCounter = Convert.FromHexString("0001");
        byte implementationParameter = 0x15;

        // Create key set
        var keySetResult = Scp02KeySet.Create(staticEncKey, staticMacKey, staticDekKey, 0x01);
        keySetResult.IsSuccess.Should().BeTrue();
        var keySet = keySetResult.Value;

        // Build card cryptogram data exactly as in test vectors (32 bytes total)
        var cardCryptogramData = Convert.FromHexString("11223344556677880001AABBCCDDEE1180000000000000000000000000000000");
        var expectedCardCryptogram = Convert.FromHexString("96476D6663D92B5E");

        // Test 1: Verify Full 3DES MAC is being used for cryptograms with S-ENC key
        Console.WriteLine("=== Test 1: Direct Full 3DES MAC with S-ENC ===");
        var correctSEncKey = Convert.FromHexString("25C9794A1205FF244F5FA0378D2F8D59");
        var full3DesResult = CryptographicOperations.CalculateFull3DesMac(correctSEncKey, cardCryptogramData);
        full3DesResult.IsSuccess.Should().BeTrue();
        Console.WriteLine($"Full 3DES MAC with S-ENC key: {Convert.ToHexString(full3DesResult.Value)}");
        Console.WriteLine($"Expected:                     {Convert.ToHexString(expectedCardCryptogram)}");
        
        // Test 2: Derive session keys
        Console.WriteLine("\n=== Test 2: Session Key Derivation ===");
        var sessionKeysResult = Scp02ProtocolImpl.DeriveSessionKeys(
            keySet,
            hostChallenge,
            cardChallenge,
            sequenceCounter,
            implementationParameter
        );
        
        sessionKeysResult.IsSuccess.Should().BeTrue();
        var sessionKeys = sessionKeysResult.Value;
        var expectedSEncKey = Convert.FromHexString("25C9794A1205FF244F5FA0378D2F8D59");
        
        Console.WriteLine($"Session S-ENC: {Convert.ToHexString(sessionKeys.SEnc)}");
        Console.WriteLine($"Expected:      {Convert.ToHexString(expectedSEncKey)}");
        sessionKeys.SEnc.SequenceEqual(expectedSEncKey).Should().BeTrue("Session S-ENC key mismatch");
        
        // For i=15, S-MAC should be static
        Console.WriteLine($"Session S-MAC: {Convert.ToHexString(sessionKeys.SMac)}");
        Console.WriteLine($"Expected:      {Convert.ToHexString(staticMacKey)}");
        sessionKeys.SMac.SequenceEqual(staticMacKey).Should().BeTrue("Session S-MAC key should be static for i=15");
        
        // Test 3: Calculate cryptogram using protocol implementation with S-ENC key
        Console.WriteLine("\n=== Test 3: Cryptogram Calculation ===");
        var cryptogramResult = Scp02ProtocolImpl.CalculateCryptogramMac(sessionKeys.SEnc, cardCryptogramData);
        cryptogramResult.IsSuccess.Should().BeTrue();
        
        Console.WriteLine($"Cryptogram with S-ENC: {Convert.ToHexString(cryptogramResult.Value)}");
        Console.WriteLine($"Expected:              {Convert.ToHexString(expectedCardCryptogram)}");
        
        // This is the actual assertion that matters
        cryptogramResult.Value.SequenceEqual(expectedCardCryptogram).Should().BeTrue("Card cryptogram mismatch");
    }
    
    [Test]
    public void SCP02_Should_Use_Full3DES_Not_Retail_MAC()
    {
        // This test verifies we're using the correct MAC algorithm
        var testKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var testData = Convert.FromHexString("11223344556677880001AABBCCDDEE118000000000000000");
        
        var full3DesResult = CryptographicOperations.CalculateFull3DesMac(testKey, testData);
        var retailMacResult = CryptographicOperations.CalculateRetailMac(testKey, testData);
        
        full3DesResult.IsSuccess.Should().BeTrue();
        retailMacResult.IsSuccess.Should().BeTrue();
        
        Console.WriteLine($"Full 3DES MAC:  {Convert.ToHexString(full3DesResult.Value)}");
        Console.WriteLine($"Retail MAC:     {Convert.ToHexString(retailMacResult.Value)}");
        
        // They should be different!
        full3DesResult.Value.SequenceEqual(retailMacResult.Value).Should().BeFalse("Full 3DES and Retail MAC should produce different results");
        
        // And Scp02ProtocolImpl should use Full 3DES
        var protocolResult = Scp02ProtocolImpl.CalculateCryptogramMac(testKey, testData);
        protocolResult.IsSuccess.Should().BeTrue();
        protocolResult.Value.SequenceEqual(full3DesResult.Value).Should().BeTrue("Scp02ProtocolImpl should use Full 3DES MAC for cryptograms");
    }
}