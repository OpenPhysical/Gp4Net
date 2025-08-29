using System;
using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Domain.Security;
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
        byte[] staticEncKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        byte[] staticMacKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        byte[] staticDekKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");

        byte[] hostChallenge = Convert.FromHexString("1122334455667788");
        byte[] cardChallenge = Convert.FromHexString("AABBCCDDEE11");
        byte[] sequenceCounter = Convert.FromHexString("0001");
        byte implementationParameter = 0x15;

        // Create key set
        Result<Scp02KeySet, SmartCardError> keySetResult = Scp02KeySet.Create(staticEncKey, staticMacKey, staticDekKey, 0x01);
        _ = keySetResult.IsSuccess.Should().BeTrue();
        Scp02KeySet? keySet = keySetResult.Value;

        // Build card cryptogram data exactly as in test vectors (32 bytes total)
        byte[] cardCryptogramData = Convert.FromHexString("11223344556677880001AABBCCDDEE1180000000000000000000000000000000");
        byte[] expectedCardCryptogram = Convert.FromHexString("96476D6663D92B5E");

        // Test 1: Verify Full 3DES MAC is being used for cryptograms with S-ENC key
        Console.WriteLine("=== Test 1: Direct Full 3DES MAC with S-ENC ===");
        byte[] correctSEncKey = Convert.FromHexString("25C9794A1205FF244F5FA0378D2F8D59");
        Result<byte[], SmartCardError> full3DesResult = MacCalculations.CalculateScp02Cryptogram(correctSEncKey, cardCryptogramData);
        _ = full3DesResult.IsSuccess.Should().BeTrue();
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

        _ = sessionKeysResult.IsSuccess.Should().BeTrue();
        var sessionKeys = sessionKeysResult.Value;
        byte[] expectedSEncKey = Convert.FromHexString("25C9794A1205FF244F5FA0378D2F8D59");

        Console.WriteLine($"Session S-ENC: {Convert.ToHexString(sessionKeys.SEnc)}");
        Console.WriteLine($"Expected:      {Convert.ToHexString(expectedSEncKey)}");
        _ = sessionKeys.SEnc.SequenceEqual(expectedSEncKey).Should().BeTrue("Session S-ENC key mismatch");

        // For i=15, S-MAC should be derived per GP Card Spec Section E.4.1 and live card trace data
        byte[] expectedSMacKey = Convert.FromHexString("9BED98891580C3B245FE9EC58BFA8D2A"); // Derived value from live card
        Console.WriteLine($"Session S-MAC: {Convert.ToHexString(sessionKeys.SMac)}");
        Console.WriteLine($"Expected:      {Convert.ToHexString(expectedSMacKey)}");
        _ = sessionKeys.SMac.SequenceEqual(expectedSMacKey).Should().BeTrue("Session S-MAC key should be derived for i=15 per GP Card Spec Section E.4.1 and live trace data");

        // Test 3: Calculate cryptogram using protocol implementation with S-ENC key
        Console.WriteLine("\n=== Test 3: Cryptogram Calculation ===");
        var cryptogramResult = Scp02ProtocolImpl.CalculateCryptogramMac(sessionKeys.SEnc, cardCryptogramData);
        _ = cryptogramResult.IsSuccess.Should().BeTrue();

        Console.WriteLine($"Cryptogram with S-ENC: {Convert.ToHexString(cryptogramResult.Value)}");
        Console.WriteLine($"Expected:              {Convert.ToHexString(expectedCardCryptogram)}");

        // This is the actual assertion that matters
        _ = cryptogramResult.Value.SequenceEqual(expectedCardCryptogram).Should().BeTrue("Card cryptogram mismatch");
    }

    [Test]
    public void SCP02_Should_Use_Full3DES_Not_Retail_MAC()
    {
        // This test verifies we're using the correct MAC algorithm
        byte[] testKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        byte[] testData = Convert.FromHexString("11223344556677880001AABBCCDDEE118000000000000000");

        Result<byte[], SmartCardError> full3DesResult = MacCalculations.CalculateScp02Cryptogram(testKey, testData);
        Result<byte[], SmartCardError> retailMacResult = MacCalculations.CalculateScp02CommandMac(testKey, testData);

        _ = full3DesResult.IsSuccess.Should().BeTrue();
        _ = retailMacResult.IsSuccess.Should().BeTrue();

        Console.WriteLine($"Full 3DES MAC:  {Convert.ToHexString(full3DesResult.Value)}");
        Console.WriteLine($"Retail MAC:     {Convert.ToHexString(retailMacResult.Value)}");

        // They should be different!
        _ = full3DesResult.Value.SequenceEqual(retailMacResult.Value).Should().BeFalse("Full 3DES and Retail MAC should produce different results");

        // And Scp02ProtocolImpl should use Full 3DES
        var protocolResult = Scp02ProtocolImpl.CalculateCryptogramMac(testKey, testData);
        _ = protocolResult.IsSuccess.Should().BeTrue();
        _ = protocolResult.Value.SequenceEqual(full3DesResult.Value).Should().BeTrue("Scp02ProtocolImpl should use Full 3DES MAC for cryptograms");
    }
}