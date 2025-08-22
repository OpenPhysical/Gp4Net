using System;
using System.IO;
using System.Text.Json;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Keys;

/// <summary>
/// Tests for KeyDerivationService with focus on SCP02 implementation parameter behavior.
/// </summary>
[TestFixture]
[Category("Unit")]
public class KeyDerivationServiceTests
{
    private KeyDerivationService _keyDerivationService;
    
    [SetUp]
    public void SetUp()
    {
        _keyDerivationService = new KeyDerivationService();
    }
    
    [Test]
    public void Scp02_I00_Should_Use_Derived_Mac_Keys()
    {
        // Load test data from JSON file
        var jsonPath = Path.Combine(TestContext.CurrentContext.TestDirectory, "TestData", "Traces", "scp02_CLR.json");
        var jsonContent = File.ReadAllText(jsonPath);
        var testData = JsonDocument.Parse(jsonContent);
        
        // Extract values using JSON path
        var staticKeys = Convert.FromHexString(testData.RootElement.GetProperty("metadata").GetProperty("hints").GetProperty("static_keys").GetString()!);
        var session = testData.RootElement.GetProperty("sessions").GetProperty("session_1");
        var hostChallenge = Convert.FromHexString(session.GetProperty("host_challenge").GetString()!);
        var cardChallenge = Convert.FromHexString(session.GetProperty("card_challenge").GetString()!);
        var sequenceCounter = Convert.FromHexString(session.GetProperty("sequence_counter").GetString()!);
        
        // Extract expected session keys from JSON
        var expectedKeys = testData.RootElement.GetProperty("metadata").GetProperty("hints").GetProperty("expected_session_keys");
        var expectedSEnc = Convert.FromHexString(expectedKeys.GetProperty("s_enc").GetString()!);
        var expectedSMac = Convert.FromHexString(expectedKeys.GetProperty("s_mac").GetString()!);
        
        // Create SCP02 key set
        var keySetResult = Scp02KeySet.Create(staticKeys, staticKeys, staticKeys, 0x01);
        _ = keySetResult.IsSuccess.Should().BeTrue();
        
        // Derive session keys with i=00 implementation
        var sessionKeysResult = _keyDerivationService.DeriveSessionKeys(
            keySetResult.Value,
            hostChallenge,
            cardChallenge,
            Maybe<byte[]>.From(sequenceCounter),
            Maybe<ScpImplementation>.From(ScpImplementation.Scp02I00));

        _ = sessionKeysResult.IsSuccess.Should().BeTrue();
        var sessionKeys = sessionKeysResult.Value;

        // Verify that i=00 uses derived MAC keys, not static MAC keys
        _ = sessionKeys.SEnc.Should().BeEquivalentTo(expectedSEnc, "S-ENC key should match GP Pro trace");
        _ = sessionKeys.SMac.Should().BeEquivalentTo(expectedSMac, "S-MAC key should be derived, not static");

        // Verify MAC key is derived (different from static key)
        _ = sessionKeys.SMac.Should().NotBeEquivalentTo(staticKeys, "MAC key should be derived, not static");
        
        TestContext.Out.WriteLine($"Implementation i=00 correctly uses derived MAC keys");
        TestContext.Out.WriteLine($"Static MAC: {Convert.ToHexString(staticKeys)}");
        TestContext.Out.WriteLine($"Derived S-MAC: {Convert.ToHexString(sessionKeys.SMac)}");
    }
    
    [Test]
    public void Scp02_I15_Should_Use_Static_Mac_Keys()
    {
        // Test that i=15 uses static MAC keys (the exception case)
        var staticKeys = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var hostChallenge = Convert.FromHexString("719426F20E234840");
        var cardChallenge = Convert.FromHexString("C284EC19415D");
        var sequenceCounter = Convert.FromHexString("0011");
        
        // Create SCP02 key set
        var keySetResult = Scp02KeySet.Create(staticKeys, staticKeys, staticKeys, 0x01);
        _ = keySetResult.IsSuccess.Should().BeTrue();
        
        // Derive session keys with i=15 implementation
        var sessionKeysResult = _keyDerivationService.DeriveSessionKeys(
            keySetResult.Value,
            hostChallenge,
            cardChallenge,
            Maybe<byte[]>.From(sequenceCounter),
            Maybe<ScpImplementation>.From(ScpImplementation.Scp02I15));

        _ = sessionKeysResult.IsSuccess.Should().BeTrue();
        var sessionKeys = sessionKeysResult.Value;

        // For i=15, MAC key should remain static (same as input)
        _ = sessionKeys.SMac.Should().BeEquivalentTo(staticKeys, "i=15 should use static MAC keys");

        // But S-ENC should still be derived
        _ = sessionKeys.SEnc.Should().NotBeEquivalentTo(staticKeys, "S-ENC should always be derived");
        
        TestContext.Out.WriteLine($"Implementation i=15 correctly uses static MAC keys");
        TestContext.Out.WriteLine($"Static MAC: {Convert.ToHexString(staticKeys)}");
        TestContext.Out.WriteLine($"S-MAC (static): {Convert.ToHexString(sessionKeys.SMac)}");
    }
    
    [TestCase(ScpImplementation.Scp02I00, true, "i=00 should derive MAC keys")]
    [TestCase(ScpImplementation.Scp02I02, true, "i=02 should derive MAC keys")]
    [TestCase(ScpImplementation.Scp02I04, true, "i=04 should derive MAC keys")]
    [TestCase(ScpImplementation.Scp02I05, true, "i=05 should derive MAC keys")]
    [TestCase(ScpImplementation.Scp02I15, false, "i=15 should use static MAC keys")]
    [TestCase(ScpImplementation.Scp02I35, true, "i=35 should derive MAC keys")]
    [TestCase(ScpImplementation.Scp02I55, true, "i=55 should derive MAC keys")]
    [TestCase(ScpImplementation.Scp02I75, true, "i=75 should derive MAC keys")]
    public void Scp02_Implementation_MAC_Key_Behavior(ScpImplementation implementation, bool shouldDeriveMac, string description)
    {
        // Test various SCP02 implementations to ensure correct MAC key behavior
        var staticKeys = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var hostChallenge = Convert.FromHexString("719426F20E234840");
        var cardChallenge = Convert.FromHexString("C284EC19415D");
        var sequenceCounter = Convert.FromHexString("0011");
        
        var keySetResult = Scp02KeySet.Create(staticKeys, staticKeys, staticKeys, 0x01);
        _ = keySetResult.IsSuccess.Should().BeTrue();
        
        var sessionKeysResult = _keyDerivationService.DeriveSessionKeys(
            keySetResult.Value,
            hostChallenge,
            cardChallenge,
            Maybe<byte[]>.From(sequenceCounter),
            Maybe<ScpImplementation>.From(implementation));

        _ = sessionKeysResult.IsSuccess.Should().BeTrue();
        var sessionKeys = sessionKeysResult.Value;
        
        if (shouldDeriveMac)
        {
            _ = sessionKeys.SMac.Should().NotBeEquivalentTo(staticKeys, description);
        }
        else
        {
            _ = sessionKeys.SMac.Should().BeEquivalentTo(staticKeys, description);
        }

        // S-ENC should always be derived regardless of implementation
        _ = sessionKeys.SEnc.Should().NotBeEquivalentTo(staticKeys, "S-ENC should always be derived");
        
        TestContext.Out.WriteLine($"{implementation} ({(byte)implementation:X2}): MAC derived = {shouldDeriveMac}");
    }
}