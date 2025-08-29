using System;
using System.IO;
using System.Text.Json;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
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
        string jsonPath = Path.Combine(TestContext.CurrentContext.TestDirectory, "TestData", "Traces", "Protocol", "SCP02", "gp_pro_scp02_clr.json");
        string jsonContent = File.ReadAllText(jsonPath);
        JsonDocument testData = JsonDocument.Parse(jsonContent);

        // Extract values using JSON path
        byte[] staticKeys = Convert.FromHexString(testData.RootElement.GetProperty("metadata").GetProperty("hints").GetProperty("static_keys").GetString()!);
        JsonElement session = testData.RootElement.GetProperty("sessions").GetProperty("session_1");
        byte[] hostChallenge = Convert.FromHexString(session.GetProperty("host_challenge").GetString()!);
        byte[] cardChallenge = Convert.FromHexString(session.GetProperty("card_challenge").GetString()!);
        byte[] sequenceCounter = Convert.FromHexString(session.GetProperty("sequence_counter").GetString()!);

        // Extract expected session keys from JSON
        JsonElement expectedKeys = testData.RootElement.GetProperty("metadata").GetProperty("hints").GetProperty("expected_session_keys");
        byte[] expectedSEnc = Convert.FromHexString(expectedKeys.GetProperty("s_enc").GetString()!);
        byte[] expectedSMac = Convert.FromHexString(expectedKeys.GetProperty("s_mac").GetString()!);

        // Create SCP02 key set
        Result<Scp02KeySet, SmartCardError> keySetResult = Scp02KeySet.Create(staticKeys, staticKeys, staticKeys, 0x01);
        _ = keySetResult.IsSuccess.Should().BeTrue();

        // Derive session keys with i=00 implementation
        Result<SessionKeys, SmartCardError> sessionKeysResult = _keyDerivationService.DeriveSessionKeys(
            keySetResult.Value,
            hostChallenge,
            cardChallenge,
            Maybe<byte[]>.From(sequenceCounter),
            Maybe<ScpImplementation>.From(ScpImplementation.Scp02I00));

        _ = sessionKeysResult.IsSuccess.Should().BeTrue();
        SessionKeys? sessionKeys = sessionKeysResult.Value;

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
    public void Scp02_I15_Should_Use_Derived_Mac_Keys()
    {
        // Test that i=15 derives MAC keys per GP Card Specification Section E.4.1 and live card trace data
        // All SCP02 implementations derive MAC keys from static keys using constant 0x0101
        byte[] staticKeys = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        byte[] hostChallenge = Convert.FromHexString("719426F20E234840");
        byte[] cardChallenge = Convert.FromHexString("C284EC19415D");
        byte[] sequenceCounter = Convert.FromHexString("0011");

        // Expected session MAC key from live trace data (CLR mode i=15)
        byte[] expectedSMac = Convert.FromHexString("0D446132B168F75CD6F0A780693A4DD3");

        // Create SCP02 key set
        Result<Scp02KeySet, SmartCardError> keySetResult = Scp02KeySet.Create(staticKeys, staticKeys, staticKeys, 0x01);
        _ = keySetResult.IsSuccess.Should().BeTrue();

        // Derive session keys with i=15 implementation
        Result<SessionKeys, SmartCardError> sessionKeysResult = _keyDerivationService.DeriveSessionKeys(
            keySetResult.Value,
            hostChallenge,
            cardChallenge,
            Maybe<byte[]>.From(sequenceCounter),
            Maybe<ScpImplementation>.From(ScpImplementation.Scp02I15));

        _ = sessionKeysResult.IsSuccess.Should().BeTrue();
        SessionKeys? sessionKeys = sessionKeysResult.Value;

        // For i=15, MAC key should be derived per GP Card Spec Section E.4.1 and live trace data
        _ = sessionKeys.SMac.Should().BeEquivalentTo(expectedSMac, "i=15 should derive MAC keys per GP Card Spec Section E.4.1 and live trace data");
        _ = sessionKeys.SMac.Should().NotBeEquivalentTo(staticKeys, "i=15 should not use static MAC keys");

        // S-ENC should always be derived
        _ = sessionKeys.SEnc.Should().NotBeEquivalentTo(staticKeys, "S-ENC should always be derived");

        TestContext.Out.WriteLine($"Implementation i=15 correctly derives MAC keys");
        TestContext.Out.WriteLine($"Static MAC: {Convert.ToHexString(staticKeys)}");
        TestContext.Out.WriteLine($"S-MAC (derived): {Convert.ToHexString(sessionKeys.SMac)}");
    }

    [TestCase(ScpImplementation.Scp02I00, true, "i=00 should derive MAC keys")]
    [TestCase(ScpImplementation.Scp02I02, true, "i=02 should derive MAC keys")]
    [TestCase(ScpImplementation.Scp02I04, true, "i=04 should derive MAC keys")]
    [TestCase(ScpImplementation.Scp02I05, true, "i=05 should derive MAC keys")]
    [TestCase(ScpImplementation.Scp02I15, true, "i=15 should derive MAC keys per GP Card Spec Section E.4.1 and live trace data")]
    [TestCase(ScpImplementation.Scp02I35, true, "i=35 should derive MAC keys")]
    [TestCase(ScpImplementation.Scp02I55, true, "i=55 should derive MAC keys")]
    [TestCase(ScpImplementation.Scp02I75, true, "i=75 should derive MAC keys")]
    public void Scp02_Implementation_MAC_Key_Behavior(ScpImplementation implementation, bool shouldDeriveMac, string description)
    {
        // Test various SCP02 implementations to ensure correct MAC key behavior
        byte[] staticKeys = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        byte[] hostChallenge = Convert.FromHexString("719426F20E234840");
        byte[] cardChallenge = Convert.FromHexString("C284EC19415D");
        byte[] sequenceCounter = Convert.FromHexString("0011");

        Result<Scp02KeySet, SmartCardError> keySetResult = Scp02KeySet.Create(staticKeys, staticKeys, staticKeys, 0x01);
        _ = keySetResult.IsSuccess.Should().BeTrue();

        Result<SessionKeys, SmartCardError> sessionKeysResult = _keyDerivationService.DeriveSessionKeys(
            keySetResult.Value,
            hostChallenge,
            cardChallenge,
            Maybe<byte[]>.From(sequenceCounter),
            Maybe<ScpImplementation>.From(implementation));

        _ = sessionKeysResult.IsSuccess.Should().BeTrue();
        SessionKeys? sessionKeys = sessionKeysResult.Value;

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