using System;
using System.IO;
using System.Text.Json;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Domain.Security;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Security;

/// <summary>
/// Isolated functional test for SCP02 cryptogram calculation using exact data from JSON.
/// This test runs each step in isolation to identify where calculations diverge.
/// </summary>
[TestFixture]
[Category("Unit")]
public class IsolatedScp02CryptogramTest
{
    [Test]
    public void SCP02_Cryptogram_Should_Match_Real_Card_Response()
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
        var actualCardCryptogram = Convert.FromHexString(session.GetProperty("card_cryptogram").GetString()!);

        // From the INITIALIZE UPDATE response parsing:
        // Key version: 0x01, SCP ID: 0x02, i parameter: 0x00
        byte keyVersion = 0x01;
        byte implementationParameter = 0x00; // i=00

        TestContext.Out.WriteLine("=== Test Data ===");
        TestContext.Out.WriteLine($"Static Keys: {Convert.ToHexString(staticKeys)}");
        TestContext.Out.WriteLine($"Host Challenge: {Convert.ToHexString(hostChallenge)}");
        TestContext.Out.WriteLine($"Card Challenge: {Convert.ToHexString(cardChallenge)}");
        TestContext.Out.WriteLine($"Sequence Counter: {Convert.ToHexString(sequenceCounter)}");
        TestContext.Out.WriteLine($"Implementation: i={implementationParameter:X2}");
        TestContext.Out.WriteLine($"Actual Card Cryptogram: {Convert.ToHexString(actualCardCryptogram)}");

        // Step 2: Create key set
        var keySetResult = Scp02KeySet.Create(staticKeys, staticKeys, staticKeys, keyVersion);
        _ = keySetResult.IsSuccess.Should().BeTrue();

        // Step 3: Derive session keys using pure function
        TestContext.Out.WriteLine("\n=== Session Key Derivation ===");
        var sessionKeysResult = Scp02ProtocolImpl.DeriveSessionKeys(
            keySetResult.Value,
            hostChallenge,
            cardChallenge,
            sequenceCounter,
            implementationParameter
        );

        _ = sessionKeysResult.IsSuccess.Should().BeTrue();
        var sessionKeys = sessionKeysResult.Value;

        TestContext.Out.WriteLine($"S-ENC: {Convert.ToHexString(sessionKeys.SEnc)}");
        TestContext.Out.WriteLine($"S-MAC: {Convert.ToHexString(sessionKeys.SMac)}");
        TestContext.Out.WriteLine($"S-RMAC: {Convert.ToHexString(sessionKeys.SrMac)}");
        TestContext.Out.WriteLine($"DEK: {Convert.ToHexString(sessionKeys.Dek)}");

        // Verify against expected session keys from JSON hints
        var expectedKeys = testData.RootElement.GetProperty("metadata").GetProperty("hints").GetProperty("expected_session_keys");
        var expectedSEnc = Convert.FromHexString(expectedKeys.GetProperty("s_enc").GetString()!);
        var expectedSMac = Convert.FromHexString(expectedKeys.GetProperty("s_mac").GetString()!);

        _ = sessionKeys.SEnc.Should().BeEquivalentTo(expectedSEnc, "S-ENC key should match expected");
        _ = sessionKeys.SMac.Should().BeEquivalentTo(expectedSMac, "S-MAC key should match expected");

        // Step 4: Build cryptogram data
        TestContext.Out.WriteLine("\n=== Cryptogram Calculation ===");
        var cryptogramData = new byte[24];
        Array.Copy(hostChallenge, 0, cryptogramData, 0, 8);
        Array.Copy(sequenceCounter, 0, cryptogramData, 8, 2);
        Array.Copy(cardChallenge, 0, cryptogramData, 10, 6);
        cryptogramData[16] = 0x80; // ISO 7816-4 padding

        TestContext.Out.WriteLine($"Cryptogram Data: {Convert.ToHexString(cryptogramData)}");

        // Step 5: Calculate cryptogram using S-ENC key
        var cryptogramResult = Scp02ProtocolImpl.CalculateCryptogramMac(sessionKeys.SEnc, cryptogramData);
        _ = cryptogramResult.IsSuccess.Should().BeTrue();

        var calculatedCryptogram = cryptogramResult.Value;
        TestContext.Out.WriteLine($"Calculated Cryptogram: {Convert.ToHexString(calculatedCryptogram)}");
        TestContext.Out.WriteLine($"Actual Card Cryptogram: {Convert.ToHexString(actualCardCryptogram)}");

        // This should match the actual card cryptogram
        _ = calculatedCryptogram.Should().BeEquivalentTo(actualCardCryptogram,
            "Calculated cryptogram should match actual card response");
    }

    [Test]
    public void SCP02_Cryptogram_Step_By_Step_Debug()
    {
        // Load test data from JSON file
        var jsonPath = Path.Combine(TestContext.CurrentContext.TestDirectory, "TestData", "Traces", "scp02_CLR.json");
        var jsonContent = File.ReadAllText(jsonPath);
        var testData = JsonDocument.Parse(jsonContent);

        var staticKey = Convert.FromHexString(testData.RootElement.GetProperty("metadata").GetProperty("hints").GetProperty("static_keys").GetString()!);
        var session = testData.RootElement.GetProperty("sessions").GetProperty("session_1");
        var hostChallenge = Convert.FromHexString(session.GetProperty("host_challenge").GetString()!);
        var sequenceCounter = Convert.FromHexString(session.GetProperty("sequence_counter").GetString()!);

        TestContext.Out.WriteLine("=== Step by Step Debugging ===");

        // Test S-ENC key derivation
        var sEncDerivationData = new byte[16];
        sEncDerivationData[0] = 0x01; // Derivation constant high byte
        sEncDerivationData[1] = 0x82; // Derivation constant low byte (S-ENC)
        Array.Copy(sequenceCounter, 0, sEncDerivationData, 2, 2);
        Array.Copy(hostChallenge, 0, sEncDerivationData, 4, 8);
        // Remaining 4 bytes are zeros (padding)

        TestContext.Out.WriteLine($"S-ENC Derivation Data: {Convert.ToHexString(sEncDerivationData)}");

        // For i=00 with b1=0 (base key mode), ENC key derivation uses ENC base key
        // Use the SCP02 key derivation method directly
        var sEncResult = Scp02Cryptography.DeriveScp02SessionKey(
            staticKey,
            [0x01, 0x82], // S-ENC constant
            sequenceCounter
        );
        _ = sEncResult.IsSuccess.Should().BeTrue();

        TestContext.Out.WriteLine($"Derived S-ENC: {Convert.ToHexString(sEncResult.Value)}");

        // Test cryptogram with known S-ENC from JSON
        var expectedKeys = testData.RootElement.GetProperty("metadata").GetProperty("hints").GetProperty("expected_session_keys");
        var knownSEnc = Convert.FromHexString(expectedKeys.GetProperty("s_enc").GetString()!);
        var cardChallenge = Convert.FromHexString(session.GetProperty("card_challenge").GetString()!);

        var cryptogramData = new byte[24];
        Array.Copy(hostChallenge, 0, cryptogramData, 0, 8);
        Array.Copy(sequenceCounter, 0, cryptogramData, 8, 2);
        Array.Copy(cardChallenge, 0, cryptogramData, 10, 6);
        cryptogramData[16] = 0x80;

        TestContext.Out.WriteLine($"Cryptogram Data: {Convert.ToHexString(cryptogramData)}");

        // Calculate using known good S-ENC
        var cryptogramResult = CryptographicOperations.CalculateFull3DesMac(knownSEnc, cryptogramData);
        _ = cryptogramResult.IsSuccess.Should().BeTrue();

        TestContext.Out.WriteLine($"Cryptogram with known S-ENC: {Convert.ToHexString(cryptogramResult.Value)}");
        TestContext.Out.WriteLine($"Expected from card: {session.GetProperty("card_cryptogram").GetString()}");
    }
}
