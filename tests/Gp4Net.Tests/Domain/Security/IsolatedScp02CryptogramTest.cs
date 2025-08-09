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
        
        TestContext.WriteLine("=== Test Data ===");
        TestContext.WriteLine($"Static Keys: {Convert.ToHexString(staticKeys)}");
        TestContext.WriteLine($"Host Challenge: {Convert.ToHexString(hostChallenge)}");
        TestContext.WriteLine($"Card Challenge: {Convert.ToHexString(cardChallenge)}");
        TestContext.WriteLine($"Sequence Counter: {Convert.ToHexString(sequenceCounter)}");
        TestContext.WriteLine($"Implementation: i={implementationParameter:X2}");
        TestContext.WriteLine($"Actual Card Cryptogram: {Convert.ToHexString(actualCardCryptogram)}");
        
        // Step 2: Create key set
        var keySetResult = Scp02KeySet.Create(staticKeys, staticKeys, staticKeys, keyVersion);
        keySetResult.IsSuccess.Should().BeTrue();
        
        // Step 3: Derive session keys using pure function
        TestContext.WriteLine("\n=== Session Key Derivation ===");
        var sessionKeysResult = Scp02ProtocolImpl.DeriveSessionKeys(
            keySetResult.Value,
            hostChallenge,
            cardChallenge,
            sequenceCounter,
            implementationParameter
        );
        
        sessionKeysResult.IsSuccess.Should().BeTrue();
        var sessionKeys = sessionKeysResult.Value;
        
        TestContext.WriteLine($"S-ENC: {Convert.ToHexString(sessionKeys.SEnc)}");
        TestContext.WriteLine($"S-MAC: {Convert.ToHexString(sessionKeys.SMac)}");
        TestContext.WriteLine($"S-RMAC: {Convert.ToHexString(sessionKeys.SrMac)}");
        TestContext.WriteLine($"DEK: {Convert.ToHexString(sessionKeys.Dek)}");
        
        // Verify against expected session keys from JSON hints
        var expectedKeys = testData.RootElement.GetProperty("metadata").GetProperty("hints").GetProperty("expected_session_keys");
        var expectedSEnc = Convert.FromHexString(expectedKeys.GetProperty("s_enc").GetString()!);
        var expectedSMac = Convert.FromHexString(expectedKeys.GetProperty("s_mac").GetString()!);
        
        sessionKeys.SEnc.Should().BeEquivalentTo(expectedSEnc, "S-ENC key should match expected");
        sessionKeys.SMac.Should().BeEquivalentTo(expectedSMac, "S-MAC key should match expected");
        
        // Step 4: Build cryptogram data
        TestContext.WriteLine("\n=== Cryptogram Calculation ===");
        var cryptogramData = new byte[24];
        Array.Copy(hostChallenge, 0, cryptogramData, 0, 8);
        Array.Copy(sequenceCounter, 0, cryptogramData, 8, 2);
        Array.Copy(cardChallenge, 0, cryptogramData, 10, 6);
        cryptogramData[16] = 0x80; // ISO 7816-4 padding
        
        TestContext.WriteLine($"Cryptogram Data: {Convert.ToHexString(cryptogramData)}");
        
        // Step 5: Calculate cryptogram using S-ENC key
        var cryptogramResult = Scp02ProtocolImpl.CalculateCryptogramMac(sessionKeys.SEnc, cryptogramData);
        cryptogramResult.IsSuccess.Should().BeTrue();
        
        var calculatedCryptogram = cryptogramResult.Value;
        TestContext.WriteLine($"Calculated Cryptogram: {Convert.ToHexString(calculatedCryptogram)}");
        TestContext.WriteLine($"Actual Card Cryptogram: {Convert.ToHexString(actualCardCryptogram)}");
        
        // This should match the actual card cryptogram
        calculatedCryptogram.Should().BeEquivalentTo(actualCardCryptogram,
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
        
        TestContext.WriteLine("=== Step by Step Debugging ===");
        
        // Test S-ENC key derivation
        var sEncDerivationData = new byte[16];
        sEncDerivationData[0] = 0x01; // Derivation constant high byte
        sEncDerivationData[1] = 0x82; // Derivation constant low byte (S-ENC)
        Array.Copy(sequenceCounter, 0, sEncDerivationData, 2, 2);
        Array.Copy(hostChallenge, 0, sEncDerivationData, 4, 8);
        // Remaining 4 bytes are zeros (padding)
        
        TestContext.WriteLine($"S-ENC Derivation Data: {Convert.ToHexString(sEncDerivationData)}");
        
        // For i=00 with b1=0 (base key mode), ENC key derivation uses ENC base key
        // Use the SCP02 key derivation method directly
        var sEncResult = Scp02Cryptography.DeriveScp02SessionKey(
            staticKey, 
            new byte[] { 0x01, 0x82 }, // S-ENC constant
            sequenceCounter
        );
        sEncResult.IsSuccess.Should().BeTrue();
        
        TestContext.WriteLine($"Derived S-ENC: {Convert.ToHexString(sEncResult.Value)}");
        
        // Test cryptogram with known S-ENC from JSON
        var expectedKeys = testData.RootElement.GetProperty("metadata").GetProperty("hints").GetProperty("expected_session_keys");
        var knownSEnc = Convert.FromHexString(expectedKeys.GetProperty("s_enc").GetString()!);
        var cardChallenge = Convert.FromHexString(session.GetProperty("card_challenge").GetString()!);
        
        var cryptogramData = new byte[24];
        Array.Copy(hostChallenge, 0, cryptogramData, 0, 8);
        Array.Copy(sequenceCounter, 0, cryptogramData, 8, 2);
        Array.Copy(cardChallenge, 0, cryptogramData, 10, 6);
        cryptogramData[16] = 0x80;
        
        TestContext.WriteLine($"Cryptogram Data: {Convert.ToHexString(cryptogramData)}");
        
        // Calculate using known good S-ENC
        var cryptogramResult = CryptographicOperations.CalculateFull3DesMac(knownSEnc, cryptogramData);
        cryptogramResult.IsSuccess.Should().BeTrue();
        
        TestContext.WriteLine($"Cryptogram with known S-ENC: {Convert.ToHexString(cryptogramResult.Value)}");
        TestContext.WriteLine($"Expected from card: {session.GetProperty("card_cryptogram").GetString()}");
    }
}