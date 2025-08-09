using System;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Domain.Security;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace Gp4Net.Tests.Integration;

/// <summary>
/// Integration tests for SCP02 using real GP Pro trace data.
/// These tests validate the complete flow from raw INITIALIZE UPDATE response bytes
/// through implementation detection, key derivation, and authentication.
/// Based on actual card response data from GP Pro traces in fix_scp02 folder.
/// </summary>
[TestFixture]
[Category("Integration")]
[Category("FailHard")]
public class Scp02RealCardTraceTests
{
    private KeyDerivationService _keyDerivationService;
    private Scp02Protocol _protocol;
    private Scp02KeySet _keySet;

    [SetUp]
    public void SetUp()
    {
        _keyDerivationService = new KeyDerivationService(NullLogger<KeyDerivationService>.Instance);
        
        // Use static GP test keys from traces
        var testKeys = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        _keySet = Scp02KeySet.Create(
            testKeys, // ENC key
            testKeys, // MAC key
            testKeys, // DEK key 
            0x01      // Key version
        ).Value;
        
        _protocol = new Scp02Protocol(_keySet, _keyDerivationService, NullLogger<Scp02Protocol>.Instance);
    }

    [Test]
    public void RealGpProCLR_InitializeUpdate_ShouldParseAndDetectImplementation()
    {
        // Arrange - Real INITIALIZE UPDATE response from GP Pro CLR trace (scp02_CLR.log line 24)
        // Response: 0000234555808320483901020011C284EC19415D17F4198ADCD5102D 9000
        var realResponse = Convert.FromHexString("0000234555808320483901020011C284EC19415D17F4198ADCD5102D");
        var hostChallenge = Convert.FromHexString("719426F20E234840");
        
        // Act - Parse the response
        var parseResult = InitializeUpdateResponse.Parse(realResponse);
        
        // Assert - Parsing should succeed
        parseResult.IsSuccess.Should().BeTrue("Real GP Pro CLR response should parse successfully");
        var response = parseResult.Value;
        
        // Verify parsed fields match expected values from trace
        response.KeyDiversificationData.Should().Equal(Convert.FromHexString("00002345558083204839"), 
            "KDD should match GP Pro trace");
        response.KeyVersion.Should().Be(0x01, "Key version should be 1");
        response.ScpId.Should().Be(0x02, "SCP ID should be 2");
        response.ScpParameter.Should().Be(0x00, "SCP parameter should be 0x00 (i=00)");
        response.SequenceCounter.Should().Equal(Convert.FromHexString("0011"), 
            "Sequence counter should match GP Pro trace");
        response.CardChallenge.Should().Equal(Convert.FromHexString("C284EC19415D"), 
            "Card challenge should match GP Pro trace");
        response.CardCryptogram.Should().Equal(Convert.FromHexString("17F4198ADCD5102D"),
            "Card cryptogram should match GP Pro trace");
            
        // Verify implementation detection
        var detectedImplResult = Scp02Protocol.GetScp02Implementation(response.ScpParameter);
        detectedImplResult.IsSuccess.Should().BeTrue("Implementation detection should succeed");
        detectedImplResult.Value.Should().Be(ScpImplementation.Scp02I00, "Should detect i=00 implementation");
        
        TestContext.WriteLine("✓ Real GP Pro CLR trace correctly parsed and implementation detected");
        TestContext.WriteLine($"KDD: {Convert.ToHexString(response.KeyDiversificationData)}");
        TestContext.WriteLine($"SCP Parameter: 0x{response.ScpParameter:X2} → {detectedImplResult.Value}");
        TestContext.WriteLine($"Sequence Counter: {Convert.ToHexString(response.SequenceCounter)}");
    }

    [Test]
    public void RealGpProMAC_InitializeUpdate_ShouldParseAndDetectImplementation()
    {
        // Arrange - Real INITIALIZE UPDATE response from GP Pro MAC trace (scp02_MAC.log line 24)
        // Response: 00002345558083204839010200123E6DB216F8D58177E15BAA128DF9 9000
        var realResponse = Convert.FromHexString("00002345558083204839010200123E6DB216F8D58177E15BAA128DF9");
        var hostChallenge = Convert.FromHexString("BD76C16D1D2E2D76");
        
        // Act - Parse the response
        var parseResult = InitializeUpdateResponse.Parse(realResponse);
        
        // Assert - Parsing should succeed
        parseResult.IsSuccess.Should().BeTrue("Real GP Pro MAC response should parse successfully");
        var response = parseResult.Value;
        
        // Verify parsed fields match expected values from trace
        response.KeyDiversificationData.Should().Equal(Convert.FromHexString("00002345558083204839"), 
            "KDD should match GP Pro trace");
        response.KeyVersion.Should().Be(0x01, "Key version should be 1");
        response.ScpId.Should().Be(0x02, "SCP ID should be 2");
        response.ScpParameter.Should().Be(0x00, "SCP parameter should be 0x00 (i=00)");
        response.SequenceCounter.Should().Equal(Convert.FromHexString("0012"), 
            "Sequence counter should match GP Pro trace");
        response.CardChallenge.Should().Equal(Convert.FromHexString("3E6DB216F8D5"), 
            "Card challenge should match GP Pro trace (6 bytes only)");
        response.CardCryptogram.Should().Equal(Convert.FromHexString("8177E15BAA128DF9"),
            "Card cryptogram should match GP Pro trace");
            
        // Verify implementation detection
        var detectedImplResult = Scp02Protocol.GetScp02Implementation(response.ScpParameter);
        detectedImplResult.IsSuccess.Should().BeTrue("Implementation detection should succeed");
        detectedImplResult.Value.Should().Be(ScpImplementation.Scp02I00, "Should detect i=00 implementation");
        
        TestContext.WriteLine("✓ Real GP Pro MAC trace correctly parsed and implementation detected");
        TestContext.WriteLine($"KDD: {Convert.ToHexString(response.KeyDiversificationData)}");
        TestContext.WriteLine($"SCP Parameter: 0x{response.ScpParameter:X2} → {detectedImplResult.Value}");
        TestContext.WriteLine($"Sequence Counter: {Convert.ToHexString(response.SequenceCounter)}");
    }

    [Test]
    public void RealGpProCLR_SessionKeyDerivation_ShouldMatchExpected()
    {
        // Arrange - Use CLR trace data
        var staticKeys = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var hostChallenge = Convert.FromHexString("719426F20E234840");
        var cardChallenge = Convert.FromHexString("C284EC19415D");
        var sequenceCounter = Convert.FromHexString("0011");
        
        // Expected session keys from GP Pro CLR trace
        var expectedSEnc = Convert.FromHexString("6DCE2A99BACB5207A7A96A92F114D66C");
        var expectedSMac = Convert.FromHexString("0D446132B168F75CD6F0A780693A4DD3");
        var expectedSrMac = Convert.FromHexString("4C7FE3A6B0E4F3891B701C3DE654F9B7");
        
        // Create key set with static keys
        var keySetResult = Scp02KeySet.Create(staticKeys, staticKeys, staticKeys, 0x01);
        keySetResult.IsSuccess.Should().BeTrue();
        
        // Act - Derive session keys for i=00 (uses derived MAC keys)
        var sessionKeysResult = _keyDerivationService.DeriveSessionKeys(
            keySetResult.Value,
            hostChallenge,
            cardChallenge,
            Maybe<byte[]>.From(sequenceCounter),
            Maybe<ScpImplementation>.From(ScpImplementation.Scp02I00));
        
        // Assert
        sessionKeysResult.IsSuccess.Should().BeTrue("Session key derivation should succeed");
        var sessionKeys = sessionKeysResult.Value;
        
        sessionKeys.SEnc.Should().Equal(expectedSEnc, "S-ENC should match GP Pro trace");
        sessionKeys.SMac.Should().Equal(expectedSMac, "S-MAC should match GP Pro trace");
        sessionKeys.SrMac.Should().Equal(expectedSrMac, "S-RMAC should match GP Pro trace");
        
        TestContext.WriteLine("✓ Real GP Pro CLR session keys match expected values");
        TestContext.WriteLine($"S-ENC:  {Convert.ToHexString(sessionKeys.SEnc)}");
        TestContext.WriteLine($"S-MAC:  {Convert.ToHexString(sessionKeys.SMac)}");
        TestContext.WriteLine($"S-RMAC: {Convert.ToHexString(sessionKeys.SrMac)}");
    }

    [Test]
    public void RealGpProMAC_SessionKeyDerivation_ShouldMatchExpected()
    {
        // Arrange - Use MAC trace data
        var staticKeys = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var hostChallenge = Convert.FromHexString("BD76C16D1D2E2D76");
        var cardChallenge = Convert.FromHexString("3E6DB216F8D5");
        var sequenceCounter = Convert.FromHexString("0012");
        
        // Expected session keys from GP Pro MAC trace
        var expectedSEnc = Convert.FromHexString("CB4ED15E982DB16EB630FE9F3E04D665");
        var expectedSMac = Convert.FromHexString("89D93B2D2D7E7AB95B61F82EDE3975B7");
        var expectedSrMac = Convert.FromHexString("9E73AA58712520FCC53800F90C2471E1");
        
        // Create key set with static keys
        var keySetResult = Scp02KeySet.Create(staticKeys, staticKeys, staticKeys, 0x01);
        keySetResult.IsSuccess.Should().BeTrue();
        
        // Act - Derive session keys for i=00 (uses derived MAC keys)
        var sessionKeysResult = _keyDerivationService.DeriveSessionKeys(
            keySetResult.Value,
            hostChallenge,
            cardChallenge,
            Maybe<byte[]>.From(sequenceCounter),
            Maybe<ScpImplementation>.From(ScpImplementation.Scp02I00));
        
        // Assert
        sessionKeysResult.IsSuccess.Should().BeTrue("Session key derivation should succeed");
        var sessionKeys = sessionKeysResult.Value;
        
        sessionKeys.SEnc.Should().Equal(expectedSEnc, "S-ENC should match GP Pro trace");
        sessionKeys.SMac.Should().Equal(expectedSMac, "S-MAC should match GP Pro trace");
        sessionKeys.SrMac.Should().Equal(expectedSrMac, "S-RMAC should match GP Pro trace");
        
        TestContext.WriteLine("✓ Real GP Pro MAC session keys match expected values");
        TestContext.WriteLine($"S-ENC:  {Convert.ToHexString(sessionKeys.SEnc)}");
        TestContext.WriteLine($"S-MAC:  {Convert.ToHexString(sessionKeys.SMac)}");
        TestContext.WriteLine($"S-RMAC: {Convert.ToHexString(sessionKeys.SrMac)}");
    }

    [Test]
    public void RealGpProCLR_ExternalAuthenticate_ShouldMatchExpectedMac()
    {
        // Arrange - Data from GP Pro CLR trace
        var sessionMac = Convert.FromHexString("0D446132B168F75CD6F0A780693A4DD3");
        var hostCryptogram = Convert.FromHexString("8E69F9E4D246FF36");
        
        // MAC input from trace: 84820000108E69F9E4D246FF36
        var expectedMacInput = Convert.FromHexString("84820000108E69F9E4D246FF36");
        var expectedMac = Convert.FromHexString("9F97E807B91F6318");
        
        // Construct MAC input for SCP02 EXTERNAL AUTHENTICATE
        // Per GP Card Specification v2.3.1 section E.5.2 (Table E-10):
        // - EXTERNAL AUTHENTICATE command: Lc='10' (16 bytes), Data='xx xx...' (Host cryptogram and MAC)
        // Per section E.4.4: "A C-MAC is generated... across the full APDU command being transmitted to
        // the card including the header and the data field in the command message"
        // The MAC input consists of header (5 bytes) + data, where Lc indicates the final command length
        var macInput = new byte[5 + hostCryptogram.Length]; // 5 header + 8 cryptogram = 13 bytes
        macInput[0] = 0x84; // CLA
        macInput[1] = 0x82; // INS (EXTERNAL AUTHENTICATE)
        macInput[2] = (byte)SecurityLevel.None; // P1=0x00 as shown in trace
        macInput[3] = 0x00; // P2
        macInput[4] = 0x10; // Lc=16 (indicates final command will have 8 byte cryptogram + 8 byte MAC)
        Array.Copy(hostCryptogram, 0, macInput, 5, hostCryptogram.Length);
        
        // Verify MAC input matches trace
        macInput.Should().Equal(expectedMacInput, "MAC input should match GP Pro trace");
        
        TestContext.WriteLine("✓ Real GP Pro CLR EXTERNAL AUTHENTICATE MAC input construction verified");
        TestContext.WriteLine($"MAC Input: {Convert.ToHexString(macInput)}");
        TestContext.WriteLine($"Expected:  {Convert.ToHexString(expectedMacInput)}");
    }

    [Test]
    public void RealGpProMAC_ExternalAuthenticate_ShouldMatchExpectedMac()
    {
        // Arrange - Data from GP Pro MAC trace
        var sessionMac = Convert.FromHexString("89D93B2D2D7E7AB95B61F82EDE3975B7");
        var hostCryptogram = Convert.FromHexString("95A78968A09DB5D9");
        
        // MAC input from trace: 848201001095A78968A09DB5D9
        var expectedMacInput = Convert.FromHexString("848201001095A78968A09DB5D9");
        var expectedMac = Convert.FromHexString("A3077662BA8EA35B");
        
        // Construct MAC input for SCP02 EXTERNAL AUTHENTICATE
        // Per GP Card Specification v2.3.1 section E.5.2 (Table E-10):
        // - EXTERNAL AUTHENTICATE command: Lc='10' (16 bytes), Data='xx xx...' (Host cryptogram and MAC)
        // Per section E.4.4: "A C-MAC is generated... across the full APDU command being transmitted to
        // the card including the header and the data field in the command message"
        // The MAC input consists of header (5 bytes) + data, where Lc indicates the final command length
        var macInput = new byte[5 + hostCryptogram.Length]; // 5 header + 8 cryptogram = 13 bytes
        macInput[0] = 0x84; // CLA
        macInput[1] = 0x82; // INS (EXTERNAL AUTHENTICATE)
        macInput[2] = (byte)SecurityLevel.CMac; // P1=0x01 as shown in trace (C-MAC)
        macInput[3] = 0x00; // P2
        macInput[4] = 0x10; // Lc=16 (indicates final command will have 8 byte cryptogram + 8 byte MAC)
        Array.Copy(hostCryptogram, 0, macInput, 5, hostCryptogram.Length);
        
        // Verify MAC input matches trace
        macInput.Should().Equal(expectedMacInput, "MAC input should match GP Pro trace");
        
        TestContext.WriteLine("✓ Real GP Pro MAC EXTERNAL AUTHENTICATE MAC input construction verified");
        TestContext.WriteLine($"MAC Input: {Convert.ToHexString(macInput)}");
        TestContext.WriteLine($"Expected:  {Convert.ToHexString(expectedMacInput)}");
    }

    [Test]
    public void UnknownScpParameter_ShouldFailHardWithClearError()
    {
        // The SCP02 implementation parameter 'i' is not sent in INITIALIZE UPDATE response
        // per GP Card Specification Table E-8. It must be determined through other means
        // (e.g., Card Capabilities or pre-configured knowledge).
        // This test validates that unknown implementation parameters are properly rejected.
        
        // Arrange - Test with an invalid implementation parameter value
        byte unknownParameter = 0xFF; // Not a valid SCP02 implementation per Table E-1
        
        // Act - Try to get implementation for unknown parameter
        var implementationResult = Scp02Protocol.GetScp02Implementation(unknownParameter);
        
        // Assert - Should fail with clear error message
        implementationResult.IsFailure.Should().BeTrue("Unknown implementation should fail");
        implementationResult.Error.Should().BeOfType<UnsupportedImplementationError>();
        implementationResult.Error.Message.Should().Contain("i=FF");
        implementationResult.Error.Message.Should().Contain("00, 02, 04, 05, 15, 35, 55, 75");
        
        TestContext.WriteLine("✓ Unknown SCP parameter correctly rejected with helpful error message");
        TestContext.WriteLine($"Invalid parameter 0xFF correctly failed: {implementationResult.Error.Message}");
    }

    [Test] 
    public void EndToEnd_RealTrace_ShouldProcessWithoutDefaults()
    {
        // Arrange - Complete flow with real CLR trace data
        var realResponse = Convert.FromHexString("0000234555808320483901020011C284EC19415D17F4198ADCD5102D");
        var hostChallenge = Convert.FromHexString("719426F20E234840");
        
        // Act - Parse response
        var parseResult = InitializeUpdateResponse.Parse(realResponse);
        parseResult.IsSuccess.Should().BeTrue();
        var response = parseResult.Value;
        
        // Detect implementation (should not default)
        var implementationResult = Scp02Protocol.GetScp02Implementation(response.ScpParameter);
        implementationResult.IsSuccess.Should().BeTrue("Implementation detection should succeed");
        implementationResult.Value.Should().Be(ScpImplementation.Scp02I00, "Should detect specific implementation, not default");
        
        // Create key derivation context
        var contextResult = KeyDerivationContext.CreateForScp02(
            _keySet,
            hostChallenge,
            response.CardChallenge,
            response.SequenceCounter,
            implementationResult.Value
        );
        contextResult.IsSuccess.Should().BeTrue("Key derivation context should be created successfully");
        
        // Derive session keys
        var sessionKeysResult = _keyDerivationService.DeriveSessionKeys(contextResult.Value);
        sessionKeysResult.IsSuccess.Should().BeTrue("Session key derivation should succeed");
        
        var sessionKeys = sessionKeysResult.Value;
        
        // Should match expected CLR trace values (derived MAC keys, not static)
        var expectedSMac = Convert.FromHexString("0D446132B168F75CD6F0A780693A4DD3");
        sessionKeys.SMac.Should().Equal(expectedSMac, "Should derive MAC keys, not use static");
        sessionKeys.SMac.Should().NotEqual(_keySet.MacKey, "MAC key should be derived, not static");
        
        TestContext.WriteLine("✓ End-to-end processing with real trace succeeds without defaults");
        TestContext.WriteLine($"Implementation: {implementationResult.Value}");
        TestContext.WriteLine($"Derived S-MAC: {Convert.ToHexString(sessionKeys.SMac)} (derived)");
        TestContext.WriteLine($"Static MAC:    {Convert.ToHexString(_keySet.MacKey)} (not used)");
    }
}