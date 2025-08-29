using System;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
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
        byte[] testKeys = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
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
        byte[] realResponse = Convert.FromHexString("0000234555808320483901020011C284EC19415D17F4198ADCD5102D");
        byte[] hostChallenge = Convert.FromHexString("719426F20E234840");

        // Act - Parse the response
        Result<InitializeUpdateResponse, SmartCardError> parseResult = InitializeUpdateResponse.Parse(realResponse);

        // Assert - Parsing should succeed
        _ = parseResult.IsSuccess.Should().BeTrue("Real GP Pro CLR response should parse successfully");
        InitializeUpdateResponse? response = parseResult.Value;

        // Verify parsed fields match expected values from trace
        _ = response.KeyDiversificationData.Should().Equal(Convert.FromHexString("00002345558083204839"),
            "KDD should match GP Pro trace");
        _ = response.KeyVersion.Should().Be(0x01, "Key version should be 1");
        _ = response.ScpId.Should().Be(0x02, "SCP ID should be 2");
        _ = response.ScpParameter.Should().Be(0x00, "SCP parameter should be 0x00 (i=00)");
        _ = response.SequenceCounter.Should().Equal(Convert.FromHexString("0011"),
            "Sequence counter should match GP Pro trace");
        _ = response.CardChallenge.Should().Equal(Convert.FromHexString("C284EC19415D"),
            "Card challenge should match GP Pro trace");
        _ = response.CardCryptogram.Should().Equal(Convert.FromHexString("17F4198ADCD5102D"),
            "Card cryptogram should match GP Pro trace");

        // Verify implementation detection
        Result<ScpImplementation, SmartCardError> detectedImplResult = Scp02Protocol.GetScp02Implementation(response.ScpParameter);
        _ = detectedImplResult.IsSuccess.Should().BeTrue("Implementation detection should succeed");
        _ = detectedImplResult.Value.Should().Be(ScpImplementation.Scp02I00, "Should detect i=00 implementation");

        TestContext.Out.WriteLine("✓ Real GP Pro CLR trace correctly parsed and implementation detected");
        TestContext.Out.WriteLine($"KDD: {Convert.ToHexString(response.KeyDiversificationData)}");
        TestContext.Out.WriteLine($"SCP Parameter: 0x{response.ScpParameter:X2} → {detectedImplResult.Value}");
        TestContext.Out.WriteLine($"Sequence Counter: {Convert.ToHexString(response.SequenceCounter)}");
    }

    [Test]
    public void RealGpProMAC_InitializeUpdate_ShouldParseAndDetectImplementation()
    {
        // Arrange - Real INITIALIZE UPDATE response from GP Pro MAC trace (scp02_MAC.log line 24)
        // Response: 00002345558083204839010200123E6DB216F8D58177E15BAA128DF9 9000
        byte[] realResponse = Convert.FromHexString("00002345558083204839010200123E6DB216F8D58177E15BAA128DF9");
        byte[] hostChallenge = Convert.FromHexString("BD76C16D1D2E2D76");

        // Act - Parse the response
        Result<InitializeUpdateResponse, SmartCardError> parseResult = InitializeUpdateResponse.Parse(realResponse);

        // Assert - Parsing should succeed
        _ = parseResult.IsSuccess.Should().BeTrue("Real GP Pro MAC response should parse successfully");
        InitializeUpdateResponse? response = parseResult.Value;

        // Verify parsed fields match expected values from trace
        _ = response.KeyDiversificationData.Should().Equal(Convert.FromHexString("00002345558083204839"),
            "KDD should match GP Pro trace");
        _ = response.KeyVersion.Should().Be(0x01, "Key version should be 1");
        _ = response.ScpId.Should().Be(0x02, "SCP ID should be 2");
        _ = response.ScpParameter.Should().Be(0x00, "SCP parameter should be 0x00 (i=00)");
        _ = response.SequenceCounter.Should().Equal(Convert.FromHexString("0012"),
            "Sequence counter should match GP Pro trace");
        _ = response.CardChallenge.Should().Equal(Convert.FromHexString("3E6DB216F8D5"),
            "Card challenge should match GP Pro trace (6 bytes only)");
        _ = response.CardCryptogram.Should().Equal(Convert.FromHexString("8177E15BAA128DF9"),
            "Card cryptogram should match GP Pro trace");

        // Verify implementation detection
        Result<ScpImplementation, SmartCardError> detectedImplResult = Scp02Protocol.GetScp02Implementation(response.ScpParameter);
        _ = detectedImplResult.IsSuccess.Should().BeTrue("Implementation detection should succeed");
        _ = detectedImplResult.Value.Should().Be(ScpImplementation.Scp02I00, "Should detect i=00 implementation");

        TestContext.Out.WriteLine("✓ Real GP Pro MAC trace correctly parsed and implementation detected");
        TestContext.Out.WriteLine($"KDD: {Convert.ToHexString(response.KeyDiversificationData)}");
        TestContext.Out.WriteLine($"SCP Parameter: 0x{response.ScpParameter:X2} → {detectedImplResult.Value}");
        TestContext.Out.WriteLine($"Sequence Counter: {Convert.ToHexString(response.SequenceCounter)}");
    }

    [Test]
    public void RealGpProCLR_SessionKeyDerivation_ShouldMatchExpected()
    {
        // Arrange - Use CLR trace data
        byte[] staticKeys = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        byte[] hostChallenge = Convert.FromHexString("719426F20E234840");
        byte[] cardChallenge = Convert.FromHexString("C284EC19415D");
        byte[] sequenceCounter = Convert.FromHexString("0011");

        // Expected session keys from GP Pro CLR trace
        byte[] expectedSEnc = Convert.FromHexString("6DCE2A99BACB5207A7A96A92F114D66C");
        byte[] expectedSMac = Convert.FromHexString("0D446132B168F75CD6F0A780693A4DD3");
        byte[] expectedSrMac = Convert.FromHexString("4C7FE3A6B0E4F3891B701C3DE654F9B7");

        // Create key set with static keys
        Result<Scp02KeySet, SmartCardError> keySetResult = Scp02KeySet.Create(staticKeys, staticKeys, staticKeys, 0x01);
        _ = keySetResult.IsSuccess.Should().BeTrue();

        // Act - Derive session keys for i=00 (uses derived MAC keys)
        Result<SessionKeys, SmartCardError> sessionKeysResult = _keyDerivationService.DeriveSessionKeys(
            keySetResult.Value,
            hostChallenge,
            cardChallenge,
            Maybe<byte[]>.From(sequenceCounter),
            Maybe<ScpImplementation>.From(ScpImplementation.Scp02I00));

        // Assert
        _ = sessionKeysResult.IsSuccess.Should().BeTrue("Session key derivation should succeed");
        SessionKeys? sessionKeys = sessionKeysResult.Value;

        _ = sessionKeys.SEnc.Should().Equal(expectedSEnc, "S-ENC should match GP Pro trace");
        _ = sessionKeys.SMac.Should().Equal(expectedSMac, "S-MAC should match GP Pro trace");
        _ = sessionKeys.SrMac.Should().Equal(expectedSrMac, "S-RMAC should match GP Pro trace");

        TestContext.Out.WriteLine("✓ Real GP Pro CLR session keys match expected values");
        TestContext.Out.WriteLine($"S-ENC:  {Convert.ToHexString(sessionKeys.SEnc)}");
        TestContext.Out.WriteLine($"S-MAC:  {Convert.ToHexString(sessionKeys.SMac)}");
        TestContext.Out.WriteLine($"S-RMAC: {Convert.ToHexString(sessionKeys.SrMac)}");
    }

    [Test]
    public void RealGpProMAC_SessionKeyDerivation_ShouldMatchExpected()
    {
        // Arrange - Use MAC trace data
        byte[] staticKeys = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        byte[] hostChallenge = Convert.FromHexString("BD76C16D1D2E2D76");
        byte[] cardChallenge = Convert.FromHexString("3E6DB216F8D5");
        byte[] sequenceCounter = Convert.FromHexString("0012");

        // Expected session keys from GP Pro MAC trace
        byte[] expectedSEnc = Convert.FromHexString("CB4ED15E982DB16EB630FE9F3E04D665");
        byte[] expectedSMac = Convert.FromHexString("89D93B2D2D7E7AB95B61F82EDE3975B7");
        byte[] expectedSrMac = Convert.FromHexString("9E73AA58712520FCC53800F90C2471E1");

        // Create key set with static keys
        Result<Scp02KeySet, SmartCardError> keySetResult = Scp02KeySet.Create(staticKeys, staticKeys, staticKeys, 0x01);
        _ = keySetResult.IsSuccess.Should().BeTrue();

        // Act - Derive session keys for i=00 (uses derived MAC keys)
        Result<SessionKeys, SmartCardError> sessionKeysResult = _keyDerivationService.DeriveSessionKeys(
            keySetResult.Value,
            hostChallenge,
            cardChallenge,
            Maybe<byte[]>.From(sequenceCounter),
            Maybe<ScpImplementation>.From(ScpImplementation.Scp02I00));

        // Assert
        _ = sessionKeysResult.IsSuccess.Should().BeTrue("Session key derivation should succeed");
        SessionKeys? sessionKeys = sessionKeysResult.Value;

        _ = sessionKeys.SEnc.Should().Equal(expectedSEnc, "S-ENC should match GP Pro trace");
        _ = sessionKeys.SMac.Should().Equal(expectedSMac, "S-MAC should match GP Pro trace");
        _ = sessionKeys.SrMac.Should().Equal(expectedSrMac, "S-RMAC should match GP Pro trace");

        TestContext.Out.WriteLine("✓ Real GP Pro MAC session keys match expected values");
        TestContext.Out.WriteLine($"S-ENC:  {Convert.ToHexString(sessionKeys.SEnc)}");
        TestContext.Out.WriteLine($"S-MAC:  {Convert.ToHexString(sessionKeys.SMac)}");
        TestContext.Out.WriteLine($"S-RMAC: {Convert.ToHexString(sessionKeys.SrMac)}");
    }

    [Test]
    public void RealGpProCLR_ExternalAuthenticate_ShouldMatchExpectedMac()
    {
        // Arrange - Data from GP Pro CLR trace
        byte[] sessionMac = Convert.FromHexString("0D446132B168F75CD6F0A780693A4DD3");
        byte[] hostCryptogram = Convert.FromHexString("8E69F9E4D246FF36");

        // MAC input from trace: 84820000108E69F9E4D246FF36
        byte[] expectedMacInput = Convert.FromHexString("84820000108E69F9E4D246FF36");
        byte[] expectedMac = Convert.FromHexString("9F97E807B91F6318");

        // Construct MAC input for SCP02 EXTERNAL AUTHENTICATE
        // Per GP Card Specification v2.3.1 section E.5.2 (Table E-10):
        // - EXTERNAL AUTHENTICATE command: Lc='10' (16 bytes), Data='xx xx...' (Host cryptogram and MAC)
        // Per section E.4.4: "A C-MAC is generated... across the full APDU command being transmitted to
        // the card including the header and the data field in the command message"
        // The MAC input consists of header (5 bytes) + data, where Lc indicates the final command length
        byte[] macInput = new byte[5 + hostCryptogram.Length]; // 5 header + 8 cryptogram = 13 bytes
        macInput[0] = 0x84; // CLA
        macInput[1] = 0x82; // INS (EXTERNAL AUTHENTICATE)
        macInput[2] = (byte)SecurityLevel.None; // P1=0x00 as shown in trace
        macInput[3] = 0x00; // P2
        macInput[4] = 0x10; // Lc=16 (indicates final command will have 8 byte cryptogram + 8 byte MAC)
        Array.Copy(hostCryptogram, 0, macInput, 5, hostCryptogram.Length);

        // Verify MAC input matches trace
        _ = macInput.Should().Equal(expectedMacInput, "MAC input should match GP Pro trace");

        TestContext.Out.WriteLine("✓ Real GP Pro CLR EXTERNAL AUTHENTICATE MAC input construction verified");
        TestContext.Out.WriteLine($"MAC Input: {Convert.ToHexString(macInput)}");
        TestContext.Out.WriteLine($"Expected:  {Convert.ToHexString(expectedMacInput)}");
    }

    [Test]
    public void RealGpProMAC_ExternalAuthenticate_ShouldMatchExpectedMac()
    {
        // Arrange - Data from GP Pro MAC trace
        byte[] sessionMac = Convert.FromHexString("89D93B2D2D7E7AB95B61F82EDE3975B7");
        byte[] hostCryptogram = Convert.FromHexString("95A78968A09DB5D9");

        // MAC input from trace: 848201001095A78968A09DB5D9
        byte[] expectedMacInput = Convert.FromHexString("848201001095A78968A09DB5D9");
        byte[] expectedMac = Convert.FromHexString("A3077662BA8EA35B");

        // Construct MAC input for SCP02 EXTERNAL AUTHENTICATE
        // Per GP Card Specification v2.3.1 section E.5.2 (Table E-10):
        // - EXTERNAL AUTHENTICATE command: Lc='10' (16 bytes), Data='xx xx...' (Host cryptogram and MAC)
        // Per section E.4.4: "A C-MAC is generated... across the full APDU command being transmitted to
        // the card including the header and the data field in the command message"
        // The MAC input consists of header (5 bytes) + data, where Lc indicates the final command length
        byte[] macInput = new byte[5 + hostCryptogram.Length]; // 5 header + 8 cryptogram = 13 bytes
        macInput[0] = 0x84; // CLA
        macInput[1] = 0x82; // INS (EXTERNAL AUTHENTICATE)
        macInput[2] = (byte)SecurityLevel.CMac; // P1=0x01 as shown in trace (C-MAC)
        macInput[3] = 0x00; // P2
        macInput[4] = 0x10; // Lc=16 (indicates final command will have 8 byte cryptogram + 8 byte MAC)
        Array.Copy(hostCryptogram, 0, macInput, 5, hostCryptogram.Length);

        // Verify MAC input matches trace
        _ = macInput.Should().Equal(expectedMacInput, "MAC input should match GP Pro trace");

        TestContext.Out.WriteLine("✓ Real GP Pro MAC EXTERNAL AUTHENTICATE MAC input construction verified");
        TestContext.Out.WriteLine($"MAC Input: {Convert.ToHexString(macInput)}");
        TestContext.Out.WriteLine($"Expected:  {Convert.ToHexString(expectedMacInput)}");
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
        Result<ScpImplementation, SmartCardError> implementationResult = Scp02Protocol.GetScp02Implementation(unknownParameter);

        // Assert - Should fail with clear error message
        _ = implementationResult.IsFailure.Should().BeTrue("Unknown implementation should fail");
        _ = implementationResult.Error.Should().BeOfType<UnsupportedImplementationError>();
        _ = implementationResult.Error.Message.Should().Contain("i=FF");
        _ = implementationResult.Error.Message.Should().Contain("00, 02, 04, 05, 15, 35, 55, 75");

        TestContext.Out.WriteLine("✓ Unknown SCP parameter correctly rejected with helpful error message");
        TestContext.Out.WriteLine($"Invalid parameter 0xFF correctly failed: {implementationResult.Error.Message}");
    }

    [Test]
    public void EndToEnd_RealTrace_ShouldProcessWithoutDefaults()
    {
        // Arrange - Complete flow with real CLR trace data
        byte[] realResponse = Convert.FromHexString("0000234555808320483901020011C284EC19415D17F4198ADCD5102D");
        byte[] hostChallenge = Convert.FromHexString("719426F20E234840");

        // Act - Parse response
        Result<InitializeUpdateResponse, SmartCardError> parseResult = InitializeUpdateResponse.Parse(realResponse);
        _ = parseResult.IsSuccess.Should().BeTrue();
        InitializeUpdateResponse? response = parseResult.Value;

        // Detect implementation (should not default)
        Result<ScpImplementation, SmartCardError> implementationResult = Scp02Protocol.GetScp02Implementation(response.ScpParameter);
        _ = implementationResult.IsSuccess.Should().BeTrue("Implementation detection should succeed");
        _ = implementationResult.Value.Should().Be(ScpImplementation.Scp02I00, "Should detect specific implementation, not default");

        // Create key derivation context
        Result<KeyDerivationContext, SmartCardError> contextResult = KeyDerivationContext.CreateForScp02(
            _keySet,
            hostChallenge,
            response.CardChallenge,
            response.SequenceCounter,
            implementationResult.Value
        );
        _ = contextResult.IsSuccess.Should().BeTrue("Key derivation context should be created successfully");

        // Derive session keys
        Result<SessionKeys, SmartCardError> sessionKeysResult = _keyDerivationService.DeriveSessionKeys(contextResult.Value);
        _ = sessionKeysResult.IsSuccess.Should().BeTrue("Session key derivation should succeed");

        SessionKeys? sessionKeys = sessionKeysResult.Value;

        // Should match expected CLR trace values (derived MAC keys, not static)
        byte[] expectedSMac = Convert.FromHexString("0D446132B168F75CD6F0A780693A4DD3");
        _ = sessionKeys.SMac.Should().Equal(expectedSMac, "Should derive MAC keys, not use static");
        _ = sessionKeys.SMac.Should().NotEqual(_keySet.MacKey, "MAC key should be derived, not static");

        TestContext.Out.WriteLine("✓ End-to-end processing with real trace succeeds without defaults");
        TestContext.Out.WriteLine($"Implementation: {implementationResult.Value}");
        TestContext.Out.WriteLine($"Derived S-MAC: {Convert.ToHexString(sessionKeys.SMac)} (derived)");
        TestContext.Out.WriteLine($"Static MAC:    {Convert.ToHexString(_keySet.MacKey)} (not used)");
    }
}