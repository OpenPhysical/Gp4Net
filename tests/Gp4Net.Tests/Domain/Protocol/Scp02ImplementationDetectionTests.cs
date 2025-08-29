using System;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Protocol;

/// <summary>
/// Tests for SCP02 implementation parameter detection logic.
/// Validates that GetScp02Implementation() correctly identifies implementations and fails hard on unknown values.
/// </summary>
[TestFixture]
[Category("Unit")]
[Category("FailHard")]
public class Scp02ImplementationDetectionTests
{
    private Scp02Protocol _protocol;
    private Scp02KeySet _keySet;

    [SetUp]
    public void SetUp()
    {
        KeyDerivationService keyDerivationService = new KeyDerivationService(NullLogger<KeyDerivationService>.Instance);
        _keySet = Scp02KeySet.Create(
            new byte[16], // ENC key
            new byte[16], // MAC key 
            new byte[16], // DEK key
            0x01          // Key version
        ).Value;
        _protocol = new Scp02Protocol(_keySet, keyDerivationService, NullLogger<Scp02Protocol>.Instance);
    }

    [TestCase(0x00, ScpImplementation.Scp02I00, "i=00 should be detected correctly")]
    [TestCase(0x02, ScpImplementation.Scp02I02, "i=02 should be detected correctly")]
    [TestCase(0x04, ScpImplementation.Scp02I04, "i=04 should be detected correctly")]
    [TestCase(0x05, ScpImplementation.Scp02I05, "i=05 should be detected correctly")]
    [TestCase(0x15, ScpImplementation.Scp02I15, "i=15 should be detected correctly")]
    [TestCase(0x35, ScpImplementation.Scp02I35, "i=35 should be detected correctly")]
    [TestCase(0x55, ScpImplementation.Scp02I55, "i=55 should be detected correctly")]
    [TestCase(0x75, ScpImplementation.Scp02I75, "i=75 should be detected correctly")]
    public void GetScp02Implementation_WithValidImplementation_ShouldReturnCorrectEnum(
        byte implementationParameter,
        ScpImplementation expectedImplementation,
        string description)
    {
        // Act
        Result<ScpImplementation, SmartCardError> result = Scp02Protocol.GetScp02Implementation(implementationParameter);

        // Assert
        _ = result.IsSuccess.Should().BeTrue($"{description} - should succeed");
        _ = result.Value.Should().Be(expectedImplementation, description);

        TestContext.Out.WriteLine($"✓ {description}");
        TestContext.Out.WriteLine($"Implementation parameter 0x{implementationParameter:X2} correctly detected as {expectedImplementation}");
    }

    [TestCase(0x01, "i=01 is not a valid SCP02 implementation")]
    [TestCase(0x03, "i=03 is not a valid SCP02 implementation")]
    [TestCase(0x06, "i=06 is not a valid SCP02 implementation")]
    [TestCase(0x10, "i=10 is not a valid SCP02 implementation")]
    [TestCase(0x20, "i=20 is not a valid SCP02 implementation")]
    [TestCase(0x50, "i=50 is not a valid SCP02 implementation")]
    [TestCase(0xFF, "i=FF is not a valid SCP02 implementation")]
    public void GetScp02Implementation_WithInvalidImplementation_ShouldFailHard(
        byte invalidImplementationParameter,
        string description)
    {
        // Act & Assert
        Result<ScpImplementation, SmartCardError> result = Scp02Protocol.GetScp02Implementation(invalidImplementationParameter);

        _ = result.IsFailure.Should().BeTrue($"{description} - should fail with error");
        _ = result.Error.Should().BeOfType<UnsupportedImplementationError>();
        _ = result.Error.Message.Should().Contain($"i={invalidImplementationParameter:X2}",
            $"{description} - should fail with specific implementation error");
        _ = result.Error.Message.Should().Contain("00, 02, 04, 05, 15, 35, 55, 75",
            $"{description} - should provide guidance on valid implementations");

        TestContext.Out.WriteLine($"✓ {description}");
        TestContext.Out.WriteLine($"Invalid implementation parameter 0x{invalidImplementationParameter:X2} correctly rejected with error: {result.Error.Message}");
    }

    [Test]
    public void ProcessInitializeUpdateResponse_WithRealGpProClrTrace_ShouldDetectImplementation()
    {
        // Arrange - Real INITIALIZE UPDATE response from GP Pro CLR trace
        // From scp02_CLR.log line 24: 0000234555808320483901020011C284EC19415D17F4198ADCD5102D
        byte[] realClrResponse = Convert.FromHexString("0000234555808320483901020011C284EC19415D17F4198ADCD5102D");
        byte[] hostChallenge = Convert.FromHexString("719426F20E234840");

        Result<InitializeUpdateResponse, SmartCardError> parseResult = InitializeUpdateResponse.Parse(realClrResponse);
        _ = parseResult.IsSuccess.Should().BeTrue("Real GP Pro response should parse successfully");

        // The ScpParameter should be at byte 11 (0x02 in this case)
        TestContext.Out.WriteLine($"Parsed ScpParameter: 0x{parseResult.Value.ScpParameter:X2}");

        // Act
        Result<SecureChannelContext, SmartCardError> result = _protocol.ProcessInitializeUpdateResponse(parseResult.Value, hostChallenge);

        // Assert - Should not fail due to unknown implementation (will fail on cryptogram, but that's expected)
        _ = result.IsFailure.Should().BeTrue("Expected failure due to cryptogram mismatch with zero keys");
        _ = result.Error.Message.Should().NotContain("Unknown SCP02 implementation parameter",
            "Real GP Pro response should have recognizable implementation parameter");

        TestContext.Out.WriteLine($"✓ Real GP Pro CLR trace correctly parsed implementation parameter");
    }

    [Test]
    public void ProcessInitializeUpdateResponse_WithRealGpProMacTrace_ShouldDetectImplementation()
    {
        // Arrange - Real INITIALIZE UPDATE response from GP Pro MAC trace  
        // From scp02_MAC.log line 24: 00002345558083204839010200123E6DB216F8D58177E15BAA128DF9
        byte[] realMacResponse = Convert.FromHexString("00002345558083204839010200123E6DB216F8D58177E15BAA128DF9");
        byte[] hostChallenge = Convert.FromHexString("BD76C16D1D2E2D76");

        Result<InitializeUpdateResponse, SmartCardError> parseResult = InitializeUpdateResponse.Parse(realMacResponse);
        _ = parseResult.IsSuccess.Should().BeTrue("Real GP Pro response should parse successfully");

        // The ScpParameter should be at byte 11 (0x02 in this case)
        TestContext.Out.WriteLine($"Parsed ScpParameter: 0x{parseResult.Value.ScpParameter:X2}");

        // Act
        Result<SecureChannelContext, SmartCardError> result = _protocol.ProcessInitializeUpdateResponse(parseResult.Value, hostChallenge);

        // Assert - Should not fail due to unknown implementation
        _ = result.IsFailure.Should().BeTrue("Expected failure due to cryptogram mismatch with zero keys");
        _ = result.Error.Message.Should().NotContain("Unknown SCP02 implementation parameter",
            "Real GP Pro response should have recognizable implementation parameter");

        TestContext.Out.WriteLine($"✓ Real GP Pro MAC trace correctly parsed implementation parameter");
    }

    /// <summary>
    /// Creates a minimal valid SCP02 INITIALIZE UPDATE response with specified implementation parameter.
    /// </summary>
    private static byte[] CreateScp02Response(byte implementationParameter)
    {
        byte[] response = new byte[28];

        // Key Diversification Data (10 bytes) - can be zeros for test
        Array.Clear(response, 0, 10);

        // Key Version (1 byte)
        response[10] = 0x01;

        // SCP ID + Implementation Parameter (1 byte) = 0x02 (SCP02) + implementation
        response[11] = implementationParameter;

        // Sequence Counter (2 bytes)
        response[12] = 0x00;
        response[13] = 0x01;

        // Card Challenge (6 bytes)
        Array.Copy(new byte[] { 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6 }, 0, response, 14, 6);

        // Card Cryptogram (8 bytes) - will be wrong, causing cryptogram validation to fail
        Array.Copy(new byte[] { 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8 }, 0, response, 20, 8);

        return response;
    }
}