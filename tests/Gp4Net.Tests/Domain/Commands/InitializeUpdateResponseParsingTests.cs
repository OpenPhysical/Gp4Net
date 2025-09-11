using System;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands;

/// <summary>
/// Tests for InitializeUpdateResponse.Parse() method validation and edge cases.
/// Ensures robust parsing of INITIALIZE UPDATE responses for both SCP02 and SCP03 protocols.
/// These tests prevent malformed responses from causing authentication failures or security issues.
/// </summary>
[TestFixture]
[Category("Unit")]
[Category("FailHard")]
public class InitializeUpdateResponseParsingTests
{
    // Removed: Parse_WithNullResponse_ShouldFailHard
    // NO NULLS rule - nulls should be converted to Result<T> at boundaries, not checked in domain

    [Test]
    public void Parse_WithTooShortResponse_ShouldFailHard()
    {
        (byte[], string)[] testCases =
        [
            ([], "INITIALIZE UPDATE response too short: 0 bytes, expected at least 28"),
            (new byte[10], "INITIALIZE UPDATE response too short: 10 bytes, expected at least 28"),
            (new byte[27], "INITIALIZE UPDATE response too short: 27 bytes, expected at least 28"),
        ];

        foreach ((byte[] response, string expectedError) in testCases)
        {
            // Act
            Result<InitializeUpdateResponse, SmartCardError> result =
                InitializeUpdateResponse.Parse(response);

            // Assert
            _ = result.IsFailure.Should().BeTrue("Too short response should be rejected");
            _ = result.Error.Message.Should().Contain(expectedError);

            TestContext.Out.WriteLine(
                $"✓ Response of {response.Length} bytes correctly rejected: {result.Error.Message}"
            );
        }
    }

    [Test]
    public void Parse_WithMinimumValidScp02Response_ShouldSucceed()
    {
        // Arrange - Minimum valid SCP02 response (28 bytes)
        byte[] response = new byte[28];

        // Key diversification data (10 bytes) - zeros
        Array.Clear(response, 0, 10);

        // Key version (1 byte)
        response[10] = 0x01;

        // SCP ID (1 byte) - 0x02 for SCP02
        response[11] = 0x02;

        // Sequence counter (2 bytes)
        response[12] = 0x00;
        response[13] = 0x01;

        // Card challenge (6 bytes for SCP02)
        response[14] = 0xC1;
        response[15] = 0xC2;
        response[16] = 0xC3;
        response[17] = 0xC4;
        response[18] = 0xC5;
        response[19] = 0xC6;

        // Card cryptogram (8 bytes)
        response[20] = 0xD1;
        response[21] = 0xD2;
        response[22] = 0xD3;
        response[23] = 0xD4;
        response[24] = 0xD5;
        response[25] = 0xD6;
        response[26] = 0xD7;
        response[27] = 0xD8;

        // Act
        Result<InitializeUpdateResponse, SmartCardError> result = InitializeUpdateResponse.Parse(
            response
        );

        // Assert
        _ = result
            .IsSuccess.Should()
            .BeTrue("Minimum valid SCP02 response should parse successfully");

        var parsed = result.Value;
        _ = parsed.KeyVersion.Should().Be(0x01);
        _ = parsed.ScpId.Should().Be(0x02);
        _ = parsed.ScpParameter.Should().Be(0x00); // Padding for SCP02
        _ = parsed.SequenceCounter.Length.Should().Be(2);
        _ = parsed.CardChallenge.Length.Should().Be(6, "SCP02 uses 6-byte card challenge");
        _ = parsed.CardCryptogram.Length.Should().Be(8);

        TestContext.Out.WriteLine("✓ Minimum valid SCP02 response parsed successfully");
        TestContext.Out.WriteLine($"Key version: 0x{parsed.KeyVersion:X2}");
        TestContext.Out.WriteLine($"SCP ID: 0x{parsed.ScpId:X2}");
        TestContext.Out.WriteLine(
            $"Sequence counter: {Convert.ToHexString(parsed.SequenceCounter)}"
        );
        TestContext.Out.WriteLine($"Card challenge: {Convert.ToHexString(parsed.CardChallenge)}");
    }

    [Test]
    public void Parse_WithValidScp03Response_ShouldSucceed()
    {
        // Arrange - Valid SCP03 response (32 bytes)
        byte[] response = new byte[32];

        // Key diversification data (10 bytes)
        Array.Clear(response, 0, 10);

        // Key version (1 byte)
        response[10] = 0x01;

        // SCP ID (1 byte) - 0x03 for SCP03
        response[11] = 0x03;

        // Implementation parameter (1 byte)
        response[12] = 0x70; // SCP03 pseudo-random

        // Card challenge (8 bytes for SCP03)
        for (int i = 0; i < 8; i++)
        {
            response[13 + i] = (byte)(0xC1 + i);
        }

        // Card cryptogram (8 bytes)
        for (int i = 0; i < 8; i++)
        {
            response[21 + i] = (byte)(0xD1 + i);
        }

        // Sequence counter (remaining 3 bytes)
        response[29] = 0x00;
        response[30] = 0x01;
        response[31] = 0x02;

        // Act
        Result<InitializeUpdateResponse, SmartCardError> result = InitializeUpdateResponse.Parse(
            response
        );

        // Assert
        _ = result.IsSuccess.Should().BeTrue("Valid SCP03 response should parse successfully");

        var parsed = result.Value;
        _ = parsed.KeyVersion.Should().Be(0x01);
        _ = parsed.ScpId.Should().Be(0x03);
        _ = parsed.ScpParameter.Should().Be(0x70);
        _ = parsed.SequenceCounter.Length.Should().Be(3);
        _ = parsed.CardChallenge.Length.Should().Be(8, "SCP03 uses 8-byte card challenge");
        _ = parsed.CardCryptogram.Length.Should().Be(8);

        TestContext.Out.WriteLine("✓ Valid SCP03 response parsed successfully");
        TestContext.Out.WriteLine($"Key version: 0x{parsed.KeyVersion:X2}");
        TestContext.Out.WriteLine($"SCP ID: 0x{parsed.ScpId:X2}");
        TestContext.Out.WriteLine($"Implementation parameter: 0x{parsed.ScpParameter:X2}");
        TestContext.Out.WriteLine(
            $"Sequence counter: {Convert.ToHexString(parsed.SequenceCounter)}"
        );
        TestContext.Out.WriteLine($"Card challenge: {Convert.ToHexString(parsed.CardChallenge)}");
    }

    [Test]
    public void Parse_WithRealGpProScp02ClrTrace_ShouldParseCorrectly()
    {
        // Arrange - Real INITIALIZE UPDATE response from GP Pro CLR trace
        byte[] realResponse = Convert.FromHexString(
            "0000234555808320483901020011C284EC19415D17F4198ADCD5102D"
        );

        // Act
        Result<InitializeUpdateResponse, SmartCardError> result = InitializeUpdateResponse.Parse(
            realResponse
        );

        // Assert
        _ = result.IsSuccess.Should().BeTrue("Real GP Pro CLR response should parse successfully");

        var parsed = result.Value;
        _ = parsed
            .KeyDiversificationData.Should()
            .Equal(Convert.FromHexString("00002345558083204839"));
        _ = parsed.KeyVersion.Should().Be(0x01);
        _ = parsed.ScpId.Should().Be(0x02);
        _ = parsed.ScpParameter.Should().Be(0x00); // SCP02 padding
        _ = parsed.SequenceCounter.Should().Equal(Convert.FromHexString("0011"));
        _ = parsed.CardChallenge.Should().Equal(Convert.FromHexString("C284EC19415D"));
        _ = parsed.CardCryptogram.Should().Equal(Convert.FromHexString("17F4198ADCD5102D"));

        TestContext.Out.WriteLine("✓ Real GP Pro CLR trace parsed correctly");
        TestContext.Out.WriteLine($"KDD: {Convert.ToHexString(parsed.KeyDiversificationData)}");
        TestContext.Out.WriteLine($"Key version: 0x{parsed.KeyVersion:X2}");
        TestContext.Out.WriteLine(
            $"SCP: 0x{parsed.ScpId:X2} (parameter 0x{parsed.ScpParameter:X2})"
        );
    }

    [Test]
    public void Parse_WithRealGpProScp02MacTrace_ShouldParseCorrectly()
    {
        // Arrange - Real INITIALIZE UPDATE response from GP Pro MAC trace
        byte[] realResponse = Convert.FromHexString(
            "00002345558083204839010200123E6DB216F8D58177E15BAA128DF9"
        );

        // Act
        Result<InitializeUpdateResponse, SmartCardError> result = InitializeUpdateResponse.Parse(
            realResponse
        );

        // Assert
        _ = result.IsSuccess.Should().BeTrue("Real GP Pro MAC response should parse successfully");

        var parsed = result.Value;
        _ = parsed
            .KeyDiversificationData.Should()
            .Equal(Convert.FromHexString("00002345558083204839"));
        _ = parsed.KeyVersion.Should().Be(0x01);
        _ = parsed.ScpId.Should().Be(0x02);
        _ = parsed.ScpParameter.Should().Be(0x00); // SCP02 padding
        _ = parsed.SequenceCounter.Should().Equal(Convert.FromHexString("0012"));
        _ = parsed.CardChallenge.Should().Equal(Convert.FromHexString("3E6DB216F8D5"));
        _ = parsed.CardCryptogram.Should().Equal(Convert.FromHexString("8177E15BAA128DF9"));

        TestContext.Out.WriteLine("✓ Real GP Pro MAC trace parsed correctly");
        TestContext.Out.WriteLine($"KDD: {Convert.ToHexString(parsed.KeyDiversificationData)}");
        TestContext.Out.WriteLine(
            $"Sequence counter: {Convert.ToHexString(parsed.SequenceCounter)}"
        );
    }

    [Test]
    public void Parse_WithCorruptedKeyDiversificationData_ShouldStillParseButPreserveData()
    {
        // Arrange - Response with all-0xFF key diversification data
        byte[] response = new byte[28];

        // Corrupted key diversification data (10 bytes of 0xFF)
        for (int i = 0; i < 10; i++)
        {
            response[i] = 0xFF;
        }

        // Valid remaining fields
        response[10] = 0x01; // Key version
        response[11] = 0x02; // SCP ID
        Array.Copy(new byte[] { 0x00, 0x01 }, 0, response, 12, 2); // Sequence counter
        Array.Copy(new byte[] { 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6 }, 0, response, 14, 6); // Card challenge
        Array.Copy(
            new byte[] { 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8 },
            0,
            response,
            20,
            8
        ); // Card cryptogram

        // Act
        Result<InitializeUpdateResponse, SmartCardError> result = InitializeUpdateResponse.Parse(
            response
        );

        // Assert
        _ = result.IsSuccess.Should().BeTrue("Parser should handle corrupted KDD gracefully");

        var parsed = result.Value;
        _ = parsed
            .KeyDiversificationData.Should()
            .Equal(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
        _ = parsed.KeyVersion.Should().Be(0x01);
        _ = parsed.ScpId.Should().Be(0x02);

        TestContext.Out.WriteLine("✓ Corrupted key diversification data preserved correctly");
        TestContext.Out.WriteLine($"KDD: {Convert.ToHexString(parsed.KeyDiversificationData)}");
    }

    [Test]
    public void Parse_WithUnknownScpVersion_ShouldFailSecurely()
    {
        // Arrange - Response with unknown SCP version 0x99
        byte[] response = new byte[28];

        // Key diversification data (10 bytes) - zeros
        Array.Clear(response, 0, 10);

        response[10] = 0x01; // Key version
        response[11] = 0x99; // Unknown SCP ID

        // Remaining fields
        Array.Copy(new byte[] { 0x00, 0x01 }, 0, response, 12, 2); // Sequence counter
        Array.Copy(new byte[] { 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6 }, 0, response, 14, 6); // Card challenge
        Array.Copy(
            new byte[] { 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8 },
            0,
            response,
            20,
            8
        ); // Card cryptogram

        // Act
        Result<InitializeUpdateResponse, SmartCardError> result = InitializeUpdateResponse.Parse(
            response
        );

        // Assert - Parser should fail secure for unknown SCP versions
        _ = result
            .IsFailure.Should()
            .BeTrue("Parser should fail immediately for unknown SCP versions");
        _ = result
            .Error.Message.Should()
            .Contain("Unsupported SCP version", "Error should specify unsupported version");
        _ = result
            .Error.Message.Should()
            .Contain("01", "Error should include the unsupported version number");

        TestContext.Out.WriteLine("✓ Unknown SCP version correctly rejected (fail secure)");
        TestContext.Out.WriteLine($"Error: {result.Error.Message}");
    }

    [Test]
    public void Parse_WithExtraTrailingBytes_ShouldIgnoreExtraData()
    {
        // Arrange - Valid 28-byte response with 4 extra bytes
        byte[] response = new byte[32];

        // Valid SCP02 response (28 bytes)
        Array.Clear(response, 0, 10); // Key diversification data
        response[10] = 0x01; // Key version
        response[11] = 0x02; // SCP ID
        Array.Copy(new byte[] { 0x00, 0x01 }, 0, response, 12, 2); // Sequence counter
        Array.Copy(new byte[] { 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6 }, 0, response, 14, 6); // Card challenge
        Array.Copy(
            new byte[] { 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8 },
            0,
            response,
            20,
            8
        ); // Card cryptogram

        // Extra trailing bytes (should be ignored for SCP02)
        response[28] = 0xAA;
        response[29] = 0xBB;
        response[30] = 0xCC;
        response[31] = 0xDD;

        // Act
        Result<InitializeUpdateResponse, SmartCardError> result = InitializeUpdateResponse.Parse(
            response
        );

        // Assert
        _ = result.IsSuccess.Should().BeTrue("Parser should handle extra trailing bytes");

        var parsed = result.Value;
        _ = parsed.KeyVersion.Should().Be(0x01);
        _ = parsed.ScpId.Should().Be(0x02);
        _ = parsed.SequenceCounter.Should().Equal(0x00, 0x01);
        _ = parsed.CardChallenge.Length.Should().Be(6, "SCP02 card challenge should be 6 bytes");
        _ = parsed.CardCryptogram.Length.Should().Be(8);

        TestContext.Out.WriteLine("✓ Extra trailing bytes handled correctly");
        TestContext.Out.WriteLine($"Response length: {response.Length} bytes (28 valid + 4 extra)");
        TestContext.Out.WriteLine(
            $"Parsed card challenge: {Convert.ToHexString(parsed.CardChallenge)}"
        );
    }

    [Test]
    public void Parse_WithFieldBoundaryValidation_ShouldHandleEdgeCases()
    {
        // Arrange - Test various field boundary conditions
        (string, int, bool)[] testCases =
        [
            // (description, responseLength, expectedSuccess)
            ("Exactly 28 bytes (minimum SCP02)", 28, true),
            ("29 bytes (SCP02 + 1)", 29, true),
            ("30 bytes (SCP02 + 2)", 30, true),
            ("32 bytes (typical SCP03)", 32, true),
            ("35 bytes (SCP03 + extra)", 35, true),
        ];

        foreach ((string description, int responseLength, bool expectedSuccess) in testCases)
        {
            // Create response of specified length
            byte[] response = new byte[responseLength];

            // Fill with valid SCP02/SCP03 structure
            Array.Clear(response, 0, 10); // Key diversification data
            response[10] = 0x01; // Key version
            response[11] = responseLength >= 32 ? (byte)0x03 : (byte)0x02; // SCP ID based on length

            if (responseLength >= 32) // SCP03
            {
                response[12] = 0x70; // Implementation parameter
                // Card challenge (8 bytes)
                for (int i = 0; i < 8; i++)
                    response[13 + i] = (byte)(0xC1 + i);
                // Card cryptogram (8 bytes)
                for (int i = 0; i < 8; i++)
                    response[21 + i] = (byte)(0xD1 + i);
                // Sequence counter (remaining bytes)
                for (int i = 29; i < responseLength; i++)
                    response[i] = (byte)(i - 28);
            }
            else // SCP02
            {
                // Sequence counter (2 bytes)
                response[12] = 0x00;
                response[13] = 0x01;
                // Card challenge (6 bytes)
                for (int i = 0; i < 6; i++)
                    response[14 + i] = (byte)(0xC1 + i);
                // Card cryptogram (8 bytes)
                for (int i = 0; i < 8; i++)
                    response[20 + i] = (byte)(0xD1 + i);
            }

            // Act
            Result<InitializeUpdateResponse, SmartCardError> result =
                InitializeUpdateResponse.Parse(response);

            // Assert
            if (expectedSuccess)
            {
                _ = result.IsSuccess.Should().BeTrue($"Parsing should succeed for {description}");
                TestContext.Out.WriteLine($"✓ {description}: Success");
            }
            else
            {
                _ = result.IsFailure.Should().BeTrue($"Parsing should fail for {description}");
                TestContext.Out.WriteLine($"✓ {description}: Failed as expected");
            }
        }
    }
}
