using System;
using System.Collections.Generic;
using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Commands;
using NUnit.Framework;

namespace Gp4Net.Tests.Integration;

/// <summary>
/// Tests to validate the fixes for all identified specification compliance issues.
/// </summary>
[TestFixture]
[Category("Integration")]
[Category("Compliance")]
public class SpecificationComplianceValidationTests
{
    [Test]
    public void DeleteTokenCalculator_UsesFunctionalErrorHandling()
    {
        // Arrange: Test the functional Result<T> pattern that replaced try-catch
        var validKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var validAid = Convert.FromHexString("A0000003080000100001");
        
        // Act & Assert: Test various validation scenarios
        
        // Invalid key length
        var invalidKey = new byte[15];
        var result1 = DeleteTokenCalculator.ComputeDeleteToken(
            invalidKey, 0x00, 0x80, validAid, Maybe<byte[]>.None);

        _ = result1.IsFailure.Should().BeTrue("Invalid key length should return Result.Failure, not throw exception");
        _ = result1.Error.Message.Should().Contain("Delete Token MAC key must be 16, 24, or 32 bytes");
        
        // Empty AID
        var emptyAid = Array.Empty<byte>();
        var result2 = DeleteTokenCalculator.ComputeDeleteToken(
            validKey, 0x00, 0x80, emptyAid, Maybe<byte[]>.None);

        _ = result2.IsFailure.Should().BeTrue("Empty AID should return Result.Failure, not throw exception");
        _ = result2.Error.Message.Should().Contain("AID cannot be empty");
        
        // AID too short
        var shortAid = new byte[4]; // Must be 5-16 bytes
        var result3 = DeleteTokenCalculator.ComputeDeleteToken(
            validKey, 0x00, 0x80, shortAid, Maybe<byte[]>.None);

        _ = result3.IsFailure.Should().BeTrue("Short AID should return Result.Failure, not throw exception");
        _ = result3.Error.Message.Should().Contain("AID length must be 5-16 bytes");
        
        // Valid case
        var result4 = DeleteTokenCalculator.ComputeDeleteToken(
            validKey, 0x00, 0x80, validAid, Maybe<byte[]>.None);

        _ = result4.IsSuccess.Should().BeTrue("Valid parameters should succeed");
        _ = result4.Value.Length.Should().Be(16, "AES-CMAC should produce 16-byte token");
    }

    [Test]
    public void DeleteCommand_TokenFormat_MatchesTraceStructure()
    {
        // Arrange: Based on real DELETE command from traces
        // Command structure: 84E40080134F09A000000308000010007547C55C046E221C
        var aid = Convert.FromHexString("A00000030800001000");
        var expectedToken = Convert.FromHexString("7547C55C046E221C");
        
        // Act: Create DELETE command with same parameters
        var deleteCommandResult = DeleteCommand.CreateForApplication(
            aid,
            deleteRelated: true,
            deletionToken: expectedToken
        );

        _ = deleteCommandResult.IsSuccess.Should().BeTrue("DELETE command creation should succeed");
        var deleteCommand = deleteCommandResult.Value;
        
        // Get APDU bytes
        var apduBytes = deleteCommand.ToApdu();

        // Assert: Command should follow GP Table 11-23 format
        _ = apduBytes[0].Should().Be(0x80, "CLA should be 0x80 for plain command");
        _ = apduBytes[1].Should().Be(0xE4, "INS should be DELETE (0xE4)");
        _ = apduBytes[2].Should().Be(0x00, "P1 should be 0x00 (delete object and related)");
        _ = apduBytes[3].Should().Be(0x80, "P2 should be 0x80 (with related objects)");

        // Verify AID TLV structure: 4F <len> <AID>
        _ = apduBytes[5].Should().Be(0x4F, "AID tag should be 0x4F");
        _ = apduBytes[6].Should().Be((byte)aid.Length, "AID length should match");
        
        // Verify token is appended directly without length prefix per trace analysis
        var tokenOffset = 7 + aid.Length;
        var tokenInApdu = apduBytes.Skip(tokenOffset).Take(expectedToken.Length).ToArray();
        _ = tokenInApdu.Should().BeEquivalentTo(expectedToken,
            "Deletion token should be appended directly without length prefix per GP Table 11-23");
    }

    [Test]
    public void InitializeUpdateResponse_VariableLengths_AllValidPerGpSpec()
    {
        // Arrange: Test the variable length support (28+ bytes) that was added
        
        // Factory unlock trace - 29 bytes (real trace data)
        var factoryResponse = Convert.FromHexString(
            "00002345558083204839FF020003A33DFDBFFADF57EB6A4A52CFB3E9");
            
        // SCP02 lock trace - 28 bytes (real trace data)
        var scp02Response = Convert.FromHexString(
            "000023455580832048390102000303D2C0BAFBF0D31B42E57648A0C5");
            
        // SCP03 trace - 32 bytes (real trace data)
        var scp03Response = Convert.FromHexString(
            "0370000000000000000001037083FA042C5C10F778148C0CAF84B0E110000002");

        // Act & Assert: All real traces should parse successfully
        var factoryResult = InitializeUpdateResponse.Parse(factoryResponse);
        _ = factoryResult.IsSuccess.Should().BeTrue("Factory unlock trace (29 bytes) should parse successfully");
        
        var scp02Result = InitializeUpdateResponse.Parse(scp02Response);
        _ = scp02Result.IsSuccess.Should().BeTrue("SCP02 lock trace (28 bytes) should parse successfully");
        
        var scp03Result = InitializeUpdateResponse.Parse(scp03Response);
        _ = scp03Result.IsSuccess.Should().BeTrue("SCP03 trace (32 bytes) should parse successfully");
    }

    [Test]
    public void InitializeUpdateResponse_InvalidLengths_ReturnsError()
    {
        // Arrange: Test lengths outside the GP spec minimum
        
        // Below minimum (27 bytes)
        var tooShortResponse = new byte[27];
        
        // Act & Assert: Only lengths below minimum should be rejected
        var shortResult = InitializeUpdateResponse.Parse(tooShortResponse);
        _ = shortResult.IsFailure.Should().BeTrue("27-byte response should be invalid (below minimum)");
        _ = shortResult.Error.Message.Should().Contain("INITIALIZE UPDATE response too short: 27 bytes, expected at least 28");
        
        // Test that larger responses are now accepted (real-world traces show up to 35+ bytes)
        var largeResponse = new byte[35];
        // Fill with minimal valid structure
        largeResponse[10] = 0x01; // Key version
        largeResponse[11] = 0x03; // SCP ID
        
        var largeResult = InitializeUpdateResponse.Parse(largeResponse);
        _ = largeResult.IsSuccess.Should().BeTrue("35-byte response should be valid (real-world trace data)");
    }

    [Test]
    public void GetStatusResponse_UsesE3ContainersOnly()
    {
        // Arrange: Test E3 container compliance (already fixed, but validate it works)
        // Valid TLV: E3 (template) containing 4F (AID), 9F70 (state), C5 (privileges)
        var aid = Convert.FromHexString("A0000000031010");
        var tlvData = BuildE3ContainerResponse(aid, 0x07, [0x80, 0x00, 0x00]);
        
        // Act: Parse the response
        var result = GetStatusResponse.Parse(tlvData);

        // Assert: Should parse successfully with E3 containers
        _ = result.IsSuccess.Should().BeTrue("E3 container format should parse successfully per GP Table 11-36");
        _ = result.Value.Applications.Should().HaveCount(1, "Should parse one application");
        
        var app = result.Value.Applications[0];
        _ = app.Aid.Should().BeEquivalentTo(aid, "AID should be parsed correctly");
        _ = app.State.Should().Be(ApplicationStatusEntry.LifecycleState.Selectable, "State should be parsed correctly");
        _ = app.Privileges.Should().BeEquivalentTo(new byte[] { 0x80, 0x00, 0x00 }, "Privileges should be parsed correctly");
    }

    private static byte[] BuildE3ContainerResponse(byte[] aid, byte lifecycleState, byte[] privileges)
    {
        var inner = new List<byte>();
        inner.Add(0x4F); 
        inner.Add((byte)aid.Length); 
        inner.AddRange(aid);
        inner.Add(0x9F); 
        inner.Add(0x70); 
        inner.Add(0x01); 
        inner.Add(lifecycleState);
        if (privileges != null && privileges.Length > 0)
        {
            inner.Add(0xC5); 
            inner.Add((byte)privileges.Length); 
            inner.AddRange(privileges);
        }
        
        var e3Container = new List<byte>();
        e3Container.Add(0xE3); 
        e3Container.Add((byte)inner.Count); 
        e3Container.AddRange(inner);
        return e3Container.ToArray();
    }
}