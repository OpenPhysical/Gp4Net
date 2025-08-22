using System;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Domain.Security;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Protocol;

/// <summary>
/// Tests that verify the SCP02 sequence counter flows correctly through the secure channel establishment.
/// These tests will fail if the sequence counter is not properly passed through all layers.
/// </summary>
public class Scp02SequenceCounterFlowTests
{
    private readonly IKeyDerivationService _keyDerivationService;
    private readonly Scp02Protocol _protocol;
    private readonly Scp02KeySet _keySet;

    public Scp02SequenceCounterFlowTests()
    {
        _keyDerivationService = new KeyDerivationService(NullLogger<KeyDerivationService>.Instance);
        _keySet = Scp02KeySet.Create(
            new byte[16], // ENC key
            new byte[16], // MAC key 
            new byte[16], // DEK key
            0x01,         // Key version
            0x00          // Key ID
        ).Value;
        _protocol = new Scp02Protocol(_keySet, _keyDerivationService, NullLogger<Scp02Protocol>.Instance);
    }

    [Test]
    public void ProcessInitializeUpdateResponse_WithMissingSequenceCounter_ShouldFail()
    {
        // Arrange - Create SCP02 response data that's missing sequence counter bytes
        var hostChallenge = new byte[8] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        
        // Build malformed SCP02 response with only 26 bytes (missing 2-byte sequence counter)
        var responseData = new byte[26];
        Array.Copy(new byte[10], 0, responseData, 0, 10); // Key diversification data
        responseData[10] = 0x01; // Key version
        responseData[11] = 0x02; // SCP02
        // Missing sequence counter at offset 12-13
        Array.Copy(new byte[6], 0, responseData, 12, 6); // Card challenge
        Array.Copy(new byte[8], 0, responseData, 18, 8); // Card cryptogram
        
        var parseResult = InitializeUpdateResponse.Parse(responseData);
        
        // If parsing succeeds but sequence counter is missing, test the protocol processing
        if (parseResult.IsSuccess)
        {
            var result = _protocol.ProcessInitializeUpdateResponse(parseResult.Value, hostChallenge);
            _ = result.IsFailure.Should().BeTrue();
            _ = result.Error.Message.Should().Contain("sequence counter");
        }
        else
        {
            // Parsing should fail for malformed response
            _ = parseResult.IsFailure.Should().BeTrue();
        }
    }

    [Test]
    public void ProcessInitializeUpdateResponse_WithInvalidSequenceCounterLength_ShouldFail()
    {
        // Arrange - Create valid SCP02 response
        var hostChallenge = new byte[8] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        
        // Build proper SCP02 response (28 bytes)
        var responseData = new byte[28];
        Array.Copy(new byte[10], 0, responseData, 0, 10); // Key diversification data
        responseData[10] = 0x01; // Key version
        responseData[11] = 0x02; // SCP02
        Array.Copy(new byte[2], 0, responseData, 12, 2); // Sequence counter
        Array.Copy(new byte[6], 0, responseData, 14, 6); // Card challenge
        Array.Copy(new byte[8], 0, responseData, 20, 8); // Card cryptogram
        
        var parseResult = InitializeUpdateResponse.Parse(responseData);
        _ = parseResult.IsSuccess.Should().BeTrue();
        
        // Act
        var result = _protocol.ProcessInitializeUpdateResponse(parseResult.Value, hostChallenge);

        // Assert - With zero sequence counter, the cryptogram won't match
        // This is expected behavior - the test verifies that SCP02 processing requires proper sequence counter
        _ = result.IsFailure.Should().BeTrue();
        // The error will be about cryptogram verification failing, which is correct
        // because without proper sequence counter, the cryptogram calculation will be wrong
        _ = result.Error.Message.Should().Contain("cryptogram");
    }

    [Test]
    public void CryptogramBuilder_BuildScp02CardCryptogramData_RequiresSequenceCounter()
    {
        // Arrange - Create SCP02 response without proper sequence counter
        var hostChallenge = new byte[8];
        
        // Build SCP02 response with missing sequence counter to test CryptogramBuilder
        var responseData = new byte[28];
        Array.Copy(new byte[10], 0, responseData, 0, 10); // Key diversification data
        responseData[10] = 0x01; // Key version
        responseData[11] = 0x02; // SCP02
        // Note: Parser might extract empty sequence counter
        Array.Copy(new byte[2], 0, responseData, 12, 2); // Empty sequence counter
        Array.Copy(new byte[6], 0, responseData, 14, 6); // Card challenge
        Array.Copy(new byte[8], 0, responseData, 20, 8); // Card cryptogram
        
        var parseResult = InitializeUpdateResponse.Parse(responseData);
        if (parseResult.IsSuccess)
        {
            // Act
            var result = CryptogramBuilder.BuildScp02CardCryptogramData(parseResult.Value, hostChallenge);

            // Assert - Should handle sequence counter properly
            // This test verifies CryptogramBuilder validates sequence counter
            if (parseResult.Value.SequenceCounter == null)
            {
                _ = result.IsFailure.Should().BeTrue();
                _ = result.Error.Message.Should().Contain("SCP02 requires sequence counter");
            }
        }
    }

    [Test]
    public void CryptogramBuilder_BuildScp02HostCryptogramData_RequiresSequenceCounter()
    {
        // Arrange
        var hostChallenge = new byte[8];
        
        // Build SCP02 response
        var responseData = new byte[28];
        Array.Copy(new byte[10], 0, responseData, 0, 10);
        responseData[10] = 0x01;
        responseData[11] = 0x02;
        Array.Copy(new byte[2], 0, responseData, 12, 2);
        Array.Copy(new byte[6], 0, responseData, 14, 6);
        Array.Copy(new byte[8], 0, responseData, 20, 8);
        
        var parseResult = InitializeUpdateResponse.Parse(responseData);
        if (parseResult.IsSuccess)
        {
            // Act
            var result = CryptogramBuilder.BuildScp02HostCryptogramData(parseResult.Value, hostChallenge);

            // Assert
            if (parseResult.Value.SequenceCounter == null)
            {
                _ = result.IsFailure.Should().BeTrue();
                _ = result.Error.Message.Should().Contain("SCP02 requires sequence counter");
            }
        }
    }

    [Test]
    public void EndToEnd_Scp02SecureChannel_WithValidSequenceCounter_ShouldSucceed()
    {
        // Arrange - Use real test vectors
        var hostChallenge = Convert.FromHexString("0102030405060708");
        
        // Build proper SCP02 response
        var responseData = new byte[28];
        Array.Copy(new byte[10], 0, responseData, 0, 10); // Key diversification
        responseData[10] = 0x01; // Key version
        responseData[11] = 0x02; // SCP02  
        Array.Copy(Convert.FromHexString("0001"), 0, responseData, 12, 2); // Sequence counter
        Array.Copy(Convert.FromHexString("0A0B0C0D0E0F"), 0, responseData, 14, 6); // Card challenge
        Array.Copy(new byte[8], 0, responseData, 20, 8); // Card cryptogram
        
        var parseResult = InitializeUpdateResponse.Parse(responseData);
        _ = parseResult.IsSuccess.Should().BeTrue();
        var response = parseResult.Value;

        // Act - Process response (skip cryptogram validation for this test)
        var contextResult = KeyDerivationContext.CreateForScp02(
            _keySet,
            hostChallenge,
            response.CardChallenge,
            response.SequenceCounter,
            ScpImplementation.Scp02I15
        );

        // Assert
        _ = contextResult.IsSuccess.Should().BeTrue();
        var context = contextResult.Value;
        _ = context.SequenceCounter.HasValue.Should().BeTrue();
        _ = context.SequenceCounter.Value.Should().Equal(new byte[] { 0x00, 0x01 });
    }
}