// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Linq;
using AwesomeAssertions;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace Gp4Net.Tests.Protocol;

/// <summary>
/// Validates SCP03 implementation against real card traces.
/// These tests ensure our implementation matches actual card behavior.
/// </summary>
[TestFixture]
[Category("Protocol")]
public class Scp03RealCardValidationTests
{
    private IKeyDerivationService _keyDerivationService;

    [SetUp]
    public void SetUp()
    {
        _keyDerivationService = new KeyDerivationService(
            NullLogger<KeyDerivationService>.Instance);
    }

    [Test]
    [TestCaseSource(typeof(Scp03RealCardTestVectors), nameof(Scp03RealCardTestVectors.AllVectors))]
    public void SCP03_InitializeUpdateParsing_WithRealCardResponse_ParsesCorrectly(Scp03RealCardTestVector vector)
    {
        // Test parsing of real INITIALIZE UPDATE response
        var responseData = vector.InitializeUpdateResponse.Take(vector.InitializeUpdateResponse.Length - 2).ToArray(); // Remove SW1SW2
        
        // Debug: Print the actual data
        Console.WriteLine($"Full response: {Convert.ToHexString(vector.InitializeUpdateResponse)}");
        Console.WriteLine($"Response data (without SW): {Convert.ToHexString(responseData)}");
        Console.WriteLine($"Expected KDD: {Convert.ToHexString(vector.KDD)}");
        Console.WriteLine($"Expected SCP Version: 0x{vector.ScpVersion:X2}");
        Console.WriteLine($"Expected Implementation Option: 0x{vector.ImplementationOption:X2}");
        
        var responseResult = InitializeUpdateResponse.Parse(responseData);
        
        // Assert parsing succeeded
        responseResult.IsSuccess.Should().BeTrue($"Failed to parse INITIALIZE UPDATE response for {vector.Name}");
        var response = responseResult.Value;
        
        Console.WriteLine($"Parsed KDD: {Convert.ToHexString(response.KeyDiversificationData)}");
        Console.WriteLine($"Parsed ScpId: 0x{response.ScpId:X2}");
        Console.WriteLine($"Parsed ScpParameter: 0x{response.ScpParameter:X2}");
        
        // Validate parsed components match trace data
        response.KeyDiversificationData.Should().BeEquivalentTo(vector.KDD,
            $"KDD parsing failed for {vector.Name}");
        response.CardChallenge.Should().BeEquivalentTo(vector.CardChallenge,
            $"Card challenge parsing failed for {vector.Name}");
        response.CardCryptogram.Should().BeEquivalentTo(vector.ExpectedCardCryptogram,
            $"Card cryptogram parsing failed for {vector.Name}");
        response.ScpId.Should().Be(vector.ScpVersion,
            $"SCP version parsing failed for {vector.Name}");
        response.ScpParameter.Should().Be(vector.ImplementationOption,
            $"Implementation option parsing failed for {vector.Name}");
    }
    
    [Test]
    public void SCP03_RealCardVector_DataIntegrity_AllFieldsPopulated()
    {
        // Validate that our real card test vector has all required data
        var vector = Scp03RealCardTestVectors.P71_SCP03_Session;
        
        vector.Name.Should().NotBeNullOrEmpty();
        vector.Description.Should().NotBeNullOrEmpty();
        vector.CardInfo.Should().NotBeNull();
        vector.CardInfo.ATR.Should().NotBeEmpty();
        vector.CardInfo.ISD_AID.Should().NotBeEmpty();
        vector.StaticKeyEnc.Should().HaveCount(16);
        vector.StaticKeyMac.Should().HaveCount(16);
        vector.StaticKeyDek.Should().HaveCount(16);
        vector.HostChallenge.Should().HaveCount(8);
        vector.CardChallenge.Should().HaveCount(8);
        vector.ExpectedSEnc.Should().HaveCount(16);
        vector.ExpectedSMac.Should().HaveCount(16);
        vector.ExpectedSRMac.Should().HaveCount(16);
        vector.ExpectedCardCryptogram.Should().HaveCount(8);
        vector.ExpectedHostCryptogram.Should().HaveCount(8);
        vector.InitializeUpdateCommand.Should().NotBeEmpty();
        vector.InitializeUpdateResponse.Should().NotBeEmpty();
        vector.ExternalAuthenticateCommand.Should().NotBeEmpty();
        vector.ExternalAuthenticateResponse.Should().NotBeEmpty();
    }
    
    [Test]
    public void SCP03_RealCardVector_P71_SupportsExpectedCapabilities()
    {
        // Validate P71 card capabilities match expected values from trace
        var vector = Scp03RealCardTestVectors.P71_SCP03_Session;
        
        vector.SupportedSCPVersions.Should().Contain("i=70", 
            "P71 card should support SCP03 i=70");
        vector.SupportedKeyLengths.Should().Contain("AES-128",
            "P71 card should support AES-128");
        vector.SupportedPrivileges.Should().Contain("SecurityDomain",
            "P71 card should support SecurityDomain privilege");
        
        // Validate implementation option
        vector.ImplementationOption.Should().Be(0x70,
            "P71 card uses SCP03 i=70");
        
        // Validate key version
        vector.KeyVersion.Should().Be(0x01,
            "P71 card uses key version 01");
    }
}