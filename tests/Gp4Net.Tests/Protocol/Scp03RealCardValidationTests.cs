// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
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
        byte[] responseData = vector.InitializeUpdateResponse.Take(vector.InitializeUpdateResponse.Length - 2).ToArray(); // Remove SW1SW2

        // Debug: Print the actual data
        Console.WriteLine($"Full response: {Convert.ToHexString(vector.InitializeUpdateResponse)}");
        Console.WriteLine($"Response data (without SW): {Convert.ToHexString(responseData)}");
        Console.WriteLine($"Expected KDD: {Convert.ToHexString(vector.KDD)}");
        Console.WriteLine($"Expected SCP Version: 0x{vector.ScpVersion:X2}");
        Console.WriteLine($"Expected Implementation Option: 0x{vector.ImplementationOption:X2}");

        Result<InitializeUpdateResponse, SmartCardError> responseResult = InitializeUpdateResponse.Parse(responseData);

        // Assert parsing succeeded
        _ = responseResult.IsSuccess.Should().BeTrue($"Failed to parse INITIALIZE UPDATE response for {vector.Name}");
        InitializeUpdateResponse? response = responseResult.Value;

        Console.WriteLine($"Parsed KDD: {Convert.ToHexString(response.KeyDiversificationData)}");
        Console.WriteLine($"Parsed ScpId: 0x{response.ScpId:X2}");
        Console.WriteLine($"Parsed ScpParameter: 0x{response.ScpParameter:X2}");

        // Validate parsed components match trace data
        _ = response.KeyDiversificationData.Should().BeEquivalentTo(vector.KDD,
            $"KDD parsing failed for {vector.Name}");
        _ = response.CardChallenge.Should().BeEquivalentTo(vector.CardChallenge,
            $"Card challenge parsing failed for {vector.Name}");
        _ = response.CardCryptogram.Should().BeEquivalentTo(vector.ExpectedCardCryptogram,
            $"Card cryptogram parsing failed for {vector.Name}");
        _ = response.ScpId.Should().Be(vector.ScpVersion,
            $"SCP version parsing failed for {vector.Name}");
        _ = response.ScpParameter.Should().Be(vector.ImplementationOption,
            $"Implementation option parsing failed for {vector.Name}");
    }

    [Test]
    public void SCP03_RealCardVector_DataIntegrity_AllFieldsPopulated()
    {
        // Validate that our real card test vector has all required data
        Scp03RealCardTestVector vector = Scp03RealCardTestVectors.P71_SCP03_Session;

        _ = vector.Name.Should().NotBeNullOrEmpty();
        _ = vector.Description.Should().NotBeNullOrEmpty();
        _ = vector.CardInfo.Should().NotBeNull();
        _ = vector.CardInfo.ATR.Should().NotBeEmpty();
        _ = vector.CardInfo.ISD_AID.Should().NotBeEmpty();
        _ = vector.StaticKeyEnc.Should().HaveCount(16);
        _ = vector.StaticKeyMac.Should().HaveCount(16);
        _ = vector.StaticKeyDek.Should().HaveCount(16);
        _ = vector.HostChallenge.Should().HaveCount(8);
        _ = vector.CardChallenge.Should().HaveCount(8);
        _ = vector.ExpectedSEnc.Should().HaveCount(16);
        _ = vector.ExpectedSMac.Should().HaveCount(16);
        _ = vector.ExpectedSRMac.Should().HaveCount(16);
        _ = vector.ExpectedCardCryptogram.Should().HaveCount(8);
        _ = vector.ExpectedHostCryptogram.Should().HaveCount(8);
        _ = vector.InitializeUpdateCommand.Should().NotBeEmpty();
        _ = vector.InitializeUpdateResponse.Should().NotBeEmpty();
        _ = vector.ExternalAuthenticateCommand.Should().NotBeEmpty();
        _ = vector.ExternalAuthenticateResponse.Should().NotBeEmpty();
    }

    [Test]
    public void SCP03_RealCardVector_P71_SupportsExpectedCapabilities()
    {
        // Validate P71 card capabilities match expected values from trace
        Scp03RealCardTestVector vector = Scp03RealCardTestVectors.P71_SCP03_Session;

        _ = vector.SupportedSCPVersions.Should().Contain("i=70",
            "P71 card should support SCP03 i=70");
        _ = vector.SupportedKeyLengths.Should().Contain("AES-128",
            "P71 card should support AES-128");
        _ = vector.SupportedPrivileges.Should().Contain("SecurityDomain",
            "P71 card should support SecurityDomain privilege");

        // Validate implementation option
        _ = vector.ImplementationOption.Should().Be(0x70,
            "P71 card uses SCP03 i=70");

        // Validate key version
        _ = vector.KeyVersion.Should().Be(0x01,
            "P71 card uses key version 01");
    }
}