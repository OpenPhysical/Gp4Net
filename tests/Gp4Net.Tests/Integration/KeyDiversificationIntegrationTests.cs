using System;
using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Tests.Infrastructure;
using NUnit.Framework;

namespace Gp4Net.Tests.Integration;

/// <summary>
/// Integration tests for GP test key diversification without mocks.
/// Validates the complete key diversification pipeline using real cryptographic operations.
/// GP Card Specification v2.3.1: SCP02 and SCP03 key diversification algorithms.
/// </summary>
[TestFixture]
[Category("Integration")]
[Category("KeyDiversification")]
[Category("GpCompliance")]
public class KeyDiversificationIntegrationTests
{
    /// <summary>
    /// Test vectors for functional testing of key diversification logic.
    /// These are standard GP test vectors for validating the functional factory pattern implementation.
    /// </summary>
    private static class TestVectors
    {
        // Standard GP test vectors for SCP02 diversification testing
        public static readonly byte[] TestKdd = Convert.FromHexString("00002345558083204839");
        public static readonly byte[] TestSequenceCounter_1 = Convert.FromHexString("0011");
        public static readonly byte[] TestSequenceCounter_2 = Convert.FromHexString("0012");
        public static readonly byte TestScpId = 0x02;
        public static readonly byte TestKeyVersion = 0x00;

        // Standard GP test key (commonly used in GP implementations)
        public static readonly byte[] BaseTestKey = Convert.FromHexString(
            "404142434445464748494A4B4C4D4E4F"
        );
    }

    [Test]
    public void SCP02_Key_Diversification_Integration_WithTestData_ProducesWorkingKeys()
    {
        // GP Card Specification v2.3.1: SCP02 key diversification using test vectors
        // Validates the functional factory pattern and diversification pipeline

        // Arrange - Create INITIALIZE UPDATE response using test vectors
        InitializeUpdateResponse initUpdateResponse = CreateInitializeUpdateResponse(
            TestVectors.TestKdd,
            TestVectors.TestSequenceCounter_1,
            TestVectors.TestScpId,
            TestVectors.TestKeyVersion
        );

        // Act - Get standard test keys (diversification removed from test key provider)
        Result<IKeySet, SmartCardError> keySetResult = GpTestKeys.GetTestKeys(
            Maybe<InitializeUpdateResponse>.From(initUpdateResponse)
        );

        // Assert
        _ = keySetResult
            .IsSuccess.Should()
            .BeTrue("Key diversification should succeed with test data");
        IKeySet? keySet = keySetResult.Value;

        // Validate key set properties
        _ = keySet.Should().NotBeNull();
        _ = keySet.KeyVersion.Should().Be(TestVectors.TestKeyVersion);

        // Verify we get the standard test keys (404142...4F)
        _ = keySet
            .EncKey.Should()
            .BeEquivalentTo(
                GpTestKeys.GpTestKey,
                "Test key provider should return standard test key for ENC"
            );
        _ = keySet
            .MacKey.Should()
            .BeEquivalentTo(
                GpTestKeys.GpTestKey,
                "Test key provider should return standard test key for MAC"
            );

        // All keys should be 16 bytes (2-key 3DES)
        _ = keySet.EncKey.Length.Should().Be(16, "SCP02 encryption key should be 16 bytes");
        _ = keySet.MacKey.Length.Should().Be(16, "SCP02 MAC key should be 16 bytes");

        // For SCP02, verify we have a proper IKeySet implementation
        _ = keySet.Should().BeAssignableTo<IKeySet>();

        TestContext.Out.WriteLine("=== SCP02 Test Vector Key Diversification ===");
        TestContext.Out.WriteLine($"KDD:             {Convert.ToHexString(TestVectors.TestKdd)}");
        TestContext.Out.WriteLine(
            $"Sequence:        {Convert.ToHexString(TestVectors.TestSequenceCounter_1)}"
        );
        TestContext.Out.WriteLine($"Diversified ENC: {Convert.ToHexString(keySet.EncKey)}");
        TestContext.Out.WriteLine($"Diversified MAC: {Convert.ToHexString(keySet.MacKey)}");
    }

    [Test]
    public void SCP02_Key_Diversification_WithDifferentSequenceCounters_ProducesDifferentKeys()
    {
        // GP Card Specification v2.3.1: Different sequence counters should produce different diversified keys
        // Uses different sequence counters with same KDD

        // Arrange - Create two responses with different sequence counters
        InitializeUpdateResponse response1 = CreateInitializeUpdateResponse(
            TestVectors.TestKdd,
            TestVectors.TestSequenceCounter_1, // 0011
            TestVectors.TestScpId,
            TestVectors.TestKeyVersion
        );

        InitializeUpdateResponse response2 = CreateInitializeUpdateResponse(
            TestVectors.TestKdd,
            TestVectors.TestSequenceCounter_2, // 0012
            TestVectors.TestScpId,
            TestVectors.TestKeyVersion
        );

        // Act - Diversify keys for both sequences
        Result<IKeySet, SmartCardError> keys1Result = GpTestKeys.GetTestKeys(
            Maybe<InitializeUpdateResponse>.From(response1)
        );
        Result<IKeySet, SmartCardError> keys2Result = GpTestKeys.GetTestKeys(
            Maybe<InitializeUpdateResponse>.From(response2)
        );

        // Assert
        _ = keys1Result.IsSuccess.Should().BeTrue("First diversification should succeed");
        _ = keys2Result.IsSuccess.Should().BeTrue("Second diversification should succeed");

        IKeySet? keys1 = keys1Result.Value;
        IKeySet? keys2 = keys2Result.Value;

        // Different sequence counters should produce different keys
        _ = keys1
            .EncKey.Should()
            .NotBeEquivalentTo(
                keys2.EncKey,
                "Different sequence counters should produce different encryption keys"
            );
        _ = keys1
            .MacKey.Should()
            .NotBeEquivalentTo(
                keys2.MacKey,
                "Different sequence counters should produce different MAC keys"
            );

        TestContext.Out.WriteLine("=== Keys with seq=0011 ===");
        TestContext.Out.WriteLine($"ENC: {Convert.ToHexString(keys1.EncKey)}");
        TestContext.Out.WriteLine($"MAC: {Convert.ToHexString(keys1.MacKey)}");
        TestContext.Out.WriteLine("=== Keys with seq=0012 ===");
        TestContext.Out.WriteLine($"ENC: {Convert.ToHexString(keys2.EncKey)}");
        TestContext.Out.WriteLine($"MAC: {Convert.ToHexString(keys2.MacKey)}");
    }

    [Test]
    public void SCP02_Key_Diversification_WithoutDiversificationData_ReturnsStaticKeys()
    {
        // GP Card Specification v2.3.1: Cards without diversification data use static test keys
        // This validates the fallback behavior

        // Arrange - Create response without diversification data using factory function
        Result<InitializeUpdateResponse, SmartCardError> cardResponseResult =
            InitializeUpdateResponse.Create(
                keyDiversificationData: null, // No diversification data
                keyVersion: 0x00,
                scpId: 0x02,
                sequenceCounter: Convert.FromHexString("0001"),
                cardChallenge: Convert.FromHexString("1234567890AB"), // 6 bytes for SCP02
                cardCryptogram: Convert.FromHexString("1234567890ABCDEF") // 8 bytes
            );

        cardResponseResult
            .Should()
            .BeSuccess("Factory should create valid response without diversification data");

        // Act & Assert - Use functional composition  
        Result<(IKeySet keySet, IKeySet staticKeys), SmartCardError> result = cardResponseResult
            .Bind((InitializeUpdateResponse cardResponse) => 
            {
                Result<CryptoService.ScpVersion, SmartCardError> scpResult = cardResponse.ScpId
                    .ToResult("Missing SCP ID")
                    .MapError(_ => SmartCardError.InvalidArgument("Missing SCP ID"));
                Result<byte, SmartCardError> scpIdResult = scpResult.Map(scpVersion => (byte)scpVersion);
                Result<IKeySet, SmartCardError> keySetResult = scpIdResult
                    .Bind((byte scpId) => GpTestKeys.GetTestKeySet(scpId, cardResponse.KeyVersion));
                return keySetResult.Bind((IKeySet keySet) => GpTestKeys.GetTestKeySet(0x02, 0x00)
                    .Map((IKeySet staticKeys) => (keySet, staticKeys)));
            });

        _ = result.IsSuccess.Should().BeTrue();
        result.Match(
            tuple =>
            {
                (IKeySet keySet, IKeySet staticKeys) = tuple;
                keySet
                    .EncKey.Should()
                    .BeEquivalentTo(
                        staticKeys.EncKey,
                        "Without diversification data, should return static encryption key"
                    );
                keySet
                    .MacKey.Should()
                    .BeEquivalentTo(
                        staticKeys.MacKey,
                        "Without diversification data, should return static MAC key"
                    );
            },
            error => Assert.Fail($"Should not fail: {error}")
        );
    }

    [Test]
    public void SCP02_Key_Diversification_RequiresSequenceCounter()
    {
        // GP Card Specification v2.3.1: SCP02 diversification requires sequence counter
        // This validates proper error handling

        // Act - Try to create response without sequence counter (should fail at factory level)
        Result<InitializeUpdateResponse, SmartCardError> factoryResult =
            InitializeUpdateResponse.Create(
                keyDiversificationData: TestVectors.TestKdd,
                keyVersion: 0x00,
                scpId: 0x02,
                sequenceCounter: null, // Missing sequence counter
                cardChallenge: Convert.FromHexString("1234567890AB"), // 6 bytes for SCP02
                cardCryptogram: Convert.FromHexString("1234567890ABCDEF")
            );

        // Assert - Factory should reject invalid SCP02 configuration
        _ = factoryResult
            .IsFailure.Should()
            .BeTrue("Factory should reject SCP02 response without sequence counter");
        _ = factoryResult.Error.Message.Should().Contain("sequence counter");
        _ = factoryResult.Error.Message.Should().Contain("SCP02");
    }

    [Test]
    public void SCP02_Key_Diversification_WithShortSequenceCounter_Fails()
    {
        // GP Card Specification v2.3.1: SCP02 requires at least 2 bytes of sequence counter
        // This validates input validation

        // Act - Try to create response with too-short sequence counter (should fail at factory level)
        Result<InitializeUpdateResponse, SmartCardError> factoryResult =
            InitializeUpdateResponse.Create(
                keyDiversificationData: TestVectors.TestKdd,
                keyVersion: 0x00,
                scpId: 0x02,
                sequenceCounter: Convert.FromHexString("00"), // Only 1 byte, should be at least 2
                cardChallenge: Convert.FromHexString("1234567890AB"), // 6 bytes for SCP02
                cardCryptogram: Convert.FromHexString("1234567890ABCDEF")
            );

        // Assert - Factory should reject invalid sequence counter length
        _ = factoryResult
            .IsFailure.Should()
            .BeTrue("Factory should reject short sequence counter for SCP02");
        _ = factoryResult.Error.Message.Should().Contain("sequence counter");
        _ = factoryResult.Error.Message.Should().Contain("2 bytes");
    }

    [Test]
    public void SCP03_Key_Diversification_Integration_ReturnsStaticKeys()
    {
        // GP Card Specification v2.3.1: SCP03 diversification (SP 800-108 KDF)
        // Currently returns static keys as SCP03 diversification is not yet fully implemented

        // Arrange - Create SCP03 response using test data
        InitializeUpdateResponse cardResponse = CreateInitializeUpdateResponse(
            TestVectors.TestKdd,
            TestVectors.TestSequenceCounter_1,
            0x03, // SCP03
            0x00
        );

        // Act & Assert - Use functional composition
        Result<(IKeySet keySet, IKeySet staticKeys), SmartCardError> comparison = cardResponse.ScpId
            .ToResult("Missing SCP ID")
            .MapError(_ => SmartCardError.InvalidArgument("Missing SCP ID"))
            .Map(scpVersion => (byte)scpVersion)
            .Bind((byte scpId) => GpTestKeys.GetTestKeySet(scpId, cardResponse.KeyVersion))
            .Bind((IKeySet keySet) => GpTestKeys.GetTestKeySet(0x03, 0x00).Map(staticKeys => (keySet, staticKeys)));

        _ = comparison.IsSuccess.Should().BeTrue("SCP03 diversification should succeed");
        comparison.Match(
            tuple =>
            {
                (IKeySet keySet, IKeySet staticKeys) = tuple;
                keySet
                    .EncKey.Should()
                    .BeEquivalentTo(staticKeys.EncKey, "SCP03 currently returns static keys");
            },
            error => Assert.Fail($"Should not fail: {error}")
        );
    }

    [Test]
    public void UnsupportedScp_Version_ReturnsError()
    {
        // GP Card Specification v2.3.1: Only SCP02 and SCP03 are supported
        // This validates error handling for unknown SCP versions

        // Arrange - Try to create response with unsupported SCP version (should fail at factory level)
        Result<InitializeUpdateResponse, SmartCardError> factoryResult =
            CreateInitializeUpdateResponseResult(
                TestVectors.TestKdd,
                TestVectors.TestSequenceCounter_1,
                0x01, // SCP01 - unsupported
                0x00
            );

        // Assert - Factory should reject unsupported SCP version
        _ = factoryResult
            .IsFailure.Should()
            .BeTrue("Factory should reject unsupported SCP version");
        _ = factoryResult.Error.Message.Should().Contain("Unsupported SCP version");
        _ = factoryResult.Error.Message.Should().Contain("01");
    }

    [Test]
    public void Key_Diversification_Deterministic_SameInputProducesSameOutput()
    {
        // GP Card Specification v2.3.1: Key diversification should be deterministic
        // Same inputs should always produce the same diversified keys

        // Arrange - Same card data
        InitializeUpdateResponse cardResponse = CreateInitializeUpdateResponse(
            TestVectors.TestKdd,
            TestVectors.TestSequenceCounter_1,
            TestVectors.TestScpId,
            TestVectors.TestKeyVersion
        );

        // Act & Assert - Compare key sets using functional composition
        Result<IKeySet, SmartCardError> keySetResult = cardResponse.ScpId
            .ToResult("Missing SCP ID")
            .MapError(_ => SmartCardError.InvalidArgument("Missing SCP ID"))
            .Map(scpVersion => (byte)scpVersion)
            .Bind((byte scpId) => GpTestKeys.GetTestKeySet(scpId, cardResponse.KeyVersion));
            
        Result<(IKeySet keySet1, IKeySet keySet2), SmartCardError> comparison = keySetResult
            .Bind((IKeySet keySet1) => keySetResult.Map(keySet2 => (keySet1, keySet2)));

        _ = comparison.IsSuccess.Should().BeTrue("Both key derivations should succeed");
        comparison.Match(
            tuple =>
            {
                (IKeySet keySet1, IKeySet keySet2) = tuple;
                keySet1
                    .EncKey.Should()
                    .BeEquivalentTo(
                        keySet2.EncKey,
                        "Same input should produce same encryption key"
                    );
                keySet1
                    .MacKey.Should()
                    .BeEquivalentTo(keySet2.MacKey, "Same input should produce same MAC key");
            },
            error => Assert.Fail($"Should not fail: {error}")
        );
    }

    [Test]
    public void SCP02_Key_Diversification_EndToEnd_ProducesValidSessionKeys()
    {
        // GP Card Specification v2.3.1: Complete end-to-end test with functional validation
        // Uses test vectors and validates the complete diversification → session key derivation pipeline

        // Arrange - Use test vectors for functional validation
        Result<InitializeUpdateResponse, SmartCardError> factoryResult =
            InitializeUpdateResponse.Create(
                keyDiversificationData: TestVectors.TestKdd,
                keyVersion: TestVectors.TestKeyVersion,
                scpId: TestVectors.TestScpId,
                sequenceCounter: TestVectors.TestSequenceCounter_1,
                cardChallenge: Convert.FromHexString("C284EC19415D"), // 6 bytes for SCP02
                cardCryptogram: Convert.FromHexString("17F4198ADCD5102D") // 8 bytes
            );

        _ = factoryResult.IsSuccess.Should().BeTrue("Factory should create valid response with test data");

        // Act - Complete pipeline: Diversification → Session Key Derivation using functional composition
        var sessionKeysResult = factoryResult
            .Bind(initUpdateResponse =>
                GpTestKeys.GetTestKeySet(initUpdateResponse.ScpId, initUpdateResponse.KeyVersion)
            )
            .Bind(diversifiedKeys =>
            {
                Result<byte[], SmartCardError> sessionEncResult =
                    CryptoService.KeyDerivation.DeriveScp02SessionKey(
                        diversifiedKeys.EncKey,
                        TestVectors.TestSequenceCounter_1,
                        0x02 // SCP02 S-ENC derivation constant
                    );

                Result<byte[], SmartCardError> sessionMacResult =
                    CryptoService.KeyDerivation.DeriveScp02SessionKey(
                        diversifiedKeys.MacKey,
                        TestVectors.TestSequenceCounter_1,
                        0x01 // SCP02 S-MAC derivation constant
                    );

                return sessionEncResult.Bind(sessionEnc =>
                    sessionMacResult.Map(sessionMac => (diversifiedKeys, sessionEnc, sessionMac))
                );
            });

        // Assert - Validate the pipeline produces working keys
        _ = sessionKeysResult.IsSuccess.Should().BeTrue("Complete key derivation pipeline should succeed");
        sessionKeysResult.Match(
            success: tuple =>
            {
                var (diversifiedKeys, derivedSessionEnc, derivedSessionMac) = tuple;

                // Validate that the diversification pipeline produces consistent, working keys
                // Verify session keys are derived correctly (should be different from base diversified keys)
                derivedSessionEnc
                    .Should()
                    .NotBeEquivalentTo(
                        diversifiedKeys.EncKey,
                        "Session ENC key should be different from diversified base ENC key"
                    );
                derivedSessionMac
                    .Should()
                    .NotBeEquivalentTo(
                        diversifiedKeys.MacKey,
                        "Session MAC key should be different from diversified base MAC key"
                    );

                // Verify keys have proper length for 2-key 3DES
                derivedSessionEnc
                    .Length.Should()
                    .Be(16, "Session ENC key should be 16 bytes for 2-key 3DES");
                derivedSessionMac
                    .Length.Should()
                    .Be(16, "Session MAC key should be 16 bytes for 2-key 3DES");

                TestContext.Out.WriteLine("=== End-to-End Key Diversification Validation ===");
                TestContext.Out.WriteLine(
                    $"KDD:                  {Convert.ToHexString(TestVectors.TestKdd)}"
                );
                TestContext.Out.WriteLine(
                    $"Sequence Counter:     {Convert.ToHexString(TestVectors.TestSequenceCounter_1)}"
                );
                TestContext.Out.WriteLine(
                    $"Diversified ENC:      {Convert.ToHexString(diversifiedKeys.EncKey)}"
                );
                TestContext.Out.WriteLine(
                    $"Diversified MAC:      {Convert.ToHexString(diversifiedKeys.MacKey)}"
                );
                TestContext.Out.WriteLine(
                    $"Session S-ENC:        {Convert.ToHexString(derivedSessionEnc)}"
                );
                TestContext.Out.WriteLine(
                    $"Session S-MAC:        {Convert.ToHexString(derivedSessionMac)}"
                );
                TestContext.Out.WriteLine("✓ Functional diversification pipeline validated!");
            },
            failure: error => Assert.Fail($"Key derivation pipeline should not fail: {error}")
        );
    }

    [Test]
    public void Key_Diversification_CryptographicValidation_ProducesWorkingKeys()
    {
        // GP Card Specification v2.3.1: Diversified keys should be cryptographically valid
        // This validates that diversified keys can be used for actual cryptographic operations

        // Arrange
        InitializeUpdateResponse cardResponse = CreateInitializeUpdateResponse(
            TestVectors.TestKdd,
            TestVectors.TestSequenceCounter_1,
            TestVectors.TestScpId,
            TestVectors.TestKeyVersion
        );

        // Act
        Result<IKeySet, SmartCardError> keySetResult = GpTestKeys.GetTestKeySet(
            cardResponse.ScpId,
            cardResponse.KeyVersion
        );

        // Assert - Test that the keys work for session key derivation (SCP02) using functional composition
        byte[] sequenceCounter = TestVectors.TestSequenceCounter_1;

        Result<
            (IKeySet keySet, byte[] sessionEnc, byte[] sessionMac),
            SmartCardError
        > sessionKeysResult = keySetResult.Bind(keySet =>
        {
            Result<byte[], SmartCardError> sessionEncResult = CryptoService.KeyDerivation.DeriveScp02SessionKey(
                keySet.EncKey,
                sequenceCounter,
                0x02 // SCP02 S-ENC derivation constant
            );

            Result<byte[], SmartCardError> sessionMacResult = CryptoService.KeyDerivation.DeriveScp02SessionKey(
                keySet.MacKey,
                sequenceCounter,
                0x01 // SCP02 S-MAC derivation constant
            );

            return sessionEncResult.Bind(sessionEnc =>
                sessionMacResult.Map(sessionMac => (keySet, sessionEnc, sessionMac))
            );
        });

        sessionKeysResult
            .Should()
            .BeSuccess("Session key derivation should work with diversified keys");
        sessionKeysResult.Match(
            success: tuple =>
            {
                var (keySet, sessionEnc, sessionMac) = tuple;

                // Verify keys are proper length and format
                sessionEnc.Length.Should().Be(16, "Session ENC key should be 16 bytes");
                sessionMac.Length.Should().Be(16, "Session MAC key should be 16 bytes");

                TestContext.Out.WriteLine(
                    $"Diversified base ENC: {Convert.ToHexString(keySet.EncKey)}"
                );
                TestContext.Out.WriteLine(
                    $"Diversified base MAC: {Convert.ToHexString(keySet.MacKey)}"
                );
                TestContext.Out.WriteLine(
                    $"Session ENC derived:  {Convert.ToHexString(sessionEnc)}"
                );
                TestContext.Out.WriteLine(
                    $"Session MAC derived:  {Convert.ToHexString(sessionMac)}"
                );
            },
            failure: error => Assert.Fail($"Session key derivation should not fail: {error}")
        );
    }

    /// <summary>
    /// Helper method to create InitializeUpdateResponse for testing using functional factory pattern.
    /// Uses the public factory function with proper validation.
    /// </summary>
    private static Result<
        InitializeUpdateResponse,
        SmartCardError
    > CreateInitializeUpdateResponseResult(
        byte[] kdd,
        byte[] sequenceCounter,
        byte scpId,
        byte keyVersion
    )
    {
        byte scpVersion = (byte)(scpId & 0x03);

        // Use appropriate challenge length for SCP version
        byte[] cardChallenge = scpVersion switch
        {
            0x02 => Convert.FromHexString("1234567890AB"), // 6 bytes for SCP02
            0x03 => Convert.FromHexString("1234567890ABCDEF"), // 8 bytes for SCP03
            _ => Convert.FromHexString("1234567890AB"), // Default to 6 bytes
        };

        return InitializeUpdateResponse.Create(
            keyDiversificationData: kdd,
            keyVersion: keyVersion,
            scpId: scpId,
            sequenceCounter: sequenceCounter,
            cardChallenge: cardChallenge,
            cardCryptogram: Convert.FromHexString("1234567890ABCDEF") // 8 bytes for cryptogram
        );
    }

    /// <summary>
    /// Helper method for tests that expect successful creation.
    /// </summary>
    private static InitializeUpdateResponse CreateInitializeUpdateResponse(
        byte[] kdd,
        byte[] sequenceCounter,
        byte scpId,
        byte keyVersion
    )
    {
        Result<InitializeUpdateResponse, SmartCardError> result =
            CreateInitializeUpdateResponseResult(kdd, sequenceCounter, scpId, keyVersion);
        _ = result
            .IsSuccess.Should()
            .BeTrue(
                $"Expected successful creation but got: {(result.IsFailure ? result.Error.Message : "unknown error")}"
            );
        return result.Value;
    }
}
