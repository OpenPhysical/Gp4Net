using System;
using System.Collections.Immutable;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using static Gp4Net.Constants.Constants.GlobalPlatform;
using ScpVersion = Gp4Net.Cryptography.CryptoOperations.ScpVersion;

namespace Gp4Net.CardEmulator.Tests.Functional;

/// <summary>
/// Tests for CardStateTransitions ensuring proper immutable state management.
/// Validates all state transitions are pure functions with no side effects.
/// </summary>
[TestFixture]
public class CardStateServiceTests
{
    private readonly CardStateTransitions _stateService =
        new(Maybe<ILogger>.From(NullLogger.Instance));

    [Test]
    public void CreateInitialState_Success_ReturnsValidCardState()
    {
        var result = _stateService.CreateInitialState();

        _ = result.IsSuccess.Should().BeTrue();
        result.Match(
            state =>
            {
                _ = state.IsSelected.Should().BeTrue();
                _ = state.ScpVersion.Should().Be(Protocols.SCP02);
                _ = state.ScpImplementation.Should().Be(ScpImplementation.Scp02I15);
                _ = state.ApplicationRegistry.HasValue.Should().BeTrue();
            },
            error => Assert.Fail($"Expected success but got error: {error}")
        );
    }

    [Test]
    public void CreateInitialState_WithUuid_Success_ReturnsStateWithSpecificUuid()
    {
        var expectedUuid = CardUuid.Generate().Value;

        var result = _stateService.CreateInitialState(expectedUuid);

        _ = result.IsSuccess.Should().BeTrue();
        result.Match(
            state =>
            {
                _ = state.Uuid.Should().Be(expectedUuid);
                _ = state.ApplicationRegistry.HasValue.Should().BeTrue();
            },
            error => Assert.Fail($"Expected success but got error: {error}")
        );
    }

    [Test]
    public void ApplyCommand_ValidCommand_Success_ReturnsNewState()
    {
        var initialStateResult = CreateValidInitialState();
        var selectCommandResult = CreateSelectCommand();
        var configResult = CardConfiguration.P71();
        var rngContext = new TestRngContext();

        var result = initialStateResult.Bind(initialState =>
            selectCommandResult.Bind(selectCommand =>
                configResult.Bind(config =>
                    _stateService.ApplyCommand(initialState, selectCommand, config, rngContext)
                )
            )
        );

        _ = result.IsSuccess.Should().BeTrue();
        if (result.IsFailure)
        {
            Assert.Fail($"Expected success but got error: {result.Error}");
        }
        if (result.IsSuccess)
        {
            var newState = result.Value;

            if (initialStateResult.IsFailure)
            {
                Assert.Fail("Initial state should be valid");
            }
            if (initialStateResult.IsSuccess)
            {
                var originalState = initialStateResult.Value;
                Assert.That(newState, Is.Not.EqualTo(originalState));
            }
        }
    }

    [Test]
    public void ApplyCommand_InvalidCommand_Failure_ReturnsError()
    {
        var initialStateResult = CreateValidInitialState();
        var invalidCommandResult = CreateInvalidCommand();
        var configResult = CardConfiguration.P71();
        var rngContext = new TestRngContext();

        var result = initialStateResult.Bind(initialState =>
            invalidCommandResult.Bind(invalidCommand =>
                configResult.Bind(config =>
                    _stateService.ApplyCommand(initialState, invalidCommand, config, rngContext)
                )
            )
        );

        result.IsFailure.Should().BeTrue();
    }

    [Test]
    public void GetSelectedApplication_WithSelectedApp_Success_ReturnsApplication()
    {
        var stateResult = CreateStateWithSelectedApplication();

        stateResult.Match(
            state =>
            {
                var result = _stateService.GetSelectedApplication(state);
                _ = result.HasValue.Should().BeTrue();
                result.Match(
                    app => _ = app.Aid.Should().NotBeEmpty(),
                    () => Assert.Fail("Expected application to be present")
                );
            },
            error => Assert.Fail($"Expected valid state but got error: {error}")
        );
    }

    [Test]
    public void GetSelectedApplication_NoSelectedApp_Success_ReturnsNone()
    {
        var stateResult = CreateStateWithoutSelectedApplication();

        stateResult.Match(
            state =>
            {
                var result = _stateService.GetSelectedApplication(state);
                _ = result.HasNoValue.Should().BeTrue();
            },
            error => Assert.Fail($"Expected valid state but got error: {error}")
        );
    }

    [Test]
    public void GetApplicationByAid_ExistingAid_Success_ReturnsApplication()
    {
        var stateResult = CreateStateWithKnownApplication();
        var knownAid = GetKnownApplicationAid();

        stateResult.Match(
            state =>
            {
                var result = _stateService.GetApplicationByAid(state, knownAid);
                _ = result.HasValue.Should().BeTrue();
                result.Match(
                    app => _ = app.Aid.Should().BeEquivalentTo(knownAid),
                    () => Assert.Fail("Expected application to be present")
                );
            },
            error => Assert.Fail($"Expected valid state but got error: {error}")
        );
    }

    [Test]
    public void GetApplicationByAid_UnknownAid_Success_ReturnsNone()
    {
        var stateResult = CreateValidInitialState();
        var unknownAid = new byte[] { 0x01, 0x02, 0x03 }.ToImmutableArray();

        stateResult.Match(
            state =>
            {
                var result = _stateService.GetApplicationByAid(state, unknownAid);
                _ = result.HasNoValue.Should().BeTrue();
            },
            error => Assert.Fail($"Expected valid state but got error: {error}")
        );
    }

    [Test]
    public void SelectApplication_ExistingApplication_Success_ReturnsUpdatedState()
    {
        var stateResult = CreateStateWithKnownApplication();
        var knownAid = GetKnownApplicationAid();

        stateResult.Match(
            state =>
            {
                var result = _stateService.SelectApplication(state, knownAid);
                result.IsSuccess.Should().BeTrue();
                result.Match(
                    newState =>
                    {
                        Assert.That(newState, Is.Not.EqualTo(state));

                        var selectedApp = _stateService.GetSelectedApplication(newState);
                        selectedApp.HasValue.Should().BeTrue();
                        selectedApp.Match(
                            app => app.Aid.Should().BeEquivalentTo(knownAid),
                            () => Assert.Fail("Expected selected application to be present")
                        );
                    },
                    error => Assert.Fail($"Expected success but got error: {error}")
                );
            },
            error => Assert.Fail($"Expected valid state but got error: {error}")
        );
    }

    [Test]
    public void SelectApplication_UnknownApplication_Failure_ReturnsError()
    {
        var stateResult = CreateValidInitialState();
        var unknownAid = new byte[] { 0x01, 0x02, 0x03 }.ToImmutableArray();

        stateResult.Match(
            state =>
            {
                var result = _stateService.SelectApplication(state, unknownAid);
                result.IsFailure.Should().BeTrue();
                result.Match(
                    _ => Assert.Fail("Expected failure"),
                    error => error.Message.Should().Contain("Application not found")
                );
            },
            error => Assert.Fail($"Expected valid state but got error: {error}")
        );
    }

    [Test]
    public void UpdateSecureChannel_ValidState_Success_ReturnsUpdatedState()
    {
        var initialStateResult = CreateValidInitialState();
        var secureChannelStateResult = CreateTestSecureChannelState();

        var result = initialStateResult.Bind(initialState =>
            secureChannelStateResult.Bind(secureChannelState =>
                _stateService.UpdateSecureChannel(initialState, secureChannelState)
            )
        );

        result.IsSuccess.Should().BeTrue();
        result.Match(
            newState =>
                initialStateResult.Match(
                    originalState =>
                    {
                        Assert.That(newState, Is.Not.EqualTo(originalState));
                        newState.IsSecureChannelEstablished.Should().BeTrue();
                        secureChannelStateResult.Match(
                            scState =>
                                newState.SecurityLevel.Should().Be((byte)scState.SecurityLevel),
                            error => Assert.Fail($"Expected valid secure channel state: {error}")
                        );
                    },
                    error => Assert.Fail($"Expected valid initial state: {error}")
                ),
            error => Assert.Fail($"Expected success but got error: {error}")
        );
    }

    [Test]
    public void UpdateSecureChannel_InvalidKeys_Failure_ReturnsError()
    {
        var initialStateResult = CreateValidInitialState();
        var invalidSecureChannelStateResult = CreateInvalidSecureChannelState();

        var result = initialStateResult.Bind(initialState =>
            invalidSecureChannelStateResult.Bind(invalidSecureChannelState =>
                _stateService.UpdateSecureChannel(initialState, invalidSecureChannelState)
            )
        );

        result.IsFailure.Should().BeTrue();
        result.Match(
            _ => Assert.Fail("Expected failure"),
            error => error.Message.Should().Contain("Session keys must be 16 bytes each")
        );
    }

    [Test]
    public void ClearSecureChannel_WithSecureChannel_Success_ReturnsStateWithoutSecureChannel()
    {
        var stateWithSecureChannelResult = CreateStateWithSecureChannel();

        stateWithSecureChannelResult.Match(
            stateWithSecureChannel =>
            {
                var result = _stateService.ClearSecureChannel(stateWithSecureChannel);

                Assert.That(result, Is.Not.EqualTo(stateWithSecureChannel));
                result.IsSecureChannelEstablished.Should().BeFalse();
                result.SecurityLevel.Should().Be((byte)SecurityLevel.None);
            },
            error => Assert.Fail($"Expected valid state with secure channel: {error}")
        );
    }

    [Test]
    public void ResetCard_PreservesEssentialState_ClearsTransientState()
    {
        var stateWithSecureChannelResult = CreateStateWithSecureChannel();

        stateWithSecureChannelResult.Match(
            stateWithSecureChannel =>
            {
                var originalUuid = stateWithSecureChannel.Uuid;
                var originalScpVersion = stateWithSecureChannel.ScpVersion;

                var result = _stateService.ResetCard(stateWithSecureChannel);

                Assert.That(result, Is.Not.EqualTo(stateWithSecureChannel));
                result.Uuid.Should().Be(originalUuid);
                result.ScpVersion.Should().Be(originalScpVersion);
                result.IsSecureChannelEstablished.Should().BeFalse();
                result.IsSelected.Should().BeTrue();
            },
            error => Assert.Fail($"Expected valid state with secure channel: {error}")
        );
    }

    [Test]
    public void ValidateState_ValidState_Success_ReturnsSuccess()
    {
        var validStateResult = CreateValidInitialState();

        validStateResult.Match(
            validState =>
            {
                var result = _stateService.ValidateState(validState);
                result.IsSuccess.Should().BeTrue();
            },
            error => Assert.Fail($"Expected valid state: {error}")
        );
    }

    [Test]
    public void ValidateState_InvalidUuid_Failure_ReturnsError()
    {
        var stateWithInvalidUuidResult = CreateStateWithInvalidUuid();

        stateWithInvalidUuidResult.Match(
            stateWithInvalidUuid =>
            {
                var result = _stateService.ValidateState(stateWithInvalidUuid);
                result.IsFailure.Should().BeTrue();
                result.Match(
                    _ => Assert.Fail("Expected failure"),
                    error => error.Message.Should().Contain("Card UUID must be 16 bytes")
                );
            },
            error => Assert.Fail($"Expected state with invalid UUID: {error}")
        );
    }

    [Test]
    public void ValidateState_InvalidSequenceCounters_Failure_ReturnsError()
    {
        var stateWithInvalidCountersResult = CreateStateWithInvalidSequenceCounters();

        stateWithInvalidCountersResult.Match(
            stateWithInvalidCounters =>
            {
                var result = _stateService.ValidateState(stateWithInvalidCounters);
                result.IsFailure.Should().BeTrue();
                result.Match(
                    _ => Assert.Fail("Expected failure"),
                    error =>
                        error.Message.Should().Contain("Sequence counters must be 2 or 3 bytes")
                );
            },
            error => Assert.Fail($"Expected state with invalid counters: {error}")
        );
    }

    [Test]
    public void StateTransitions_AreImmutable_OriginalStateUnchanged()
    {
        var originalStateResult = CreateValidInitialState();

        originalStateResult.Match(
            originalState =>
            {
                var originalHashCode = originalState.GetHashCode();
                var originalIsSelected = originalState.IsSelected;

                _stateService.ClearSecureChannel(originalState);
                _stateService.ResetCard(originalState);

                originalState.GetHashCode().Should().Be(originalHashCode);
                originalState.IsSelected.Should().Be(originalIsSelected);
            },
            error => Assert.Fail($"Expected valid original state: {error}")
        );
    }

    #region Test Helpers

    private Result<CardState, SmartCardError> CreateValidInitialState()
    {
        return _stateService.CreateInitialState();
    }

    private Result<CardState, SmartCardError> CreateStateWithSelectedApplication()
    {
        var testAid = GetKnownApplicationAid();
        return CreateValidInitialState()
            .Bind(state => _stateService.SelectApplication(state, testAid));
    }

    private Result<CardState, SmartCardError> CreateStateWithoutSelectedApplication()
    {
        return CreateValidInitialState()
            .Map(state =>
                state with
                {
                    ApplicationRegistry = state.ApplicationRegistry.Map(registry =>
                        registry with
                        {
                            SelectedApplicationAid = Maybe<ImmutableArray<byte>>.None,
                        }
                    ),
                }
            );
    }

    private Result<CardState, SmartCardError> CreateStateWithKnownApplication()
    {
        return CreateValidInitialState(); // ISD is already present as known app
    }

    private Result<CardState, SmartCardError> CreateStateWithSecureChannel()
    {
        return CreateValidInitialState()
            .Bind(state =>
                CreateTestSecureChannelState()
                    .Bind(secureChannelState =>
                        _stateService.UpdateSecureChannel(state, secureChannelState)
                    )
            );
    }

    private Result<CardState, SmartCardError> CreateStateWithInvalidUuid()
    {
        return CreateValidInitialState()
            .Map(state =>
            {
                var invalidUuid = new CardUuid(Guid.Empty); // Invalid empty GUID
                return state with { Uuid = invalidUuid };
            });
    }

    private Result<CardState, SmartCardError> CreateStateWithInvalidSequenceCounters()
    {
        return CreateValidInitialState()
            .Map(state =>
            {
                var builder = ImmutableDictionary.CreateBuilder<byte, byte[]>();
                builder.Add(0x01, new byte[1]); // Invalid length
                var invalidCounters = builder.ToImmutable();
                return state with { SequenceCounters = invalidCounters };
            });
    }

    private ImmutableArray<byte> GetKnownApplicationAid()
    {
        return [.. new byte[] { 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00 }]; // ISD AID
    }

    private Result<ApduCommand, SmartCardError> CreateSelectCommand()
    {
        var selectCommandBytes = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 }; // SELECT command
        return ApduCommand.Create(selectCommandBytes);
    }

    private Result<ApduCommand, SmartCardError> CreateInvalidCommand()
    {
        var invalidBytes = new byte[] { 0x00 }; // Too short
        return ApduCommand.Create(invalidBytes);
    }

    private Result<SecureChannelState, SmartCardError> CreateTestSecureChannelState()
    {
        return SessionKeys
            .Create(sEnc: new byte[16], sMac: new byte[16], sRMac: new byte[16], dek: new byte[16])
            .Bind(sessionKeys =>
                SecureChannelState.Create(
                    sessionKeys: sessionKeys,
                    securityLevel: SecurityLevel.CMac | SecurityLevel.CEncryption,
                    protocolVersion: ScpVersion.Scp02,
                    initialMacChainingValue: new byte[8],
                    implementationParameter: 0x15
                )
            );
    }

    private Result<SecureChannelState, SmartCardError> CreateInvalidSecureChannelState()
    {
        return SessionKeys
            .Create(
                sEnc: new byte[8], // Invalid length
                sMac: new byte[8], // Invalid length
                sRMac: new byte[8], // Invalid length
                dek: new byte[8] // Invalid length
            )
            .Bind(invalidSessionKeys =>
                SecureChannelState.Create(
                    sessionKeys: invalidSessionKeys,
                    securityLevel: SecurityLevel.CMac,
                    protocolVersion: ScpVersion.Scp02,
                    initialMacChainingValue: new byte[8],
                    implementationParameter: 0x15
                )
            );
    }

    private class TestRngContext : IRngContext
    {
        public Result<byte[], SmartCardError> GenerateBytes(int length) =>
            Result.Success<byte[], SmartCardError>(new byte[length]);

        public bool HasEnoughEntropy(int requiredBytes) => true;

        public Maybe<int> RemainingEntropy => Maybe<int>.None;
    }

    #endregion
}
