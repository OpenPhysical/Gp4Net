// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using AwesomeAssertions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Security;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain;

[TestFixture]
[Category("Unit")]
public class SecureChannelStateTests
{
    private SessionKeys _sessionKeys = null!;
    private byte[] _macChainingValue = null!;

    [SetUp]
    public void SetUp()
    {
        var testKeys = new SessionKeys(
            new byte[16], // S-ENC
            new byte[16], // S-MAC
            new byte[16], // S-RMAC
            new byte[16]  // S-DEK
        );
        _sessionKeys = testKeys;
        _macChainingValue = new byte[16]; // SCP03 MAC chaining value size
    }

    [TearDown]
    public void TearDown()
    {
        _sessionKeys?.Dispose();
    }

    [Test]
    public void Create_ValidParameters_CreatesState()
    {
        var macChainingState = MacChainingState.Create(_macChainingValue, ProtocolIdentifiers.Scp03, 0x00);
        _ = macChainingState.IsSuccess.Should().BeTrue();

        var result = SecureChannelState.Create(
            _sessionKeys,
            SecurityLevel.CMac,
            ProtocolIdentifiers.Scp03,
            _macChainingValue,
            0x00 // implementation parameter
        );

        _ = result.IsSuccess.Should().BeTrue();
        var state = result.Value;

        _ = state.SecurityLevel.Should().Be(SecurityLevel.CMac);
        _ = state.ProtocolVersion.Should().Be(ProtocolIdentifiers.Scp03);
        _ = state.SessionKeys.Should().Be(_sessionKeys);
        _ = state.EncryptionCounter.Should().Be(0);
        _ = state.SessionId.Should().NotBeEmpty();
        _ = state.SessionId.Length.Should().Be(8);
    }

    // Removed: Create_NullSessionKeys_ReturnsFailure
    // NO NULLS rule - nulls should be converted to Result<T> at boundaries, not checked in domain

    [Test]
    public void Create_EmptyMacChaining_ReturnsFailure()
    {
        var result = SecureChannelState.Create(
            _sessionKeys,
            SecurityLevel.CMac,
            ProtocolIdentifiers.Scp03,
            [],
            0x00 // implementation parameter
        );

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<InvalidLengthError>();
        var lengthError = (InvalidLengthError)result.Error;
        _ = lengthError.Expected.Should().Be(16); // SCP03 expects 16 bytes
    }

    [Test]
    public void IncrementEncryptionCounter_ReturnsNewStateWithIncrementedCounter()
    {
        var result = SecureChannelState.Create(
            _sessionKeys,
            SecurityLevel.CMac,
            ProtocolIdentifiers.Scp03,
            _macChainingValue,
            0x00 // implementation parameter
        );
        _ = result.IsSuccess.Should().BeTrue();
        var state = result.Value;

        var newState = state.IncrementEncryptionCounter();

        _ = newState.EncryptionCounter.Should().Be(1);
        _ = newState.SessionKeys.Should().Be(_sessionKeys);
        _ = newState.SecurityLevel.Should().Be(SecurityLevel.CMac);

        // Original state should be unchanged
        _ = state.EncryptionCounter.Should().Be(0);
    }

    [Test]
    public void UpdateMacChaining_ValidMacState_ReturnsNewState()
    {
        var result = SecureChannelState.Create(
            _sessionKeys,
            SecurityLevel.CMac,
            ProtocolIdentifiers.Scp03,
            _macChainingValue,
            0x00 // implementation parameter
        );
        _ = result.IsSuccess.Should().BeTrue();
        var state = result.Value;

        var newMacChaining = new byte[16];
        Array.Fill(newMacChaining, (byte)0xFF);
        var newMacState = MacChainingState.Create(newMacChaining, ProtocolIdentifiers.Scp03, 0x00);
        _ = newMacState.IsSuccess.Should().BeTrue();

        var updateResult = state.UpdateMacChaining(newMacState.Value);

        _ = updateResult.IsSuccess.Should().BeTrue();
        var newState = updateResult.Value;

        _ = newState.MacChaining.Value.Should().Equal(newMacChaining);
        _ = newState.SessionKeys.Should().Be(_sessionKeys);

        // Original state should be unchanged
        _ = state.MacChaining.Value.Should().Equal(_macChainingValue);
    }

    [Test]
    public void UpdateMacChaining_NullMacState_ReturnsFailure()
    {
        var result = SecureChannelState.Create(
            _sessionKeys,
            SecurityLevel.CMac,
            ProtocolIdentifiers.Scp03,
            _macChainingValue,
            0x00 // implementation parameter
        );
        _ = result.IsSuccess.Should().BeTrue();
        var state = result.Value;

        var updateResult = state.UpdateMacChaining(null!);

        _ = updateResult.IsFailure.Should().BeTrue();
        _ = updateResult.Error.Should().BeOfType<SmartCardError>();
        _ = updateResult.Error.Message.Should().Contain("cannot be null");
        // This should ideally be NullParameterError for null parameter validation
    }

    [Test]
    public void UpdateCounterAndMac_ValidParameters_UpdatesBoth()
    {
        var result = SecureChannelState.Create(
            _sessionKeys,
            SecurityLevel.CMac,
            ProtocolIdentifiers.Scp03,
            _macChainingValue,
            0x00 // implementation parameter
        );
        _ = result.IsSuccess.Should().BeTrue();
        var state = result.Value;

        var newMacChaining = new byte[16];
        Array.Fill(newMacChaining, (byte)0xAA);
        var newMacState = MacChainingState.Create(newMacChaining, ProtocolIdentifiers.Scp03, 0x00);
        _ = newMacState.IsSuccess.Should().BeTrue();
        
        var newCounter = 42u;

        var updateResult = state.UpdateCounterAndMac(newCounter, newMacState.Value);

        _ = updateResult.IsSuccess.Should().BeTrue();
        var newState = updateResult.Value;

        _ = newState.EncryptionCounter.Should().Be(newCounter);
        _ = newState.MacChaining.Value.Should().Equal(newMacChaining);
        _ = newState.SessionKeys.Should().Be(_sessionKeys);

        // Original state should be unchanged
        _ = state.EncryptionCounter.Should().Be(0);
        _ = state.MacChaining.Value.Should().Equal(_macChainingValue);
    }

    [Test]
    public void ImmutableStatePattern_EnsuresImmutability()
    {
        var result = SecureChannelState.Create(
            _sessionKeys,
            SecurityLevel.CMac,
            ProtocolIdentifiers.Scp03,
            _macChainingValue,
            0x00 // implementation parameter
        );
        _ = result.IsSuccess.Should().BeTrue();
        var originalState = result.Value;

        // Perform multiple operations
        var state1 = originalState.IncrementEncryptionCounter();
        var state2 = state1.IncrementEncryptionCounter();

        // Verify each state is independent
        _ = originalState.EncryptionCounter.Should().Be(0);
        _ = state1.EncryptionCounter.Should().Be(1);
        _ = state2.EncryptionCounter.Should().Be(2);

        // All should have same session keys reference (immutable)
        _ = originalState.SessionKeys.Should().Be(_sessionKeys);
        _ = state1.SessionKeys.Should().Be(_sessionKeys);
        _ = state2.SessionKeys.Should().Be(_sessionKeys);
    }
}