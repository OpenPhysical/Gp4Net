// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using AwesomeAssertions;
using Gp4Net.Constants;
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
        macChainingState.IsSuccess.Should().BeTrue();

        var result = SecureChannelState.Create(
            _sessionKeys,
            SecurityLevel.CMac,
            ProtocolIdentifiers.Scp03,
            _macChainingValue,
            0x00 // implementation parameter
        );

        result.IsSuccess.Should().BeTrue();
        var state = result.Value;
        
        state.SecurityLevel.Should().Be(SecurityLevel.CMac);
        state.ProtocolVersion.Should().Be(ProtocolIdentifiers.Scp03);
        state.SessionKeys.Should().Be(_sessionKeys);
        state.EncryptionCounter.Should().Be(0);
        state.SessionId.Should().NotBeEmpty();
        state.SessionId.Length.Should().Be(8);
    }

    [Test]
    public void Create_NullSessionKeys_ReturnsFailure()
    {
        var result = SecureChannelState.Create(
            null!,
            SecurityLevel.CMac,
            ProtocolIdentifiers.Scp03,
            _macChainingValue,
            0x00 // implementation parameter
        );

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("INVALID_ARGUMENT");
    }

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

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("INVALID_ARGUMENT");
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
        result.IsSuccess.Should().BeTrue();
        var state = result.Value;

        var newState = state.IncrementEncryptionCounter();

        newState.EncryptionCounter.Should().Be(1);
        newState.SessionKeys.Should().Be(_sessionKeys);
        newState.SecurityLevel.Should().Be(SecurityLevel.CMac);
        
        // Original state should be unchanged
        state.EncryptionCounter.Should().Be(0);
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
        result.IsSuccess.Should().BeTrue();
        var state = result.Value;

        var newMacChaining = new byte[16];
        Array.Fill(newMacChaining, (byte)0xFF);
        var newMacState = MacChainingState.Create(newMacChaining, ProtocolIdentifiers.Scp03, 0x00);
        newMacState.IsSuccess.Should().BeTrue();

        var updateResult = state.UpdateMacChaining(newMacState.Value);

        updateResult.IsSuccess.Should().BeTrue();
        var newState = updateResult.Value;
        
        newState.MacChaining.Value.Should().Equal(newMacChaining);
        newState.SessionKeys.Should().Be(_sessionKeys);
        
        // Original state should be unchanged
        state.MacChaining.Value.Should().Equal(_macChainingValue);
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
        result.IsSuccess.Should().BeTrue();
        var state = result.Value;

        var updateResult = state.UpdateMacChaining(null!);

        updateResult.IsFailure.Should().BeTrue();
        updateResult.Error.Code.Should().Be("INVALID_ARGUMENT");
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
        result.IsSuccess.Should().BeTrue();
        var state = result.Value;

        var newMacChaining = new byte[16];
        Array.Fill(newMacChaining, (byte)0xAA);
        var newMacState = MacChainingState.Create(newMacChaining, ProtocolIdentifiers.Scp03, 0x00);
        newMacState.IsSuccess.Should().BeTrue();
        
        var newCounter = 42u;

        var updateResult = state.UpdateCounterAndMac(newCounter, newMacState.Value);

        updateResult.IsSuccess.Should().BeTrue();
        var newState = updateResult.Value;
        
        newState.EncryptionCounter.Should().Be(newCounter);
        newState.MacChaining.Value.Should().Equal(newMacChaining);
        newState.SessionKeys.Should().Be(_sessionKeys);
        
        // Original state should be unchanged
        state.EncryptionCounter.Should().Be(0);
        state.MacChaining.Value.Should().Equal(_macChainingValue);
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
        result.IsSuccess.Should().BeTrue();
        var originalState = result.Value;

        // Perform multiple operations
        var state1 = originalState.IncrementEncryptionCounter();
        var state2 = state1.IncrementEncryptionCounter();
        
        // Verify each state is independent
        originalState.EncryptionCounter.Should().Be(0);
        state1.EncryptionCounter.Should().Be(1);
        state2.EncryptionCounter.Should().Be(2);
        
        // All should have same session keys reference (immutable)
        originalState.SessionKeys.Should().Be(_sessionKeys);
        state1.SessionKeys.Should().Be(_sessionKeys);
        state2.SessionKeys.Should().Be(_sessionKeys);
    }
}