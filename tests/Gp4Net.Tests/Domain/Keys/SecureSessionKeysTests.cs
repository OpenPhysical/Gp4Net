// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

namespace Gp4Net.Tests.Domain.Keys;

using System;
using AwesomeAssertions;
using Gp4Net.Domain.Keys;
using NUnit.Framework;

/// <summary>
/// Unit tests for the <see cref="SecureSessionKeys"/> class.
/// </summary>
[TestFixture]
[Category("Unit")]
public class SecureSessionKeysTests
{
    private byte[] _testSEnc;
    private byte[] _testSMac;
    private byte[] _testSrMac;
    private byte[] _testDek;

    /// <summary>
    /// Sets up test data before each test.
    /// </summary>
    [SetUp]
    public void SetUp()
    {
        _testSEnc = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        _testSMac = [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18];
        _testSrMac = [0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28];
        _testDek = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
    }

    /// <summary>
    /// Tests that the constructor creates an instance with valid keys.
    /// </summary>
    [Test]
    public void Constructor_WithValidKeys_CreatesInstance()
    {
        // Act
        using (
            SecureSessionKeys sessionKeys = new SecureSessionKeys(
                _testSEnc,
                _testSMac,
                _testSrMac,
                _testDek
            )
        )
        {
            // Assert
            _ = sessionKeys.Should().NotBeNull();
        }
    }

    /// <summary>
    /// Tests that the constructor works without DEK.
    /// </summary>
    [Test]
    public void Constructor_WithoutDek_CreatesInstance()
    {
        // Act
        using (
            SecureSessionKeys sessionKeys = new SecureSessionKeys(
                _testSEnc,
                _testSMac,
                _testSrMac,
                dek: null
            )
        )
        {
            // Assert
            _ = sessionKeys.Should().NotBeNull();
        }
    }

    /// <summary>
    /// Tests that UseSEnc executes action with correct key.
    /// </summary>
    [Test]
    public void UseSEnc_ExecutesActionWithKey()
    {
        // Arrange
        using (
            SecureSessionKeys sessionKeys = new SecureSessionKeys(
                _testSEnc,
                _testSMac,
                _testSrMac,
                _testDek
            )
        )
        {
            bool executed = false;
            byte[]? receivedKey = null;

            // Act
            sessionKeys.UseSEnc(key =>
            {
                executed = true;
                receivedKey = new byte[key.Length];
                Array.Copy(key, receivedKey, key.Length);
            });

            // Assert
            _ = executed.Should().BeTrue();
            _ = receivedKey.Should().BeEquivalentTo(_testSEnc);
        }
    }

    /// <summary>
    /// Tests that UseSMac function returns correct result.
    /// </summary>
    [Test]
    public void UseSMac_FunctionReturnsResult()
    {
        // Arrange
        using (
            SecureSessionKeys sessionKeys = new SecureSessionKeys(
                _testSEnc,
                _testSMac,
                _testSrMac,
                _testDek
            )
        )
        {
            // Act
            int result = sessionKeys.UseSMac(key => key.Length);

            // Assert
            _ = result.Should().Be(8);
        }
    }

    /// <summary>
    /// Tests that UseDek handles null DEK properly.
    /// </summary>
    [Test]
    public void UseDek_WithNullDek_PassesNull()
    {
        // Arrange
        using (
            SecureSessionKeys sessionKeys = new SecureSessionKeys(
                _testSEnc,
                _testSMac,
                _testSrMac,
                null
            )
        )
        {
            bool executed = false;
            byte[]? receivedKey = null;

            // Act
            sessionKeys.UseDek(key =>
            {
                executed = true;
                receivedKey = key;
            });

            // Assert
            _ = executed.Should().BeTrue();
            _ = receivedKey.Should().BeNull();
        }
    }

    /// <summary>
    /// Tests that ToSessionKeys creates correct legacy object.
    /// </summary>
    [Test]
    public void ToSessionKeys_CreatesLegacyObject()
    {
        // Arrange
        using (
            SecureSessionKeys secureKeys = new SecureSessionKeys(
                _testSEnc,
                _testSMac,
                _testSrMac,
                _testDek
            )
        )
        {
            // Act
            SessionKeys? legacyKeys = secureKeys.ToSessionKeys();

            // Assert
            _ = legacyKeys.SEnc.Should().BeEquivalentTo(_testSEnc);
            _ = legacyKeys.SMac.Should().BeEquivalentTo(_testSMac);
            _ = legacyKeys.SrMac.Should().BeEquivalentTo(_testSrMac);
            _ = legacyKeys.Dek.Should().BeEquivalentTo(_testDek);
        }
    }

    /// <summary>
    /// Tests that operations throw after disposal.
    /// </summary>
    [Test]
    public void AfterDispose_OperationsThrow()
    {
        // Arrange
        SecureSessionKeys sessionKeys = new SecureSessionKeys(
            _testSEnc,
            _testSMac,
            _testSrMac,
            _testDek
        );
        sessionKeys.Dispose();

        // Act & Assert
        Action act1 = () => sessionKeys.UseSEnc(k => { });
        _ = act1.Should().ThrowExactly<ObjectDisposedException>();

        Action act2 = () => sessionKeys.UseSMac(k => { });
        _ = act2.Should().ThrowExactly<ObjectDisposedException>();

        Action act3 = () => sessionKeys.UseSrMac(k => { });
        _ = act3.Should().ThrowExactly<ObjectDisposedException>();

        Action act4 = () => sessionKeys.UseDek(k => { });
        _ = act4.Should().ThrowExactly<ObjectDisposedException>();

        Action act5 = () => sessionKeys.ToSessionKeys();
        _ = act5.Should().ThrowExactly<ObjectDisposedException>();
    }

    /// <summary>
    /// Tests that the constructor makes defensive copies.
    /// </summary>
    [Test]
    public void Constructor_MakesDefensiveCopies()
    {
        // Arrange
        byte[] originalSEnc = [0x01, 0x02, 0x03, 0x04];
        byte[] originalSMac = [0x11, 0x12, 0x13, 0x14];
        byte[] originalSrMac = [0x21, 0x22, 0x23, 0x24];

        using (
            SecureSessionKeys sessionKeys = new SecureSessionKeys(
                originalSEnc,
                originalSMac,
                originalSrMac,
                dek: null
            )
        )
        {
            // Act - Modify originals
            originalSEnc[0] = 0xFF;
            originalSMac[0] = 0xFF;
            originalSrMac[0] = 0xFF;

            // Assert - Keys should be unchanged
            _ = sessionKeys.UseSEnc(key => key[0].Should().Be(0x01));
            _ = sessionKeys.UseSMac(key => key[0].Should().Be(0x11));
            _ = sessionKeys.UseSrMac(key => key[0].Should().Be(0x21));
        }
    }
}