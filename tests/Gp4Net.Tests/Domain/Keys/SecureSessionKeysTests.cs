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
        this._testSEnc = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        this._testSMac = new byte[] { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
        this._testSrMac = new byte[] { 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28 };
        this._testDek = new byte[] { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    }

    /// <summary>
    /// Tests that the constructor creates an instance with valid keys.
    /// </summary>
    [Test]
    public void Constructor_WithValidKeys_CreatesInstance()
    {
        // Act
        using (
            var sessionKeys = new SecureSessionKeys(
                this._testSEnc,
                this._testSMac,
                this._testSrMac,
                this._testDek
            )
        )
        {
            // Assert
            sessionKeys.Should().NotBeNull();
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
            var sessionKeys = new SecureSessionKeys(
                this._testSEnc,
                this._testSMac,
                this._testSrMac,
                null
            )
        )
        {
            // Assert
            sessionKeys.Should().NotBeNull();
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
            var sessionKeys = new SecureSessionKeys(
                this._testSEnc,
                this._testSMac,
                this._testSrMac,
                this._testDek
            )
        )
        {
            var executed = false;
            byte[] receivedKey = null;

            // Act
            sessionKeys.UseSEnc(key =>
            {
                executed = true;
                receivedKey = new byte[key.Length];
                Array.Copy(key, receivedKey, key.Length);
            });

            // Assert
            executed.Should().BeTrue();
            receivedKey.Should().BeEquivalentTo(this._testSEnc);
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
            var sessionKeys = new SecureSessionKeys(
                this._testSEnc,
                this._testSMac,
                this._testSrMac,
                this._testDek
            )
        )
        {
            // Act
            var result = sessionKeys.UseSMac(key => key.Length);

            // Assert
            result.Should().Be(8);
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
            var sessionKeys = new SecureSessionKeys(
                this._testSEnc,
                this._testSMac,
                this._testSrMac,
                null
            )
        )
        {
            var executed = false;
            byte[] receivedKey = null;

            // Act
            sessionKeys.UseDek(key =>
            {
                executed = true;
                receivedKey = key;
            });

            // Assert
            executed.Should().BeTrue();
            receivedKey.Should().BeNull();
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
            var secureKeys = new SecureSessionKeys(
                this._testSEnc,
                this._testSMac,
                this._testSrMac,
                this._testDek
            )
        )
        {
            // Act
            var legacyKeys = secureKeys.ToSessionKeys();

            // Assert
            legacyKeys.SEnc.Should().BeEquivalentTo(this._testSEnc);
            legacyKeys.SMac.Should().BeEquivalentTo(this._testSMac);
            legacyKeys.SrMac.Should().BeEquivalentTo(this._testSrMac);
            legacyKeys.Dek.Should().BeEquivalentTo(this._testDek);
        }
    }

    /// <summary>
    /// Tests that operations throw after disposal.
    /// </summary>
    [Test]
    public void AfterDispose_OperationsThrow()
    {
        // Arrange
        var sessionKeys = new SecureSessionKeys(
            this._testSEnc,
            this._testSMac,
            this._testSrMac,
            this._testDek
        );
        sessionKeys.Dispose();

        // Act & Assert
        var act1 = () => sessionKeys.UseSEnc(k => { });
        act1.Should().ThrowExactly<ObjectDisposedException>();
            
        var act2 = () => sessionKeys.UseSMac(k => { });
        act2.Should().ThrowExactly<ObjectDisposedException>();
            
        var act3 = () => sessionKeys.UseSrMac(k => { });
        act3.Should().ThrowExactly<ObjectDisposedException>();
            
        var act4 = () => sessionKeys.UseDek(k => { });
        act4.Should().ThrowExactly<ObjectDisposedException>();
            
        Action act5 = () => sessionKeys.ToSessionKeys();
        act5.Should().ThrowExactly<ObjectDisposedException>();
    }

    /// <summary>
    /// Tests that the constructor makes defensive copies.
    /// </summary>
    [Test]
    public void Constructor_MakesDefensiveCopies()
    {
        // Arrange
        var originalSEnc = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var originalSMac = new byte[] { 0x11, 0x12, 0x13, 0x14 };
        var originalSrMac = new byte[] { 0x21, 0x22, 0x23, 0x24 };

        using (
            var sessionKeys = new SecureSessionKeys(
                originalSEnc,
                originalSMac,
                originalSrMac,
                null
            )
        )
        {
            // Act - Modify originals
            originalSEnc[0] = 0xFF;
            originalSMac[0] = 0xFF;
            originalSrMac[0] = 0xFF;

            // Assert - Keys should be unchanged
            sessionKeys.UseSEnc(key => key[0].Should().Be(0x01));
            sessionKeys.UseSMac(key => key[0].Should().Be(0x11));
            sessionKeys.UseSrMac(key => key[0].Should().Be(0x21));
        }
    }
}