// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

namespace Gp4Net.Tests.Domain.Keys
{
    using System;
    using Gp4Net.Domain.Keys;
    using NUnit.Framework;

    /// <summary>
    /// Unit tests for the <see cref="SecureSessionKeys"/> class.
    /// </summary>
    [TestFixture]
    public class SecureSessionKeysTests
    {
        private byte[] testSEnc;
        private byte[] testSMac;
        private byte[] testSRMac;
        private byte[] testDek;

        /// <summary>
        /// Sets up test data before each test.
        /// </summary>
        [SetUp]
        public void SetUp()
        {
            this.testSEnc = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
            this.testSMac = new byte[] { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
            this.testSRMac = new byte[] { 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28 };
            this.testDek = new byte[] { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
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
                    this.testSEnc,
                    this.testSMac,
                    this.testSRMac,
                    this.testDek
                )
            )
            {
                // Assert
                Assert.That(sessionKeys, Is.Not.Null);
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
                    this.testSEnc,
                    this.testSMac,
                    this.testSRMac,
                    null
                )
            )
            {
                // Assert
                Assert.That(sessionKeys, Is.Not.Null);
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
                    this.testSEnc,
                    this.testSMac,
                    this.testSRMac,
                    this.testDek
                )
            )
            {
                bool executed = false;
                byte[] receivedKey = null;

                // Act
                sessionKeys.UseSEnc(key =>
                {
                    executed = true;
                    receivedKey = new byte[key.Length];
                    Array.Copy(key, receivedKey, key.Length);
                });

                // Assert
                Assert.That(executed, Is.True);
                Assert.That(receivedKey, Is.EqualTo(this.testSEnc));
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
                    this.testSEnc,
                    this.testSMac,
                    this.testSRMac,
                    this.testDek
                )
            )
            {
                // Act
                int result = sessionKeys.UseSMac(key => key.Length);

                // Assert
                Assert.That(result, Is.EqualTo(8));
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
                    this.testSEnc,
                    this.testSMac,
                    this.testSRMac,
                    null
                )
            )
            {
                bool executed = false;
                byte[] receivedKey = null;

                // Act
                sessionKeys.UseDek(key =>
                {
                    executed = true;
                    receivedKey = key;
                });

                // Assert
                Assert.That(executed, Is.True);
                Assert.That(receivedKey, Is.Null);
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
                    this.testSEnc,
                    this.testSMac,
                    this.testSRMac,
                    this.testDek
                )
            )
            {
                // Act
                SessionKeys legacyKeys = secureKeys.ToSessionKeys();

                // Assert
                Assert.That(legacyKeys.SEnc, Is.EqualTo(this.testSEnc));
                Assert.That(legacyKeys.SMac, Is.EqualTo(this.testSMac));
                Assert.That(legacyKeys.SRMac, Is.EqualTo(this.testSRMac));
                Assert.That(legacyKeys.Dek, Is.EqualTo(this.testDek));
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
                this.testSEnc,
                this.testSMac,
                this.testSRMac,
                this.testDek
            );
            sessionKeys.Dispose();

            // Act & Assert
            _ = Assert.Throws<ObjectDisposedException>(() => sessionKeys.UseSEnc(k => { }));
            _ = Assert.Throws<ObjectDisposedException>(() => sessionKeys.UseSMac(k => { }));
            _ = Assert.Throws<ObjectDisposedException>(() => sessionKeys.UseSRMac(k => { }));
            _ = Assert.Throws<ObjectDisposedException>(() => sessionKeys.UseDek(k => { }));
            _ = Assert.Throws<ObjectDisposedException>(() => sessionKeys.ToSessionKeys());
        }

        /// <summary>
        /// Tests that the constructor makes defensive copies.
        /// </summary>
        [Test]
        public void Constructor_MakesDefensiveCopies()
        {
            // Arrange
            byte[] originalSEnc = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            byte[] originalSMac = new byte[] { 0x11, 0x12, 0x13, 0x14 };
            byte[] originalSRMac = new byte[] { 0x21, 0x22, 0x23, 0x24 };

            using (
                var sessionKeys = new SecureSessionKeys(
                    originalSEnc,
                    originalSMac,
                    originalSRMac,
                    null
                )
            )
            {
                // Act - Modify originals
                originalSEnc[0] = 0xFF;
                originalSMac[0] = 0xFF;
                originalSRMac[0] = 0xFF;

                // Assert - Keys should be unchanged
                sessionKeys.UseSEnc(key => Assert.That(key[0], Is.EqualTo(0x01)));
                sessionKeys.UseSMac(key => Assert.That(key[0], Is.EqualTo(0x11)));
                sessionKeys.UseSRMac(key => Assert.That(key[0], Is.EqualTo(0x21)));
            }
        }
    }
}
