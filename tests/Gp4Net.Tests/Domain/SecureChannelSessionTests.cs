// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using Gp4Net.Constants;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Tests.TestHelpers;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain
{
    [TestFixture]
    public class SecureChannelSessionTests
    {
        private SessionKeys _sessionKeys;
        private byte[] _macChainingValue;

        [SetUp]
        public void Setup()
        {
            _sessionKeys = new SessionKeys(
                sEnc: Convert.FromHexString("0123456789ABCDEF0123456789ABCDEF"),
                sMac: Convert.FromHexString("FEDCBA9876543210FEDCBA9876543210"),
                sRMac: Convert.FromHexString("0123456789ABCDEF0123456789ABCDEF"),
                dek: Convert.FromHexString("FEDCBA9876543210FEDCBA9876543210")
            );

            _macChainingValue = new byte[16]; // Zero IV
        }

        [TearDown]
        public void TearDown()
        {
            _sessionKeys?.Dispose();
        }

        [Test]
        public void Constructor_ValidParameters_CreatesSession()
        {
            // Act
            var session = new SecureChannelSession(
                _sessionKeys,
                SecurityLevel.CMac,
                ProtocolIdentifiers.Scp03,
                _macChainingValue
            );

            // Assert
            Assert.That(session, Is.Not.Null);
            Assert.That(session.SecurityLevel, Is.EqualTo(SecurityLevel.CMac));
            Assert.That(session.ProtocolVersion, Is.EqualTo(ProtocolIdentifiers.Scp03));
            Assert.That(session.IsScp03, Is.True);
            Assert.That(session.SessionId, Is.Not.Null);
            Assert.That(session.SessionId.Length, Is.EqualTo(8));
        }

        [Test]
        public void WrapCommand_WithCMac_AddsEightBytesToCommand()
        {
            // Arrange
            var session = new SecureChannelSession(
                _sessionKeys,
                SecurityLevel.CMac,
                ProtocolIdentifiers.Scp03,
                _macChainingValue
            );

            var commandBytes = new byte[]
            {
                0x00,
                0xA4,
                0x04,
                0x00,
                0x07,
                0xA0,
                0x00,
                0x00,
                0x00,
                0x03,
                0x00,
                0x00,
            };

            var command = TestApduCommand.FromBytes(commandBytes);

            // Act
            var (wrappedData, expectedResponseLength) = session.WrapCommand(command);

            // Assert
            Assert.That(wrappedData.Length, Is.EqualTo(commandBytes.Length + 8));
            Assert.That(wrappedData[4], Is.EqualTo(0x0F)); // Updated Lc (7 + 8)
        }

        [Test]
        public void WrapCommand_InvalidCommand_ThrowsException()
        {
            // Arrange
            var session = new SecureChannelSession(
                _sessionKeys,
                SecurityLevel.CMac,
                ProtocolIdentifiers.Scp03,
                _macChainingValue
            );

            var invalidCommandBytes = new byte[] { 0x00, 0xA4 }; // Too short

            // Act & Assert
            _ = Assert.Throws<ArgumentException>(() => TestApduCommand.FromBytes(invalidCommandBytes));
        }

        [Test]
        public void UnwrapResponse_InvalidResponse_ThrowsException()
        {
            // Arrange
            var session = new SecureChannelSession(
                _sessionKeys,
                SecurityLevel.RMac,
                ProtocolIdentifiers.Scp03,
                _macChainingValue
            );

            var invalidResponse = new byte[] { 0x90 }; // Too short

            // Act & Assert
            _ = Assert.Throws<ArgumentException>(() => session.UnwrapResponse(invalidResponse));
        }
    }
}
