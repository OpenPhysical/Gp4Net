// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using NUnit.Framework;

namespace Gp4Net.Tests.Protocol;

/// <summary>
/// SCP protocol tests for domain key set models.
/// Tests for protocol implementation have been removed as part of the unified SCP channel refactoring.
/// See SCP_UNIFICATION_GUIDE.md for details on the new unified architecture.
/// </summary>
[TestFixture]
[Category("Protocol")]
public class ScpProtocolTests
{
    [Test]
    public void Scp02_KeySetCreation_WithValidKeys_Succeeds()
    {
        // Arrange
        byte[] encKey = new byte[16];
        byte[] macKey = new byte[16];
        byte[] dekKey = new byte[16];

        // Act
        Result<Scp02KeySet, SmartCardError> result = Scp02KeySet.Create(
            encKey,
            macKey,
            dekKey,
            0x01
        );

        // Assert
        _ = result.IsSuccess.Should().BeTrue("Valid keys should create successful key set");
    }

    [Test]
    public void Scp03_KeySetCreation_WithValidKeys_Succeeds()
    {
        // Arrange
        byte[] encKey = new byte[16];
        byte[] macKey = new byte[16];
        byte[] dekKey = new byte[16];

        // Act
        var keySet = new Scp03KeySet(encKey, macKey, dekKey, 0x01);

        // Assert
        _ = keySet.Should().NotBeNull("Valid keys should create successful key set");
        _ = keySet.EncKey.Should().BeEquivalentTo(encKey);
        _ = keySet.MacKey.Should().BeEquivalentTo(macKey);
        _ = keySet.DekKey.Should().BeEquivalentTo(dekKey);
    }
}
