using System;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.Core;
using NUnit.Framework;

namespace Gp4Net.CardEmulator.Tests.Core;

/// <summary>
/// Tests for CardUuid value object functionality.
/// Verifies cryptographically secure generation, validation, and serialization.
/// </summary>
[TestFixture]
public class CardUuidTests
{
    [Test]
    public void Generate_ProducesValidUuid()
    {
        // Act
        var result = CardUuid.Generate();

        // Assert
        result.Match(
            uuid =>
            {
                _ = uuid.IsEmpty.Should().BeFalse();
                _ = uuid.ToGuid().Should().NotBe(Guid.Empty);
            },
            error => Assert.Fail($"Expected success but got error: {error}")
        );
    }

    [Test]
    public void Generate_ProducesUniqueUuids()
    {
        // Act
        var result1 = CardUuid.Generate();
        var result2 = CardUuid.Generate();

        // Assert
        result1.IsSuccess.Should().BeTrue();
        result2.IsSuccess.Should().BeTrue();

        result1.Match(
            uuid1 =>
                result2.Match(
                    uuid2 =>
                    {
                        _ = uuid1.Should().NotBe(uuid2);
                        _ = uuid1.ToGuid().Should().NotBe(uuid2.ToGuid());
                    },
                    error => Assert.Fail($"Failed to generate second UUID: {error}")
                ),
            error => Assert.Fail($"Failed to generate first UUID: {error}")
        );
    }

    [Test]
    public void FromGuid_WithValidGuid_ReturnsSuccess()
    {
        // Arrange
        var guid = Guid.NewGuid();

        // Act
        var result = CardUuid.FromGuid(guid);

        // Assert
        result.IsSuccess.Should().BeTrue();

        result.Match(
            uuid => uuid.ToGuid().Should().Be(guid),
            error => Assert.Fail($"Expected success but got error: {error}")
        );
    }

    [Test]
    public void FromGuid_WithEmptyGuid_ReturnsFailure()
    {
        // Arrange
        var emptyGuid = Guid.Empty;

        // Act
        var result = CardUuid.FromGuid(emptyGuid);

        // Assert
        result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
    }

    [Test]
    public void FromBytes_WithValidBytes_ReturnsSuccess()
    {
        // Arrange
        var guid = Guid.NewGuid();
        byte[] bytes = guid.ToByteArray();

        // Act
        var result = CardUuid.FromBytes(bytes);

        // Assert
        result.IsSuccess.Should().BeTrue();

        result.Match(
            uuid => uuid.ToGuid().Should().Be(guid),
            error => Assert.Fail($"Expected success but got error: {error}")
        );
    }

    [Test]
    public void FromBytes_WithNullBytes_ReturnsFailure()
    {
        // Act
        var result = CardUuid.FromBytes(null!);

        // Assert
        result.IsFailure.Should().BeTrue();
    }

    [Test]
    public void FromBytes_WithWrongLength_ReturnsFailure()
    {
        // Arrange
        byte[] incorrectBytes = new byte[15]; // Should be 16

        // Act
        var result = CardUuid.FromBytes(incorrectBytes);

        // Assert
        result.IsFailure.Should().BeTrue();
    }

    [Test]
    public void ToByteArray_ReturnsCorrectBytes()
    {
        // Arrange
        var guid = Guid.NewGuid();
        var uuidResult = CardUuid.FromGuid(guid);
        byte[] expectedBytes = guid.ToByteArray();

        // Act & Assert
        uuidResult.Match(
            uuid =>
            {
                byte[] actualBytes = uuid.ToByteArray();
                _ = actualBytes.Should().BeEquivalentTo(expectedBytes);
            },
            error => Assert.Fail($"Failed to create CardUuid: {error}")
        );
    }

    [Test]
    public void ToString_ReturnsGuidString()
    {
        // Arrange
        var guid = Guid.NewGuid();
        var uuidResult = CardUuid.FromGuid(guid);

        // Act & Assert
        uuidResult.Match(
            uuid =>
            {
                string result = uuid.ToString();
                _ = result.Should().Be(guid.ToString());
            },
            error => Assert.Fail($"Failed to create CardUuid: {error}")
        );
    }

    [Test]
    public void ToStringWithFormat_ReturnsFormattedGuidString()
    {
        // Arrange
        var guid = Guid.NewGuid();
        var uuidResult = CardUuid.FromGuid(guid);

        // Act & Assert
        uuidResult.Match(
            uuid =>
            {
                string result = uuid.ToString("N");
                _ = result.Should().Be(guid.ToString("N"));
            },
            error => Assert.Fail($"Failed to create CardUuid: {error}")
        );
    }

    [Test]
    public void IsEmpty_WithEmptyUuid_ReturnsTrue()
    {
        // Arrange
        var emptyUuid = CardUuid.Empty;

        // Act & Assert
        _ = emptyUuid.IsEmpty.Should().BeTrue();
    }

    [Test]
    public void IsEmpty_WithNonEmptyUuid_ReturnsFalse()
    {
        // Arrange
        var nonEmptyUuidResult = CardUuid.Generate();

        // Act & Assert
        nonEmptyUuidResult.Match(
            uuid => uuid.IsEmpty.Should().BeFalse(),
            error => Assert.Fail($"Failed to generate CardUuid: {error}")
        );
    }

    [Test]
    public void Equality_WithSameGuid_ReturnsTrue()
    {
        // Arrange
        var guid = Guid.NewGuid();
        var uuid1Result = CardUuid.FromGuid(guid);
        var uuid2Result = CardUuid.FromGuid(guid);

        // Act & Assert
        uuid1Result.Match(
            uuid1 =>
                uuid2Result.Match(
                    uuid2 =>
                    {
                        _ = uuid1.Should().Be(uuid2);
                        _ = (uuid1 == uuid2).Should().BeTrue();
                        _ = (uuid1 != uuid2).Should().BeFalse();
                    },
                    error => Assert.Fail($"Failed to create second CardUuid: {error}")
                ),
            error => Assert.Fail($"Failed to create first CardUuid: {error}")
        );
    }

    [Test]
    public void Equality_WithDifferentGuids_ReturnsFalse()
    {
        // Arrange
        var uuid1Result = CardUuid.Generate();
        var uuid2Result = CardUuid.Generate();

        // Act & Assert
        uuid1Result.Match(
            uuid1 =>
                uuid2Result.Match(
                    uuid2 =>
                    {
                        _ = uuid1.Should().NotBe(uuid2);
                        _ = (uuid1 == uuid2).Should().BeFalse();
                        _ = (uuid1 != uuid2).Should().BeTrue();
                    },
                    error => Assert.Fail($"Failed to generate second CardUuid: {error}")
                ),
            error => Assert.Fail($"Failed to generate first CardUuid: {error}")
        );
    }

    [Test]
    public void RoundTrip_ByteArrayConversion_PreservesUuid()
    {
        // Arrange
        var originalUuidResult = CardUuid.Generate();

        // Act & Assert
        originalUuidResult.Match(
            originalUuid =>
            {
                byte[] bytes = originalUuid.ToByteArray();
                var reconstructedUuidResult = CardUuid.FromBytes(
                    bytes
                );

                reconstructedUuidResult.Match(
                    reconstructedUuid => reconstructedUuid.Should().Be(originalUuid),
                    error => Assert.Fail($"Failed to reconstruct CardUuid: {error}")
                );
            },
            error => Assert.Fail($"Failed to generate original CardUuid: {error}")
        );
    }
}
