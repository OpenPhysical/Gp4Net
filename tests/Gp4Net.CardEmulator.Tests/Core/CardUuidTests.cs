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
        Result<CardUuid, SmartCardError> result = CardUuid.Generate();

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
        Result<CardUuid, SmartCardError> result1 = CardUuid.Generate();
        Result<CardUuid, SmartCardError> result2 = CardUuid.Generate();

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
        Guid guid = Guid.NewGuid();

        // Act
        Result<CardUuid, SmartCardError> result = CardUuid.FromGuid(guid);

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
        Guid emptyGuid = Guid.Empty;

        // Act
        Result<CardUuid, SmartCardError> result = CardUuid.FromGuid(emptyGuid);

        // Assert
        result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
    }

    [Test]
    public void FromBytes_WithValidBytes_ReturnsSuccess()
    {
        // Arrange
        Guid guid = Guid.NewGuid();
        byte[] bytes = guid.ToByteArray();

        // Act
        Result<CardUuid, SmartCardError> result = CardUuid.FromBytes(bytes);

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
        Result<CardUuid, SmartCardError> result = CardUuid.FromBytes(null!);

        // Assert
        result.IsFailure.Should().BeTrue();
    }

    [Test]
    public void FromBytes_WithWrongLength_ReturnsFailure()
    {
        // Arrange
        byte[] incorrectBytes = new byte[15]; // Should be 16

        // Act
        Result<CardUuid, SmartCardError> result = CardUuid.FromBytes(incorrectBytes);

        // Assert
        result.IsFailure.Should().BeTrue();
    }

    [Test]
    public void ToByteArray_ReturnsCorrectBytes()
    {
        // Arrange
        Guid guid = Guid.NewGuid();
        Result<CardUuid, SmartCardError> uuidResult = CardUuid.FromGuid(guid);
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
        Guid guid = Guid.NewGuid();
        Result<CardUuid, SmartCardError> uuidResult = CardUuid.FromGuid(guid);

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
        Guid guid = Guid.NewGuid();
        Result<CardUuid, SmartCardError> uuidResult = CardUuid.FromGuid(guid);

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
        CardUuid emptyUuid = CardUuid.Empty;

        // Act & Assert
        _ = emptyUuid.IsEmpty.Should().BeTrue();
    }

    [Test]
    public void IsEmpty_WithNonEmptyUuid_ReturnsFalse()
    {
        // Arrange
        Result<CardUuid, SmartCardError> nonEmptyUuidResult = CardUuid.Generate();

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
        Guid guid = Guid.NewGuid();
        Result<CardUuid, SmartCardError> uuid1Result = CardUuid.FromGuid(guid);
        Result<CardUuid, SmartCardError> uuid2Result = CardUuid.FromGuid(guid);

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
        Result<CardUuid, SmartCardError> uuid1Result = CardUuid.Generate();
        Result<CardUuid, SmartCardError> uuid2Result = CardUuid.Generate();

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
        Result<CardUuid, SmartCardError> originalUuidResult = CardUuid.Generate();

        // Act & Assert
        originalUuidResult.Match(
            originalUuid =>
            {
                byte[] bytes = originalUuid.ToByteArray();
                Result<CardUuid, SmartCardError> reconstructedUuidResult = CardUuid.FromBytes(
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
