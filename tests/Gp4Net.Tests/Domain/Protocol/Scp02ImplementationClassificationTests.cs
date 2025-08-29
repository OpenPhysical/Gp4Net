using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Protocol;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Protocol;

/// <summary>
/// Tests for ScpImplementation classification and extension methods.
/// Validates the IsScp02() extension method edge cases and ensures robust implementation detection.
/// These tests are critical because bugs in IsScp02() would cause GetScp02Implementation() to fail
/// incorrectly, potentially leading to authentication failures with valid cards.
/// </summary>
[TestFixture]
[Category("Unit")]
[Category("FailHard")]
public class Scp02ImplementationClassificationTests
{
    [TestCase(ScpImplementation.Scp02I00, true, "i=00 should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I02, true, "i=02 should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I04, true, "i=04 should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I05, true, "i=05 should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I0A, true, "i=0A should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I14, true, "i=14 should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I15, true, "i=15 should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I1A, true, "i=1A should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I24, true, "i=24 should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I25, true, "i=25 should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I2A, true, "i=2A should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I34, true, "i=34 should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I35, true, "i=35 should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I3A, true, "i=3A should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I44, true, "i=44 should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I45, true, "i=45 should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I4A, true, "i=4A should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I54, true, "i=54 should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I55, true, "i=55 should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I64, true, "i=64 should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I65, true, "i=65 should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I6A, true, "i=6A should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I74, true, "i=74 should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I75, true, "i=75 should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I7A, true, "i=7A should be classified as SCP02")]
    public void IsScp02_WithKnownScp02Implementations_ShouldReturnTrue(
        ScpImplementation implementation,
        bool expected,
        string description)
    {
        // Act
        bool result = implementation.IsScp02();

        // Assert
        _ = result.Should().Be(expected, description);

        TestContext.Out.WriteLine($"✓ {description}");
        TestContext.Out.WriteLine($"Implementation {implementation} (0x{(byte)implementation:X2}) correctly classified as SCP02: {result}");
    }

    [TestCase(ScpImplementation.Scp03I10, false, "i=10 should not be classified as SCP02 (is SCP03)")]
    [TestCase(ScpImplementation.Scp03I11, false, "i=11 should not be classified as SCP02 (is SCP03)")]
    [TestCase(ScpImplementation.Scp03I20, false, "i=20 should not be classified as SCP02 (is SCP03)")]
    [TestCase(ScpImplementation.Scp03I30, false, "i=30 should not be classified as SCP02 (is SCP03)")]
    [TestCase(ScpImplementation.Scp03I60, false, "i=60 should not be classified as SCP02 (is SCP03)")]
    [TestCase(ScpImplementation.Scp03I70, false, "i=70 should not be classified as SCP02 (is SCP03)")]
    public void IsScp02_WithKnownScp03Implementations_ShouldReturnFalse(
        ScpImplementation implementation,
        bool expected,
        string description)
    {
        // Act
        bool result = implementation.IsScp02();

        // Assert
        _ = result.Should().Be(expected, description);

        TestContext.Out.WriteLine($"✓ {description}");
        TestContext.Out.WriteLine($"Implementation {implementation} (0x{(byte)implementation:X2}) correctly classified as SCP02: {result}");
    }

    /// <summary>
    /// Tests edge case where a value appears to be in SCP02 range (≤ 0x7A) but is actually an SCP03 implementation.
    /// This is critical because the IsScp02() logic must explicitly exclude known SCP03 values.
    /// </summary>
    [Test]
    public void IsScp02_WithScp03ValuesInScp02Range_ShouldReturnFalse()
    {
        // Arrange - SCP03 values that fall within the SCP02 range (≤ 0x7A)
        byte[] scp03ValuesInRange =
        [
            (byte)ScpImplementation.Scp03I10,      // 0x10
            (byte)ScpImplementation.Scp03I11, // 0x11
            (byte)ScpImplementation.Scp03I20,      // 0x20
            (byte)ScpImplementation.Scp03I30,      // 0x30
            (byte)ScpImplementation.Scp03I60, // 0x60
            (byte)ScpImplementation.Scp03I70    // 0x70
        ];

        foreach (byte value in scp03ValuesInRange)
        {
            // Act - Cast byte to enum and test classification
            ScpImplementation implementation = (ScpImplementation)value;
            bool result = implementation.IsScp02();

            // Assert
            _ = result.Should().BeFalse($"Value 0x{value:X2} should be classified as SCP03, not SCP02");
            _ = implementation.IsScp03().Should().BeTrue($"Value 0x{value:X2} should be classified as SCP03");

            TestContext.Out.WriteLine($"✓ SCP03 value 0x{value:X2} correctly excluded from SCP02 classification");
        }
    }

    /// <summary>
    /// Tests that values above 0x7A are correctly rejected as non-SCP02.
    /// Per GP Card Specification, SCP02 bitmap only goes up to 0x7A.
    /// </summary>
    [TestCase(0x80, "0x80 should not be SCP02 (above valid range)")]
    [TestCase(0xFF, "0xFF should not be SCP02 (above valid range)")]
    [TestCase(0x7B, "0x7B should not be SCP02 (above valid range)")]
    [TestCase(0x7C, "0x7C should not be SCP02 (above valid range)")]
    [TestCase(0x7D, "0x7D should not be SCP02 (above valid range)")]
    [TestCase(0x7E, "0x7E should not be SCP02 (above valid range)")]
    [TestCase(0x7F, "0x7F should not be SCP02 (above valid range)")]
    public void IsScp02_WithValuesAboveValidRange_ShouldReturnFalse(
        byte value,
        string description)
    {
        // Act - Cast raw byte value to enum (may not be defined)
        ScpImplementation implementation = (ScpImplementation)value;
        bool result = implementation.IsScp02();

        // Assert
        _ = result.Should().BeFalse(description);

        TestContext.Out.WriteLine($"✓ {description}");
        TestContext.Out.WriteLine($"Value 0x{value:X2} correctly rejected as non-SCP02");
    }

    /// <summary>
    /// Tests IsScp02() consistency with GetScp02Implementation() for all valid SCP02 values.
    /// If IsScp02() returns true, GetScp02Implementation() should succeed.
    /// This ensures the two methods stay in sync.
    /// </summary>
    [Test]
    public void IsScp02_ConsistencyWithGetScp02Implementation_ShouldMatch()
    {
        // Test all possible byte values
        for (int i = 0; i <= 255; i++)
        {
            byte byteValue = (byte)i;
            ScpImplementation implementation = (ScpImplementation)byteValue;
            bool isScp02Result = implementation.IsScp02();

            if (isScp02Result)
            {
                // If IsScp02() says it's SCP02, GetScp02Implementation() should succeed
                Result<ScpImplementation, SmartCardError> result = Scp02Protocol.GetScp02Implementation(byteValue);
                _ = result.IsSuccess.Should().BeTrue($"IsScp02() returned true for 0x{byteValue:X2}, but GetScp02Implementation() failed: {(result.IsFailure ? result.Error.Message : "unknown error")}");
            }
            else
            {
                // If IsScp02() says it's not SCP02, GetScp02Implementation() should fail
                Result<ScpImplementation, SmartCardError> result = Scp02Protocol.GetScp02Implementation(byteValue);
                _ = result.IsFailure.Should().BeTrue($"IsScp02() returned false for 0x{byteValue:X2}, but GetScp02Implementation() succeeded");
                _ = result.Error.Should().BeOfType<UnsupportedImplementationError>();
            }
        }

        TestContext.Out.WriteLine("✓ IsScp02() and GetScp02Implementation() are consistent across all 256 possible byte values");
    }

    /// <summary>
    /// Tests that additional SCP02 implementations are correctly classified as SCP02.
    /// These cover the full range of defined SCP02 implementations.
    /// </summary>
    [TestCase(ScpImplementation.Scp02I00, true, "SCP02 i=00 should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I15, true, "SCP02 i=15 should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I35, true, "SCP02 i=35 should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I55, true, "SCP02 i=55 should be classified as SCP02")]
    [TestCase(ScpImplementation.Scp02I75, true, "SCP02 i=75 should be classified as SCP02")]
    public void IsScp02_WithAdditionalScp02Implementations_ShouldReturnTrue(
        ScpImplementation implementation,
        bool expected,
        string description)
    {
        // Act
        bool result = implementation.IsScp02();

        // Assert
        _ = result.Should().Be(expected, description);

        TestContext.Out.WriteLine($"✓ {description}");
        TestContext.Out.WriteLine($"Legacy alias {implementation} correctly classified as SCP02: {result}");
    }

    /// <summary>
    /// Tests that undefined enum values in the SCP02 range are handled correctly.
    /// This tests the robustness of the IsScp02() logic against enum corruption or undefined values.
    /// </summary>
    [TestCase(0x01, false, "0x01 is not a defined SCP02 implementation")]
    [TestCase(0x03, false, "0x03 is not a defined SCP02 implementation")]
    [TestCase(0x06, false, "0x06 is not a defined SCP02 implementation")]
    [TestCase(0x07, false, "0x07 is not a defined SCP02 implementation")]
    [TestCase(0x08, false, "0x08 is not a defined SCP02 implementation")]
    [TestCase(0x09, false, "0x09 is not a defined SCP02 implementation")]
    [TestCase(0x0B, false, "0x0B is not a defined SCP02 implementation")]
    [TestCase(0x0C, false, "0x0C is not a defined SCP02 implementation")]
    [TestCase(0x0D, false, "0x0D is not a defined SCP02 implementation")]
    [TestCase(0x0E, false, "0x0E is not a defined SCP02 implementation")]
    [TestCase(0x0F, false, "0x0F is not a defined SCP02 implementation")]
    public void IsScp02_WithUndefinedValuesInScp02Range_ShouldReturnFalse(
        byte value,
        bool expected,
        string description)
    {
        // Act - Cast undefined byte value to enum
        ScpImplementation implementation = (ScpImplementation)value;
        bool result = implementation.IsScp02();

        // Assert
        _ = result.Should().Be(expected, description);

        // Also verify that GetScp02Implementation() would fail for these values
        Result<ScpImplementation, SmartCardError> implResult = Scp02Protocol.GetScp02Implementation(value);
        _ = implResult.IsFailure.Should().BeTrue($"GetScp02Implementation() should fail for undefined value 0x{value:X2}");
        _ = implResult.Error.Should().BeOfType<UnsupportedImplementationError>();

        TestContext.Out.WriteLine($"✓ {description}");
        TestContext.Out.WriteLine($"Undefined value 0x{value:X2} correctly rejected by both IsScp02() and GetScp02Implementation()");
    }
}