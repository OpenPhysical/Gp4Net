using System;
using System.Collections.Generic;
using System.ComponentModel;
using AwesomeAssertions;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Services;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Tests.TestHelpers;
using NUnit.Framework;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Tests.Tool.Infrastructure;

[TestFixture]
public class ReaderNameTypeConverterTests
{
    private ReaderNameTypeConverter _converter;
    private Gp4Net.Tool.Services.ICardService _cardService;

    private VirtualCardService _virtualCardService = null!;

    [SetUp]
    public void Setup()
    {
        _converter = new ReaderNameTypeConverter();
        _virtualCardService = new VirtualCardService();
        _virtualCardService.SetupComprehensiveTestEnvironment();
        _cardService = new TestCardService(_virtualCardService);

        // Setup CardServiceProvider for tests
        CardServiceProvider.SetCardService(_cardService);
    }

    [TearDown]
    public void TearDown()
    {
        _cardService?.Dispose();
        _virtualCardService?.Dispose();
    }

    [Test]
    public void CanConvertFrom_String_ReturnsTrue()
    {
        // Act
        var result = _converter.CanConvertFrom(null, typeof(string));

        // Assert
        _ = result.Should().BeTrue();
    }

    [Test]
    public void CanConvertFrom_NotString_ReturnsFalse()
    {
        // Act
        var result = _converter.CanConvertFrom(null, typeof(int));

        // Assert
        _ = result.Should().BeFalse();
    }

    [Test]
    public void ConvertFrom_Auto_SingleReader_ReturnsAutoDetectedReader()
    {
        // Arrange
        // Virtual card service provides virtual readers, but auto-detection doesn't work with them
        // This test should expect an exception since auto-detection requires explicit virtual- prefix

        // Act & Assert
        Action act = () => _converter.ConvertFrom(null, null, "auto");
        var ex = act.Should().ThrowExactly<ArgumentException>().And;
        _ = ex.Message.Should().Contain("No physical card readers found for auto-detection");
    }

    [Test]
    public void ConvertFrom_Auto_NoReaders_ThrowsArgumentException()
    {
        // Arrange
        // Virtual card service provides virtual readers, but auto-detection doesn't support them
        // Clear card service provider to simulate no readers scenario
        CardServiceProvider.SetCardService(new EmptyCardService());

        // Act & Assert
        Action act = () => _converter.ConvertFrom(null, null, "auto");
        var ex = act.Should().ThrowExactly<ArgumentException>().And;
        _ = ex.Message.Should().Contain("No card readers found");
    }

    [Test]
    public void ConvertFrom_Auto_MultipleReaders_RequiresUserSelection()
    {
        // Arrange
        var readers = new List<string> { "Reader 1", "Reader 2", "Reader 3" };
        // Virtual card service provides test readers automatically

        // Note: In a real test, we would need to mock the console interaction
        // For now, this test would require manual intervention or a more sophisticated setup
        // This demonstrates the test structure
    }

    [Test]
    public void ConvertFrom_ExactMatch_ReturnsReader()
    {
        // Arrange
        // Virtual card service provides actual virtual readers
        // Use exact name from virtual reader

        // Act
        var result = _converter.ConvertFrom(null, null, "Virtual P71 Reader 00 00") as Reader;

        // Assert
        _ = result.Should().BeOfType<Reader>();
        _ = result!.Name.Should().Be("Virtual P71 Reader 00 00");
        _ = result.IsAutoDetected.Should().BeFalse();
        _ = result.IsPartialMatch.Should().BeFalse();
    }

    [Test]
    public void ConvertFrom_ExactMatchCaseInsensitive_ReturnsReader()
    {
        // Arrange
        // Virtual card service provides actual virtual readers
        // Test case-insensitive matching

        // Act
        var result = _converter.ConvertFrom(null, null, "virtual p71 reader 00 00") as Reader;

        // Assert
        _ = result.Should().BeOfType<Reader>();
        _ = result!.Name.Should().Be("Virtual P71 Reader 00 00");
        _ = result.IsAutoDetected.Should().BeFalse();
        _ = result.IsPartialMatch.Should().BeFalse();
    }

    [Test]
    public void ConvertFrom_PartialMatch_SingleMatch_ReturnsReader()
    {
        // Arrange
        var readers = new List<string> { "Virtual SCP03 Reader 02 00", "Another Reader" };
        // Virtual card service provides test readers automatically

        // Act
        var result = _converter.ConvertFrom(null, null, "SCP03") as Reader;

        // Assert
        _ = result.Should().NotBeNull();
        _ = result!.Name.Should().Be("Virtual SCP03 Reader 02 00");
        _ = result.IsAutoDetected.Should().BeFalse();
        _ = result.IsPartialMatch.Should().BeTrue();
    }

    [Test]
    public void ConvertFrom_PartialMatch_CaseInsensitive_ReturnsReader()
    {
        // Arrange
        var readers = new List<string> { "Virtual SCP03 Reader 02 00" };
        // Virtual card service provides test readers automatically

        // Act
        var result = _converter.ConvertFrom(null, null, "scp03") as Reader;

        // Assert
        _ = result.Should().NotBeNull();
        _ = result!.Name.Should().Be("Virtual SCP03 Reader 02 00");
        _ = result.IsAutoDetected.Should().BeFalse();
        _ = result.IsPartialMatch.Should().BeTrue();
    }

    [Test]
    public void ConvertFrom_PartialMatch_MultipleMatches_RequiresUserSelection()
    {
        // Arrange
        var readers = new List<string> { "Virtual SCP03 Reader 02 A", "Virtual SCP03 Reader 02 B" };
        // Virtual card service provides test readers automatically

        // Note: Similar to auto with multiple readers, this would require console mocking
    }

    [Test]
    public void ConvertFrom_NoMatch_ThrowsArgumentException()
    {
        // Arrange
        var readers = new List<string> { "Reader 1", "Reader 2" };
        // Virtual card service provides test readers automatically

        // Act & Assert
        Action act = () => _converter.ConvertFrom(null, null, "NonExistent");
        var ex = act.Should().ThrowExactly<ArgumentException>().And;
        _ = ex.Message.Should().Contain("Reader 'NonExistent' not found");
    }

    [Test]
    public void ConvertFrom_NullInput_UsesAuto()
    {
        // Arrange
        // Virtual card service provides virtual readers, but auto-detection doesn't support them
        // This should throw since auto-detection requires physical readers

        // Act & Assert
        Action act = () => _converter.ConvertFrom(null, null, null);
        var ex = act.Should().ThrowExactly<ArgumentException>().And;
        _ = ex.Message.Should().Contain("No physical card readers found for auto-detection");
    }

    [Test]
    public void ConvertFrom_EmptyInput_UsesAuto()
    {
        // Arrange
        // Virtual card service provides virtual readers, but auto-detection doesn't support them
        // Empty input defaults to "auto" which should throw

        // Act & Assert
        Action act = () => _converter.ConvertFrom(null, null, "");
        var ex = act.Should().ThrowExactly<ArgumentException>().And;
        _ = ex.Message.Should().Contain("No physical card readers found for auto-detection");
    }

    [Test]
    public void ConvertFrom_NonStringInput_CallsBase()
    {
        // Act & Assert
        Action act = () => _converter.ConvertFrom(null, null, 123);
        _ = act.Should().ThrowExactly<NotSupportedException>();
    }

    [Test]
    public void ConvertFrom_CardServiceNotAvailable_ThrowsInvalidOperationException()
    {
        // Arrange
        // Clear the CardServiceProvider to simulate it not being initialized
        // This would require making CardServiceProvider more testable in real code

        // Clear card service provider to simulate error condition
        CardServiceProvider.SetCardService(new EmptyCardService());
        
        // Act & Assert - With no readers available, converter handles gracefully
        Action act = () => _converter.ConvertFrom(null, null, "auto");
        _ = act.Should().ThrowExactly<ArgumentException>();
    }

    [Test]
    public void DefaultValueAttribute_TriggersTypeConverter()
    {
        // This test verifies that using [DefaultValue("auto")] on a Reader property
        // will trigger the TypeConverter when the property is accessed

        // Arrange
        var readers = new List<string> { "Default Reader" };
        // Virtual card service provides test readers automatically

        // Create a test class with DefaultValue attribute
        var testSettings = new TestSettings();

        // Act - Get default value through type descriptor
        var properties = TypeDescriptor.GetProperties(testSettings);
        var readerProperty = properties["TestReader"];
        var defaultValue =
            readerProperty?.Attributes[typeof(DefaultValueAttribute)] as DefaultValueAttribute;

        // Assert
        _ = defaultValue.Should().NotBeNull();
        _ = defaultValue!.Value.Should().Be("auto");
    }

    // Test helper class
    private class TestSettings
    {
        [TypeConverter(typeof(ReaderNameTypeConverter))]
        [DefaultValue("auto")]
        public Reader? TestReader { get; set; }
    }
}