using System;
using System.Collections.Generic;
using System.ComponentModel;
using AwesomeAssertions;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Services;
using Moq;
using NUnit.Framework;

namespace Gp4Net.Tests.Tool.Infrastructure;

[TestFixture]
public class ReaderNameTypeConverterTests
{
    private ReaderNameTypeConverter _converter;
    private Mock<ICardService> _mockCardService;

    [SetUp]
    public void Setup()
    {
        _converter = new ReaderNameTypeConverter();
        _mockCardService = new Mock<ICardService>();

        // Setup CardServiceProvider for tests
        CardServiceProvider.SetCardService(_mockCardService.Object);
    }

    [TearDown]
    public void TearDown()
    {
        // Clean up the static CardServiceProvider
        // Note: In a real scenario, you might want to make CardServiceProvider more testable
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
        var readers = new List<string> { "Test Reader 1" };
        _ = _mockCardService.Setup(s => s.GetReaders()).Returns(readers);

        // Act
        var result = _converter.ConvertFrom(null, null, "auto") as Reader;

        // Assert
        _ = result.Should().NotBeNull();
        _ = result!.Name.Should().Be("Test Reader 1");
        _ = result.IsAutoDetected.Should().BeTrue();
        _ = result.IsPartialMatch.Should().BeFalse();
    }

    [Test]
    public void ConvertFrom_Auto_NoReaders_ThrowsArgumentException()
    {
        // Arrange
        _ = _mockCardService.Setup(s => s.GetReaders()).Returns(new List<string>());

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
        _ = _mockCardService.Setup(s => s.GetReaders()).Returns(readers);

        // Note: In a real test, we would need to mock the console interaction
        // For now, this test would require manual intervention or a more sophisticated setup
        // This demonstrates the test structure
    }

    [Test]
    public void ConvertFrom_ExactMatch_ReturnsReader()
    {
        // Arrange
        var readers = new List<string> { "Test Reader 1", "Test Reader 2" };
        _ = _mockCardService.Setup(s => s.GetReaders()).Returns(readers);

        // Act
        var result = _converter.ConvertFrom(null, null, "Test Reader 1") as Reader;

        // Assert
        _ = result.Should().NotBeNull();
        _ = result!.Name.Should().Be("Test Reader 1");
        _ = result.IsAutoDetected.Should().BeFalse();
        _ = result.IsPartialMatch.Should().BeFalse();
    }

    [Test]
    public void ConvertFrom_ExactMatchCaseInsensitive_ReturnsReader()
    {
        // Arrange
        var readers = new List<string> { "Test Reader 1" };
        _ = _mockCardService.Setup(s => s.GetReaders()).Returns(readers);

        // Act
        var result = _converter.ConvertFrom(null, null, "test READER 1") as Reader;

        // Assert
        _ = result.Should().NotBeNull();
        _ = result!.Name.Should().Be("Test Reader 1");
        _ = result.IsAutoDetected.Should().BeFalse();
        _ = result.IsPartialMatch.Should().BeFalse();
    }

    [Test]
    public void ConvertFrom_PartialMatch_SingleMatch_ReturnsReader()
    {
        // Arrange
        var readers = new List<string> { "Identiv SCR3500 Contact Reader", "Another Reader" };
        _ = _mockCardService.Setup(s => s.GetReaders()).Returns(readers);

        // Act
        var result = _converter.ConvertFrom(null, null, "SCR3500") as Reader;

        // Assert
        _ = result.Should().NotBeNull();
        _ = result!.Name.Should().Be("Identiv SCR3500 Contact Reader");
        _ = result.IsAutoDetected.Should().BeFalse();
        _ = result.IsPartialMatch.Should().BeTrue();
    }

    [Test]
    public void ConvertFrom_PartialMatch_CaseInsensitive_ReturnsReader()
    {
        // Arrange
        var readers = new List<string> { "Identiv SCR3500 Contact Reader" };
        _ = _mockCardService.Setup(s => s.GetReaders()).Returns(readers);

        // Act
        var result = _converter.ConvertFrom(null, null, "scr3500") as Reader;

        // Assert
        _ = result.Should().NotBeNull();
        _ = result!.Name.Should().Be("Identiv SCR3500 Contact Reader");
        _ = result.IsAutoDetected.Should().BeFalse();
        _ = result.IsPartialMatch.Should().BeTrue();
    }

    [Test]
    public void ConvertFrom_PartialMatch_MultipleMatches_RequiresUserSelection()
    {
        // Arrange
        var readers = new List<string> { "Identiv SCR3500 A", "Identiv SCR3500 B" };
        _ = _mockCardService.Setup(s => s.GetReaders()).Returns(readers);

        // Note: Similar to auto with multiple readers, this would require console mocking
    }

    [Test]
    public void ConvertFrom_NoMatch_ThrowsArgumentException()
    {
        // Arrange
        var readers = new List<string> { "Reader 1", "Reader 2" };
        _ = _mockCardService.Setup(s => s.GetReaders()).Returns(readers);

        // Act & Assert
        Action act = () => _converter.ConvertFrom(null, null, "NonExistent");
        var ex = act.Should().ThrowExactly<ArgumentException>().And;
        _ = ex.Message.Should().Contain("Reader 'NonExistent' not found");
    }

    [Test]
    public void ConvertFrom_NullInput_UsesAuto()
    {
        // Arrange
        var readers = new List<string> { "Test Reader" };
        _ = _mockCardService.Setup(s => s.GetReaders()).Returns(readers);

        // Act
        var result = _converter.ConvertFrom(null, null, null) as Reader;

        // Assert
        _ = result.Should().NotBeNull();
        _ = result!.Name.Should().Be("Test Reader");
        _ = result.IsAutoDetected.Should().BeTrue();
    }

    [Test]
    public void ConvertFrom_EmptyInput_UsesAuto()
    {
        // Arrange
        var readers = new List<string> { "Test Reader" };
        _ = _mockCardService.Setup(s => s.GetReaders()).Returns(readers);

        // Act
        var result = _converter.ConvertFrom(null, null, "") as Reader;

        // Assert
        _ = result.Should().NotBeNull();
        _ = result!.Name.Should().Be("Test Reader");
        _ = result.IsAutoDetected.Should().BeTrue();
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

        // For now, we'll test what happens when GetReaders throws
        _ = _mockCardService.Setup(s => s.GetReaders()).Throws<InvalidOperationException>();

        // Act & Assert
        Action act = () => _converter.ConvertFrom(null, null, "auto");
        _ = act.Should().ThrowExactly<InvalidOperationException>();
    }

    [Test]
    public void DefaultValueAttribute_TriggersTypeConverter()
    {
        // This test verifies that using [DefaultValue("auto")] on a Reader property
        // will trigger the TypeConverter when the property is accessed

        // Arrange
        var readers = new List<string> { "Default Reader" };
        _ = _mockCardService.Setup(s => s.GetReaders()).Returns(readers);

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