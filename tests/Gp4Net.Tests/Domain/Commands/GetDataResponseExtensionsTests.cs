using System;
using AwesomeAssertions;
using Gp4Net.Domain.Commands;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands;

public class GetDataResponseExtensionsTests
{
    [Test]
    public void ParseAsCardData_WithValidData_ReturnsCardDataInfo()
    {
        // Arrange - Sample card data with OID
        var data = Convert.FromHexString("660C73066060402A00640508AAAA");

        // Act
        var result = data.ParseAsCardData();

        // Assert
        result.HasValue.Should().BeTrue();
        // Further assertions would require knowing the expected CardDataInfo structure
    }

    [Test]
    public void ParseAsCardData_WithInvalidData_ReturnsNone()
    {
        // Arrange
        var data = new byte[] { 0x00, 0x01, 0x02 };

        // Act
        var result = data.ParseAsCardData();

        // Assert
        result.HasValue.Should().BeFalse();
    }

    [Test]
    public void ParseAsCardData_WithEmptyData_ReturnsNone()
    {
        // Arrange
        var data = Array.Empty<byte>();

        // Act
        var result = data.ParseAsCardData();

        // Assert
        result.HasValue.Should().BeFalse();
    }

    [Test]
    public void ParseAsCardData_WithNullData_ReturnsNone()
    {
        // Arrange
        byte[] data = null;

        // Act
        var result = data.ParseAsCardData();

        // Assert
        result.HasValue.Should().BeFalse();
    }

    [Test]
    public void ParseAsCardCapabilities_WithValidData_ReturnsCardCapabilities()
    {
        // Arrange - Sample capabilities data
        var data = Convert.FromHexString("670A810201820103830101");

        // Act
        var result = data.ParseAsCardCapabilities();

        // Assert
        result.HasValue.Should().BeTrue();
        // Further assertions would require knowing the expected CardCapabilities structure
    }

    [Test]
    public void ParseAsCardCapabilities_WithInvalidData_ReturnsNone()
    {
        // Arrange
        var data = new byte[] { 0xFF };

        // Act
        var result = data.ParseAsCardCapabilities();

        // Assert
        result.HasValue.Should().BeFalse();
    }

    [Test]
    public void ParseAsCardCapabilities_WithEmptyData_ReturnsNone()
    {
        // Arrange
        var data = Array.Empty<byte>();

        // Act
        var result = data.ParseAsCardCapabilities();

        // Assert
        result.HasValue.Should().BeFalse();
    }

    [Test]
    public void ParseAsCardCapabilities_WithNullData_ReturnsNone()
    {
        // Arrange
        byte[] data = null;

        // Act
        var result = data.ParseAsCardCapabilities();

        // Assert
        result.HasValue.Should().BeFalse();
    }

    [Test]
    public void ParseAsKeyInformation_WithValidData_ReturnsKeyInformationTemplate()
    {
        // Arrange - Sample key information template data (tag E0)
        var data = Convert.FromHexString("E010C00401018810C00402018810C00403018810");

        // Act
        var result = data.ParseAsKeyInformation();

        // Assert
        result.HasValue.Should().BeTrue();
        result.Value.Keys.Should().NotBeEmpty();
    }

    [Test]
    public void ParseAsKeyInformation_WithInvalidData_ReturnsNone()
    {
        // Arrange
        var data = new byte[] { 0x00 };

        // Act
        var result = data.ParseAsKeyInformation();

        // Assert
        result.HasValue.Should().BeFalse();
    }

    [Test]
    public void ParseAsKeyInformation_WithEmptyData_ReturnsNone()
    {
        // Arrange
        var data = Array.Empty<byte>();

        // Act
        var result = data.ParseAsKeyInformation();

        // Assert
        result.HasValue.Should().BeFalse();
    }

    [Test]
    public void ParseAsKeyInformation_WithNullData_ReturnsNone()
    {
        // Arrange
        byte[] data = null;

        // Act
        var result = data.ParseAsKeyInformation();

        // Assert
        result.HasValue.Should().BeFalse();
    }

    [Test]
    public void ParseAsCplc_WithValidData_ReturnsCplcData()
    {
        // Arrange - CPLC data is always 42 bytes
        var data = new byte[42];
        // Fill with sample data
        Array.Fill(data, (byte)0x00);
        data[0] = 0x12; // IC Fabricator
        data[1] = 0x34;

        // Act
        var result = data.ParseAsCplc();

        // Assert
        result.HasValue.Should().BeTrue();
        result.Value.IcFabricator.Should().Be(0x1234);
    }

    [Test]
    public void ParseAsCplc_WithWrongLength_ReturnsNone()
    {
        // Arrange - CPLC must be exactly 42 bytes
        var data = new byte[40];

        // Act
        var result = data.ParseAsCplc();

        // Assert
        result.HasValue.Should().BeFalse();
    }

    [Test]
    public void ParseAsCplc_WithEmptyData_ReturnsNone()
    {
        // Arrange
        var data = Array.Empty<byte>();

        // Act
        var result = data.ParseAsCplc();

        // Assert
        result.HasValue.Should().BeFalse();
    }

    [Test]
    public void ParseAsCplc_WithNullData_ReturnsNone()
    {
        // Arrange
        byte[] data = null;

        // Act
        var result = data.ParseAsCplc();

        // Assert
        result.HasValue.Should().BeFalse();
    }

    [Test]
    public void AllParseMethods_HandleExceptionsGracefully()
    {
        // Arrange - Data that might cause parsing exceptions
        var malformedData = new byte[] { 0xFF, 0xFF, 0xFF };

        // Act & Assert - None should throw, all should return None
        malformedData.ParseAsCardData().HasValue.Should().BeFalse();
        malformedData.ParseAsCardCapabilities().HasValue.Should().BeFalse();
        malformedData.ParseAsKeyInformation().HasValue.Should().BeFalse();
        malformedData.ParseAsCplc().HasValue.Should().BeFalse();
    }
}