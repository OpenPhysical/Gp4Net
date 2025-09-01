using System;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Domain.CardInfo;
using Gp4Net.Domain.Commands;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands;

public class GetDataResponseExtensionsTests
{
    [Test]
    public void ParseAsCardData_WithValidData_ReturnsCardDataInfo()
    {
        // Arrange - Sample card data with OID
        byte[] data = Convert.FromHexString("660C73066060402A00640508AAAA");

        // Act
        Maybe<CardDataInfo> result = data.ParseAsCardData();

        // Assert
        _ = result.HasValue.Should().BeTrue();
        // Further assertions would require knowing the expected CardDataInfo structure
    }

    [Test]
    public void ParseAsCardData_WithInvalidData_ReturnsNone()
    {
        // Arrange
        byte[] data = [0x00, 0x01, 0x02];

        // Act
        Maybe<CardDataInfo> result = data.ParseAsCardData();

        // Assert
        _ = result.HasValue.Should().BeFalse();
    }

    [Test]
    public void ParseAsCardData_WithEmptyData_ReturnsNone()
    {
        // Arrange
        byte[] data = [];

        // Act
        Maybe<CardDataInfo> result = data.ParseAsCardData();

        // Assert
        _ = result.HasValue.Should().BeFalse();
    }

    [Test]
    public void ParseAsCardData_WithNullData_ReturnsNone()
    {
        // Arrange
        byte[]? data = null;

        // Act
        Maybe<CardDataInfo> result = data.ParseAsCardData();

        // Assert
        _ = result.HasValue.Should().BeFalse();
    }

    [Test]
    public void ParseAsCardCapabilities_WithValidData_ReturnsCardCapabilities()
    {
        // Arrange - Sample capabilities data
        byte[] data = Convert.FromHexString("670A810201820103830101");

        // Act
        Maybe<CardCapabilities> result = data.ParseAsCardCapabilities();

        // Assert
        _ = result.HasValue.Should().BeTrue();
        // Further assertions would require knowing the expected CardCapabilities structure
    }

    [Test]
    public void ParseAsCardCapabilities_WithInvalidData_ReturnsNone()
    {
        // Arrange
        byte[] data = [0xFF];

        // Act
        Maybe<CardCapabilities> result = data.ParseAsCardCapabilities();

        // Assert
        _ = result.HasValue.Should().BeFalse();
    }

    [Test]
    public void ParseAsCardCapabilities_WithEmptyData_ReturnsNone()
    {
        // Arrange
        byte[] data = [];

        // Act
        Maybe<CardCapabilities> result = data.ParseAsCardCapabilities();

        // Assert
        _ = result.HasValue.Should().BeFalse();
    }

    [Test]
    public void ParseAsCardCapabilities_WithNullData_ReturnsNone()
    {
        // Arrange
        byte[]? data = null;

        // Act
        Maybe<CardCapabilities> result = data.ParseAsCardCapabilities();

        // Assert
        _ = result.HasValue.Should().BeFalse();
    }

    [Test]
    public void ParseAsKeyInformation_WithValidData_ReturnsKeyInformationTemplate()
    {
        // Arrange - Sample key information template data (tag E0)
        byte[] data = Convert.FromHexString("E010C00401018810C00402018810C00403018810");

        // Act
        Maybe<KeyInformationTemplate> result = data.ParseAsKeyInformation();

        // Assert
        _ = result.HasValue.Should().BeTrue();
        _ = result.Value.Keys.Should().NotBeEmpty();
    }

    [Test]
    public void ParseAsKeyInformation_WithInvalidData_ReturnsNone()
    {
        // Arrange
        byte[] data = [0x00];

        // Act
        Maybe<KeyInformationTemplate> result = data.ParseAsKeyInformation();

        // Assert
        _ = result.HasValue.Should().BeFalse();
    }

    [Test]
    public void ParseAsKeyInformation_WithEmptyData_ReturnsNone()
    {
        // Arrange
        byte[] data = [];

        // Act
        Maybe<KeyInformationTemplate> result = data.ParseAsKeyInformation();

        // Assert
        _ = result.HasValue.Should().BeFalse();
    }

    [Test]
    public void ParseAsKeyInformation_WithNullData_ReturnsNone()
    {
        // Arrange
        byte[]? data = null;

        // Act
        Maybe<KeyInformationTemplate> result = data.ParseAsKeyInformation();

        // Assert
        _ = result.HasValue.Should().BeFalse();
    }

    [Test]
    public void ParseAsCplc_WithValidData_ReturnsCplcData()
    {
        // Arrange - CPLC data is always 42 bytes
        byte[] data = new byte[42];
        // Fill with sample data
        Array.Fill(data, (byte)0x00);
        data[0] = 0x12; // IC Fabricator
        data[1] = 0x34;

        // Act
        Maybe<CplcData> result = data.ParseAsCplc();

        // Assert
        _ = result.HasValue.Should().BeTrue();
        _ = result.Value.IcFabricator.Should().Be(0x1234);
    }

    [Test]
    public void ParseAsCplc_WithWrongLength_ReturnsNone()
    {
        // Arrange - CPLC must be exactly 42 bytes
        byte[] data = new byte[40];

        // Act
        Maybe<CplcData> result = data.ParseAsCplc();

        // Assert
        _ = result.HasValue.Should().BeFalse();
    }

    [Test]
    public void ParseAsCplc_WithEmptyData_ReturnsNone()
    {
        // Arrange
        byte[] data = [];

        // Act
        Maybe<CplcData> result = data.ParseAsCplc();

        // Assert
        _ = result.HasValue.Should().BeFalse();
    }

    [Test]
    public void ParseAsCplc_WithNullData_ReturnsNone()
    {
        // Arrange
        byte[]? data = null;

        // Act
        Maybe<CplcData> result = data.ParseAsCplc();

        // Assert
        _ = result.HasValue.Should().BeFalse();
    }

    [Test]
    public void AllParseMethods_HandleExceptionsGracefully()
    {
        // Arrange - Data that might cause parsing exceptions
        byte[] malformedData = [0xFF, 0xFF, 0xFF];

        // Act & Assert - None should throw, all should return None
        _ = malformedData.ParseAsCardData().HasValue.Should().BeFalse();
        _ = malformedData.ParseAsCardCapabilities().HasValue.Should().BeFalse();
        _ = malformedData.ParseAsKeyInformation().HasValue.Should().BeFalse();
        _ = malformedData.ParseAsCplc().HasValue.Should().BeFalse();
    }
}
