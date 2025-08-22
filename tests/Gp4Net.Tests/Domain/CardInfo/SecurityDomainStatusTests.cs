using System;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Domain.CardInfo;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.CardInfo;

/// <summary>
/// Unit tests for SecurityDomainStatus parser.
/// </summary>
public class SecurityDomainStatusTests
{
    [Test]
    public void Parse_WithValidC1020004_ReturnsCorrectStatus()
    {
        // Arrange - C1020004 from card 1
        var data = Convert.FromHexString("C1020004");
        
        // Act
        var result = SecurityDomainStatus.Parse(data);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var status = result.Value;
        _ = status.StateByte.Should().Be(0x00);
        _ = status.GetIsdState().Should().Be(IsdState.Unknown);
        _ = status.IsPersonalized().Should().BeFalse();
        _ = status.IsLocked().Should().BeFalse();
        _ = status.GetSequenceCounter().HasValue.Should().BeTrue();
        _ = status.GetSequenceCounter().Value.Should().Be((ushort)0x04);
    }
    
    [Test]
    public void Parse_WithValidC103000046_ReturnsCorrectStatus()
    {
        // Arrange - C103000046 from card 2
        var data = Convert.FromHexString("C103000046");
        
        // Act
        var result = SecurityDomainStatus.Parse(data);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var status = result.Value;
        _ = status.StateByte.Should().Be(0x00);
        _ = status.GetIsdState().Should().Be(IsdState.Unknown);
        _ = status.IsPersonalized().Should().BeFalse();
        _ = status.IsLocked().Should().BeFalse();
        _ = status.GetSequenceCounter().HasValue.Should().BeTrue();
        _ = status.GetSequenceCounter().Value.Should().Be((ushort)0x0046);
    }
    
    [Test]
    public void Parse_WithOpReadyState_ReturnsCorrectState()
    {
        // Arrange - OP_READY state
        var data = Convert.FromHexString("C1020112"); // State: 0x01 (OP_READY), Counter: 0x12
        
        // Act
        var result = SecurityDomainStatus.Parse(data);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var status = result.Value;
        _ = status.GetIsdState().Should().Be(IsdState.OpReady);
        _ = status.IsPersonalized().Should().BeFalse();
        _ = status.IsLocked().Should().BeFalse();
    }
    
    [Test]
    public void Parse_WithPersonalizedFlag_ReturnsCorrectStatus()
    {
        // Arrange - Personalized flag set
        var data = Convert.FromHexString("C1021700"); // State: 0x17 (0x10 | 0x07)
        
        // Act
        var result = SecurityDomainStatus.Parse(data);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var status = result.Value;
        _ = status.GetIsdState().Should().Be(IsdState.Initialized);
        _ = status.IsPersonalized().Should().BeTrue();
        _ = status.IsLocked().Should().BeFalse();
    }
    
    [Test]
    public void Parse_WithLockedFlag_ReturnsCorrectStatus()
    {
        // Arrange - Locked flag set
        var data = Convert.FromHexString("C1028100"); // State: 0x81 (0x80 | 0x01)
        
        // Act
        var result = SecurityDomainStatus.Parse(data);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var status = result.Value;
        _ = status.GetIsdState().Should().Be(IsdState.OpReady);
        _ = status.IsPersonalized().Should().BeFalse();
        _ = status.IsLocked().Should().BeTrue();
    }
    
    [Test]
    public void Parse_WithCardLockedState_ReturnsCorrectState()
    {
        // Arrange - CARD_LOCKED state
        var data = Convert.FromHexString("C1027F00");
        
        // Act
        var result = SecurityDomainStatus.Parse(data);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var status = result.Value;
        _ = status.GetIsdState().Should().Be(IsdState.CardLocked);
    }
    
    [Test]
    public void Parse_WithTerminatedState_ReturnsCorrectState()
    {
        // Arrange - TERMINATED state
        var data = Convert.FromHexString("C102FF00");
        
        // Act
        var result = SecurityDomainStatus.Parse(data);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var status = result.Value;
        _ = status.GetIsdState().Should().Be(IsdState.Terminated);
    }
    
    [Test]
    public void Parse_WithWrongTag_ReturnsFailure()
    {
        // Arrange - Wrong tag
        var data = Convert.FromHexString("C2020004");
        
        // Act
        var result = SecurityDomainStatus.Parse(data);

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("Invalid tag: expected 0xC1, got 0xC2");
    }
    
    [Test]
    public void Parse_WithTooShortData_ReturnsFailure()
    {
        // Arrange - Too short
        var data = Convert.FromHexString("C102");
        
        // Act
        var result = SecurityDomainStatus.Parse(data);

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("too short");
    }
    
    [Test]
    public void Parse_WithNullData_ReturnsFailure()
    {
        // Act
        var result = SecurityDomainStatus.Parse(Maybe<byte[]>.None);

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("cannot be null");
    }
    
    [Test]
    public void ToString_WithC1020004_ReturnsFormattedString()
    {
        // Arrange
        var data = Convert.FromHexString("C1020004");
        var status = SecurityDomainStatus.Parse(data).Value;
        
        // Act
        var description = status.ToString();

        // Assert
        _ = description.Should().Contain("Security Domain Status:");
        _ = description.Should().Contain("State=Unknown");
        _ = description.Should().Contain("Sequence=0x0004");
    }
    
    [Test]
    public void GetShortDescription_WithPersonalizedAndCounter_ReturnsCompactString()
    {
        // Arrange
        var data = Convert.FromHexString("C1031F1234"); // Personalized, Initialized, Counter: 0x1234
        var status = SecurityDomainStatus.Parse(data).Value;
        
        // Act
        var description = status.GetShortDescription();

        // Assert
        _ = description.Should().Be("Secured, Personalized, Seq:0x1234");
    }
    
    [TestCase("C10100", 0)] // No additional data - length 1, just state byte
    [TestCase("C1020000", 0)] // Two bytes additional data but zero value
    [TestCase("C1020004", 0x0004)] // Two byte counter
    [TestCase("C103000046", 0x0046)] // Three bytes, counter in last two
    [TestCase("C104AA001234", 0x1234)] // Four bytes, counter in last two
    public void GetSequenceCounter_WithVariousFormats_ReturnsExpectedValue(string hex, int expectedCounter)
    {
        // Arrange
        var data = Convert.FromHexString(hex);
        var status = SecurityDomainStatus.Parse(data).Value;
        
        // Act
        var counter = status.GetSequenceCounter();
        
        // Assert
        if (expectedCounter == 0 && hex.Length <= 6)
        {
            _ = counter.HasValue.Should().BeFalse();
        }
        else
        {
            _ = counter.HasValue.Should().BeTrue();
            _ = counter.Value.Should().Be((ushort)expectedCounter);
        }
    }
}