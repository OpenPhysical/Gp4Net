using AwesomeAssertions;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands;

[TestFixture]
[Category("Unit")]
public class RMacSessionCommandsTests
{
    [Test]
    public void BeginRMacSessionCommand_Create_WithValidSecurityLevel_ReturnsSuccess()
    {
        var result = BeginRMacSessionCommand.Create(SecurityLevel.RMac);

        result.IsSuccess.Should().BeTrue();
        result.Value.P1.Should().Be((byte)SecurityLevel.RMac);
    }

    [Test]
    public void BeginRMacSessionCommand_Create_WithInvalidSecurityLevel_ReturnsFailure()
    {
        var result = BeginRMacSessionCommand.Create((SecurityLevel)255);

        result.IsFailure.Should().BeTrue();
        result.Error.Message.Should().Contain("Invalid security level");
    }

    [Test]
    public void BeginRMacSessionCommand_Create_WithInvalidCla_ReturnsFailure()
    {
        var result = BeginRMacSessionCommand.Create(SecurityLevel.RMac, 0xFF);

        result.IsFailure.Should().BeTrue();
        result.Error.Message.Should().Contain("Invalid CLA byte");
    }

    [Test]
    public void BeginRMacSessionCommand_Create_WithInvalidMacLength_ReturnsFailure()
    {
        var invalidMac = new byte[4]; // Should be 8 bytes
        var result = BeginRMacSessionCommand.Create(SecurityLevel.RMac, mac: invalidMac);

        result.IsFailure.Should().BeTrue();
        result.Error.Message.Should().Contain("MAC must be exactly 8 bytes");
    }

    [Test]
    public void BeginRMacSessionCommand_ToString_ReturnsExpectedString()
    {
        var result = BeginRMacSessionCommand.Create(SecurityLevel.RMac);

        result.Value.ToString().Should().Be("BEGIN R-MAC SESSION");
    }

    [Test]
    public void EndRMacSessionCommand_Create_WithValidSecurityLevel_ReturnsSuccess()
    {
        var result = EndRMacSessionCommand.Create(SecurityLevel.RMac);

        result.IsSuccess.Should().BeTrue();
        result.Value.P2.Should().Be(0x03);
    }

    [Test]
    public void EndRMacSessionCommand_Create_WithInvalidSecurityLevel_ReturnsFailure()
    {
        var result = EndRMacSessionCommand.Create((SecurityLevel)255);

        result.IsFailure.Should().BeTrue();
        result.Error.Message.Should().Contain("Invalid security level");
    }

    [Test]
    public void EndRMacSessionCommand_ToString_ReturnsExpectedString()
    {
        var result = EndRMacSessionCommand.Create(SecurityLevel.RMac);

        result.Value.ToString().Should().Be("END R-MAC SESSION");
    }

    [Test]
    public void EndRMacSessionResponse_Parse_WithValidData_ReturnsSuccess()
    {
        var validRMac = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        var result = EndRMacSessionResponse.Parse(validRMac);

        result.IsSuccess.Should().BeTrue();
        result.Value.RMac.Should().BeEquivalentTo(validRMac);
    }

    [Test]
    public void EndRMacSessionResponse_Parse_WithInvalidLength_ReturnsFailure()
    {
        var invalidRMac = new byte[] { 0x01, 0x02 }; // Should be 8 bytes
        var result = EndRMacSessionResponse.Parse(invalidRMac);

        result.IsFailure.Should().BeTrue();
        result.Error.Message.Should().Contain("Response must be exactly 8 bytes");
        result.Error.Message.Should().Contain("got 2 bytes");
    }

    [Test]
    public void EndRMacSessionResponse_Parse_WithNull_ReturnsFailure()
    {
        var result = EndRMacSessionResponse.Parse(null);

        result.IsFailure.Should().BeTrue();
        result.Error.Message.Should().Contain("Response data cannot be null");
    }

    [Test]
    public void EndRMacSessionResponse_ToString_ReturnsExpectedFormat()
    {
        var validRMac = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        var result = EndRMacSessionResponse.Parse(validRMac);
        var toString = result.Value.ToString();

        toString.Should().StartWith("END R-MAC SESSION RESPONSE");
        toString.Should().Contain("0102030405060708");
    }
}