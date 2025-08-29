using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
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
        Result<BeginRMacSessionCommand, SmartCardError> result = BeginRMacSessionCommand.Create(SecurityLevel.RMac);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.P1.Should().Be((byte)SecurityLevel.RMac);
    }

    [Test]
    public void BeginRMacSessionCommand_Create_WithInvalidSecurityLevel_ReturnsFailure()
    {
        Result<BeginRMacSessionCommand, SmartCardError> result = BeginRMacSessionCommand.Create((SecurityLevel)255);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("Invalid security level");
    }

    [Test]
    public void BeginRMacSessionCommand_Create_WithInvalidCla_ReturnsFailure()
    {
        Result<BeginRMacSessionCommand, SmartCardError> result = BeginRMacSessionCommand.Create(SecurityLevel.RMac, 0xFF);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("Invalid CLA byte");
    }

    [Test]
    public void BeginRMacSessionCommand_Create_WithInvalidMacLength_ReturnsFailure()
    {
        byte[] invalidMac = new byte[4]; // Should be 8 bytes
        Result<BeginRMacSessionCommand, SmartCardError> result = BeginRMacSessionCommand.Create(SecurityLevel.RMac, mac: invalidMac);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("MAC must be exactly 8 bytes");
    }

    [Test]
    public void BeginRMacSessionCommand_ToString_ReturnsExpectedString()
    {
        Result<BeginRMacSessionCommand, SmartCardError> result = BeginRMacSessionCommand.Create(SecurityLevel.RMac);

        _ = result.Value.ToString().Should().Be("BEGIN R-MAC SESSION");
    }

    [Test]
    public void EndRMacSessionCommand_Create_WithValidSecurityLevel_ReturnsSuccess()
    {
        Result<EndRMacSessionCommand, SmartCardError> result = EndRMacSessionCommand.Create(SecurityLevel.RMac);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.P2.Should().Be(0x03);
    }

    [Test]
    public void EndRMacSessionCommand_Create_WithInvalidSecurityLevel_ReturnsFailure()
    {
        Result<EndRMacSessionCommand, SmartCardError> result = EndRMacSessionCommand.Create((SecurityLevel)255);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("Invalid security level");
    }

    [Test]
    public void EndRMacSessionCommand_ToString_ReturnsExpectedString()
    {
        Result<EndRMacSessionCommand, SmartCardError> result = EndRMacSessionCommand.Create(SecurityLevel.RMac);

        _ = result.Value.ToString().Should().Be("END R-MAC SESSION");
    }

    [Test]
    public void EndRMacSessionResponse_Parse_WithValidData_ReturnsSuccess()
    {
        byte[] validRMac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        Result<EndRMacSessionResponse, SmartCardError> result = EndRMacSessionResponse.Parse(validRMac);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.RMac.Should().BeEquivalentTo(validRMac);
    }

    [Test]
    public void EndRMacSessionResponse_Parse_WithInvalidLength_ReturnsFailure()
    {
        byte[] invalidRMac = [0x01, 0x02]; // Should be 8 bytes
        Result<EndRMacSessionResponse, SmartCardError> result = EndRMacSessionResponse.Parse(invalidRMac);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("Response must be exactly 8 bytes");
        _ = result.Error.Message.Should().Contain("got 2 bytes");
    }

    [Test]
    public void EndRMacSessionResponse_Parse_WithNull_ReturnsFailure()
    {
        Result<EndRMacSessionResponse, SmartCardError> result = EndRMacSessionResponse.Parse(null);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("Response data cannot be null");
    }

    [Test]
    public void EndRMacSessionResponse_ToString_ReturnsExpectedFormat()
    {
        byte[] validRMac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        Result<EndRMacSessionResponse, SmartCardError> result = EndRMacSessionResponse.Parse(validRMac);
        string? toString = result.Value.ToString();

        _ = toString.Should().StartWith("END R-MAC SESSION RESPONSE");
        _ = toString.Should().Contain("0102030405060708");
    }
}