using System;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain;
using Gp4Net.Core;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands
{
    [TestFixture]
    public class RMacSessionCommandsTests
    {
        [Test]
        public void BeginRMacSessionCommand_Create_WithValidSecurityLevel_ReturnsSuccess()
        {
            var result = BeginRMacSessionCommand.Create(SecurityLevel.RMac);
            
            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.P1, Is.EqualTo((byte)SecurityLevel.RMac));
        }

        [Test]
        public void BeginRMacSessionCommand_Create_WithInvalidSecurityLevel_ReturnsFailure()
        {
            var result = BeginRMacSessionCommand.Create((SecurityLevel)255);
            
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Message, Does.Contain("Invalid security level"));
        }

        [Test]
        public void BeginRMacSessionCommand_Create_WithInvalidCla_ReturnsFailure()
        {
            var result = BeginRMacSessionCommand.Create(SecurityLevel.RMac, 0xFF);
            
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Message, Does.Contain("Invalid CLA byte"));
        }

        [Test]
        public void BeginRMacSessionCommand_Create_WithInvalidMacLength_ReturnsFailure()
        {
            var invalidMac = new byte[4]; // Should be 8 bytes
            var result = BeginRMacSessionCommand.Create(SecurityLevel.RMac, mac: invalidMac);
            
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Message, Does.Contain("MAC must be exactly 8 bytes"));
        }

        [Test]
        public void BeginRMacSessionCommand_ToString_ReturnsExpectedString()
        {
            var result = BeginRMacSessionCommand.Create(SecurityLevel.RMac);
            
            Assert.That(result.Value.ToString(), Is.EqualTo("BEGIN R-MAC SESSION"));
        }

        [Test]
        public void EndRMacSessionCommand_Create_WithValidSecurityLevel_ReturnsSuccess()
        {
            var result = EndRMacSessionCommand.Create(SecurityLevel.RMac);
            
            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.P2, Is.EqualTo(0x03));
        }

        [Test]
        public void EndRMacSessionCommand_Create_WithInvalidSecurityLevel_ReturnsFailure()
        {
            var result = EndRMacSessionCommand.Create((SecurityLevel)255);
            
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Message, Does.Contain("Invalid security level"));
        }

        [Test]
        public void EndRMacSessionCommand_ToString_ReturnsExpectedString()
        {
            var result = EndRMacSessionCommand.Create(SecurityLevel.RMac);
            
            Assert.That(result.Value.ToString(), Is.EqualTo("END R-MAC SESSION"));
        }

        [Test]
        public void EndRMacSessionResponse_Parse_WithValidData_ReturnsSuccess()
        {
            var validRMac = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
            var result = EndRMacSessionResponse.Parse(validRMac);
            
            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.RMac, Is.EqualTo(validRMac));
        }

        [Test]
        public void EndRMacSessionResponse_Parse_WithInvalidLength_ReturnsFailure()
        {
            var invalidRMac = new byte[] { 0x01, 0x02 }; // Should be 8 bytes
            var result = EndRMacSessionResponse.Parse(invalidRMac);
            
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Message, Does.Contain("Response must be exactly 8 bytes"));
            Assert.That(result.Error.Message, Does.Contain("got 2 bytes"));
        }

        [Test]
        public void EndRMacSessionResponse_Parse_WithNull_ReturnsFailure()
        {
            var result = EndRMacSessionResponse.Parse(null);
            
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Message, Does.Contain("Response data cannot be null"));
        }

        [Test]
        public void EndRMacSessionResponse_ToString_ReturnsExpectedFormat()
        {
            var validRMac = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
            var result = EndRMacSessionResponse.Parse(validRMac);
            var toString = result.Value.ToString();
            
            Assert.That(toString, Does.StartWith("END R-MAC SESSION RESPONSE"));
            Assert.That(toString, Does.Contain("0102030405060708"));
        }
    }
}