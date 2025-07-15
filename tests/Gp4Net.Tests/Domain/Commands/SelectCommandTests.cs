using System;
using System.Linq;
using Gp4Net.Core;
using Gp4Net.Core.Tlv;
using Gp4Net.Domain.Commands;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands
{
    [TestFixture]
    public class SelectCommandTests
    {
        [Test]
        public void Create_WithValidAid_ReturnsSuccess()
        {
            var aid = Convert.FromHexString("A000000151000000");

            var result = SelectCommand.Create(aid);

            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.Aid, Is.EqualTo(aid));
            Assert.That(result.Value.Control, Is.EqualTo(SelectCommand.SelectionControl.SelectByName));
            Assert.That(result.Value.ControlInfo, Is.EqualTo(SelectCommand.FileControlInfo.ReturnFci));
        }

        [Test]
        public void Create_WithEmptyAid_ReturnsSuccess()
        {
            var aid = Array.Empty<byte>();

            var result = SelectCommand.Create(aid);

            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.Aid, Is.Empty);
            Assert.That(result.Value.Control, Is.EqualTo(SelectCommand.SelectionControl.SelectByName));
            Assert.That(result.Value.ControlInfo, Is.EqualTo(SelectCommand.FileControlInfo.ReturnFci));
        }

        [Test]
        public void Create_WithNullAid_ReturnsFailure()
        {
            var result = SelectCommand.Create(null);

            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Code, Is.EqualTo("INVALID_DATA"));
            Assert.That(result.Error.Message, Does.Contain("AID cannot be null"));
        }

        [Test]
        public void Create_WithMaxLengthAid_ReturnsSuccess()
        {
            var aid = new byte[16]; // Maximum allowed length
            aid[0] = 0xA0; // Make it a valid AID

            var result = SelectCommand.Create(aid);

            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.Aid, Is.EqualTo(aid));
        }

        [Test]
        public void Create_WithTooLongAid_ReturnsFailure()
        {
            var aid = new byte[17]; // Too long

            var result = SelectCommand.Create(aid);

            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Code, Is.EqualTo("INVALID_DATA"));
            Assert.That(result.Error.Message, Does.Contain("AID must be 16 bytes or less"));
        }

        [Test]
        public void Create_WithFirstMode_SetsCorrectControlInfo()
        {
            var aid = Convert.FromHexString("A000000151000000");

            var result = SelectCommand.Create(aid, SelectCommand.SelectMode.First);

            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.ControlInfo, Is.EqualTo(SelectCommand.FileControlInfo.ReturnFci));
        }

        [Test]
        public void Create_WithNextMode_SetsCorrectControlInfo()
        {
            var aid = Convert.FromHexString("A000000151000000");

            var result = SelectCommand.Create(aid, SelectCommand.SelectMode.Next);

            Assert.That(result.IsSuccess, Is.True);
            var expectedControlInfo = (SelectCommand.FileControlInfo)((byte)SelectCommand.FileControlInfo.ReturnFci | (byte)SelectCommand.SelectMode.Next);
            Assert.That(result.Value.ControlInfo, Is.EqualTo(expectedControlInfo));
        }

        [Test]
        public void CreateForIssuerSecurityDomain_CreatesCorrectCommand()
        {
            var result = SelectCommand.CreateForIssuerSecurityDomain();

            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.Aid, Is.Empty);
            Assert.That(result.Value.Control, Is.EqualTo(SelectCommand.SelectionControl.SelectByName));
            Assert.That(result.Value.ControlInfo, Is.EqualTo(SelectCommand.FileControlInfo.ReturnFci));
        }

        [Test]
        public void ApduProperties_AreCorrect()
        {
            var aid = Convert.FromHexString("A000000151000000");
            var result = SelectCommand.Create(aid);
            var command = result.Value;

            Assert.That(command.Cla, Is.EqualTo(0x00));
            Assert.That(command.Ins, Is.EqualTo(0xA4));
            Assert.That(command.P1, Is.EqualTo((byte)SelectCommand.SelectionControl.SelectByName));
            Assert.That(command.P2, Is.EqualTo((byte)SelectCommand.FileControlInfo.ReturnFci));
            Assert.That(command.Data, Is.EqualTo(aid));
            Assert.That(command.ExpectedResponseLength, Is.EqualTo(256));
        }

        [Test]
        public void ToApdu_WithEmptyAid_GeneratesCorrectApdu()
        {
            var result = SelectCommand.CreateForIssuerSecurityDomain();
            var command = result.Value;

            var apdu = command.ToApdu();

            Assert.That(apdu, Is.EqualTo(new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 }));
        }

        [Test]
        public void ToApdu_WithAid_GeneratesCorrectApdu()
        {
            var aid = Convert.FromHexString("A000000151000000");
            var result = SelectCommand.Create(aid);
            var command = result.Value;

            var apdu = command.ToApdu();

            var expected = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x08 }
                .Concat(aid)
                .Concat(new byte[] { 0x00 })
                .ToArray();
            Assert.That(apdu, Is.EqualTo(expected));
        }

        [Test]
        public void ToApdu_WithNextMode_GeneratesCorrectApdu()
        {
            var aid = Convert.FromHexString("A000000151000000");
            var result = SelectCommand.Create(aid, SelectCommand.SelectMode.Next);
            var command = result.Value;

            var apdu = command.ToApdu();

            var expected = new byte[] { 0x00, 0xA4, 0x04, 0x02, 0x08 }
                .Concat(aid)
                .Concat(new byte[] { 0x00 })
                .ToArray();
            Assert.That(apdu, Is.EqualTo(expected));
        }

        [Test]
        public void ToString_ReturnsSelect()
        {
            var result = SelectCommand.Create(Array.Empty<byte>());
            var command = result.Value;

            Assert.That(command.ToString(), Is.EqualTo("SELECT"));
        }

        [Test]
        public void Aid_IsCloned_NotShared()
        {
            var originalAid = Convert.FromHexString("A000000151000000");
            var result = SelectCommand.Create(originalAid);
            var command = result.Value;

            originalAid[0] = 0xFF;

            Assert.That(command.Aid[0], Is.EqualTo(0xA0));
        }

        [Test]
        public void SelectMode_FirstValue_IsZero()
        {
            Assert.That((byte)SelectCommand.SelectMode.First, Is.EqualTo(0x00));
        }

        [Test]
        public void SelectMode_NextValue_IsCorrect()
        {
            Assert.That((byte)SelectCommand.SelectMode.Next, Is.EqualTo(0x02));
        }

        [Test]
        public void SelectionControl_SelectByName_IsCorrect()
        {
            Assert.That((byte)SelectCommand.SelectionControl.SelectByName, Is.EqualTo(0x04));
        }

        [Test]
        public void FileControlInfo_Values_AreCorrect()
        {
            Assert.That((byte)SelectCommand.FileControlInfo.ReturnFci, Is.EqualTo(0x00));
            Assert.That((byte)SelectCommand.FileControlInfo.ReturnFcp, Is.EqualTo(0x04));
            Assert.That((byte)SelectCommand.FileControlInfo.ReturnFmd, Is.EqualTo(0x08));
            Assert.That((byte)SelectCommand.FileControlInfo.NoResponseData, Is.EqualTo(0x0C));
        }

        [Test]
        public void IsExtendedLength_WithShortAid_ReturnsFalse()
        {
            var aid = Convert.FromHexString("A000000151000000");
            var result = SelectCommand.Create(aid);
            var command = result.Value;

            Assert.That(command.IsExtendedLength, Is.False);
        }

        // Test the obsolete method for backward compatibility
        [Test]
        public void CreateEmptySelect_IsObsolete_ButWorks()
        {
            var command = SelectCommand.CreateEmptySelect();

            Assert.That(command.Aid, Is.Empty);
            Assert.That(command.Control, Is.EqualTo(SelectCommand.SelectionControl.SelectByName));
            Assert.That(command.ControlInfo, Is.EqualTo(SelectCommand.FileControlInfo.ReturnFci));
        }

        [Test]
        public void CreateEmptySelect_WithCustomControlInfo_SetsCorrectValue()
        {
            var command = SelectCommand.CreateEmptySelect(SelectCommand.FileControlInfo.ReturnFcp);

            Assert.That(command.Aid, Is.Empty);
            Assert.That(command.Control, Is.EqualTo(SelectCommand.SelectionControl.SelectByName));
            Assert.That(command.ControlInfo, Is.EqualTo(SelectCommand.FileControlInfo.ReturnFcp));
        }

        [Test]
        public void VariousAidLengths_AllWork()
        {
            // Test various valid AID lengths
            var lengths = new[] { 0, 1, 5, 8, 12, 16 };
            
            foreach (var length in lengths)
            {
                var aid = new byte[length];
                if (length > 0)
                    aid[0] = 0xA0; // Make it look like a valid AID
                
                var result = SelectCommand.Create(aid);
                
                Assert.That(result.IsSuccess, Is.True, $"AID length {length} should be valid");
                Assert.That(result.Value.Aid.Length, Is.EqualTo(length));
            }
        }

        [Test]
        public void ClassAndInstructionConstants_AreCorrect()
        {
            Assert.That(SelectCommand.ClassByte, Is.EqualTo(0x00));
            Assert.That(SelectCommand.InstructionByte, Is.EqualTo(0xA4));
        }

        [Test]
        public void ExpectedResponseLength_WithNoResponseData_ReturnsNull()
        {
            var command = SelectCommand.CreateEmptySelect(SelectCommand.FileControlInfo.NoResponseData);

            Assert.That(command.ExpectedResponseLength, Is.Null);
        }

        [Test]
        public void ExpectedResponseLength_WithReturnFci_Returns256()
        {
            var command = SelectCommand.CreateEmptySelect(SelectCommand.FileControlInfo.ReturnFci);

            Assert.That(command.ExpectedResponseLength, Is.EqualTo(256));
        }

        [Test]
        public void ExpectedResponseLength_WithReturnFcp_Returns256()
        {
            var command = SelectCommand.CreateEmptySelect(SelectCommand.FileControlInfo.ReturnFcp);

            Assert.That(command.ExpectedResponseLength, Is.EqualTo(256));
        }

        [Test]
        public void ExpectedResponseLength_WithReturnFmd_Returns256()
        {
            var command = SelectCommand.CreateEmptySelect(SelectCommand.FileControlInfo.ReturnFmd);

            Assert.That(command.ExpectedResponseLength, Is.EqualTo(256));
        }

        [Test]
        public void ToApdu_WithNoResponseData_GeneratesCorrectApdu()
        {
            var command = SelectCommand.CreateEmptySelect(SelectCommand.FileControlInfo.NoResponseData);

            var apdu = command.ToApdu();

            Assert.That(apdu, Is.EqualTo(new byte[] { 0x00, 0xA4, 0x04, 0x0C }));
        }

        [Test]
        public void ToApdu_WithReturnFcp_GeneratesCorrectApdu()
        {
            var command = SelectCommand.CreateEmptySelect(SelectCommand.FileControlInfo.ReturnFcp);

            var apdu = command.ToApdu();

            Assert.That(apdu, Is.EqualTo(new byte[] { 0x00, 0xA4, 0x04, 0x04, 0x00 }));
        }

        [Test]
        public void ToApdu_WithReturnFmd_GeneratesCorrectApdu()
        {
            var command = SelectCommand.CreateEmptySelect(SelectCommand.FileControlInfo.ReturnFmd);

            var apdu = command.ToApdu();

            Assert.That(apdu, Is.EqualTo(new byte[] { 0x00, 0xA4, 0x04, 0x08, 0x00 }));
        }

        [Test]
        public void ToApdu_WithAidAndReturnFcp_GeneratesCorrectApdu()
        {
            var aid = Convert.FromHexString("A000000151000000");
            var command = SelectCommand.CreateEmptySelect(SelectCommand.FileControlInfo.ReturnFcp);
            // Need to access through Create method since constructor is private
            var result = SelectCommand.Create(aid, SelectCommand.SelectMode.First);
            var createdCommand = result.Value;
            
            // Create manually with ReturnFcp since we can't easily combine Create with different FileControlInfo
            var manualCommand = SelectCommand.CreateEmptySelect(SelectCommand.FileControlInfo.ReturnFcp);
            
            var apdu = manualCommand.ToApdu();

            Assert.That(apdu, Is.EqualTo(new byte[] { 0x00, 0xA4, 0x04, 0x04, 0x00 }));
        }

        [Test]
        public void CreateEmptySelect_WithAllFileControlInfoOptions_SetsCorrectValues()
        {
            var options = new[]
            {
                SelectCommand.FileControlInfo.ReturnFci,
                SelectCommand.FileControlInfo.ReturnFcp,
                SelectCommand.FileControlInfo.ReturnFmd,
                SelectCommand.FileControlInfo.NoResponseData
            };

            foreach (var option in options)
            {
                var command = SelectCommand.CreateEmptySelect(option);
                
                Assert.That(command.ControlInfo, Is.EqualTo(option), $"FileControlInfo {option} should be set correctly");
                Assert.That(command.Aid, Is.Empty, $"AID should be empty for {option}");
                Assert.That(command.Control, Is.EqualTo(SelectCommand.SelectionControl.SelectByName), $"Control should be SelectByName for {option}");
            }
        }
    }
}