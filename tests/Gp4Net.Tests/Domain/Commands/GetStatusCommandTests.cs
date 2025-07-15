using System;
using System.Collections.Generic;
using System.Linq;
using Gp4Net.Domain.Commands;
using Gp4Net.Transport;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands
{
    [TestFixture]
    public class GetStatusCommandTests
    {
        #region Command Creation Tests

        [Test]
        [TestCase(GetStatusCommand.StatusSubset.IssuerSecurityDomain)]
        [TestCase(GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains)]
        [TestCase(GetStatusCommand.StatusSubset.ExecutableLoadFiles)]
        [TestCase(GetStatusCommand.StatusSubset.ExecutableLoadFilesAndModules)]
        public void Create_WithValidStatusSubset_ReturnsSuccessResult(GetStatusCommand.StatusSubset subset)
        {
            var result = GetStatusCommand.Create(subset);

            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.Subset, Is.EqualTo(subset));
            Assert.That(result.Value.Format, Is.EqualTo(GetStatusCommand.ResponseFormat.None));
            Assert.That(result.Value.SearchCriteria, Is.Null);
        }

        [Test]
        [TestCase(GetStatusCommand.ResponseFormat.None)]
        [TestCase(GetStatusCommand.ResponseFormat.Tlv)]
        public void Create_WithValidResponseFormat_ReturnsSuccessResult(GetStatusCommand.ResponseFormat format)
        {
            var result = GetStatusCommand.Create(
                GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
                format
            );

            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.Format, Is.EqualTo(format));
        }

        [Test]
        public void Create_WithValidSearchCriteria_ReturnsSuccessResult()
        {
            var aid = Convert.FromHexString("A0000000031010");

            var result = GetStatusCommand.Create(
                GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
                GetStatusCommand.ResponseFormat.None,
                aid
            );

            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.SearchCriteria, Is.EqualTo(aid));
        }

        [Test]
        [TestCase(4)]  // Too short
        [TestCase(17)] // Too long
        public void Create_WithInvalidSearchCriteriaLength_ReturnsFailureResult(int length)
        {
            var aid = new byte[length];

            var result = GetStatusCommand.Create(
                GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
                GetStatusCommand.ResponseFormat.None,
                aid
            );

            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Message, Does.Contain("Search criteria AID must be between 5 and 16 bytes"));
        }

        [Test]
        [TestCase(5)]  // Minimum valid length
        [TestCase(10)] // Mid-range
        [TestCase(16)] // Maximum valid length
        public void Create_WithValidSearchCriteriaLengths_ReturnsSuccessResult(int length)
        {
            var aid = new byte[length];

            var result = GetStatusCommand.Create(
                GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
                GetStatusCommand.ResponseFormat.None,
                aid
            );

            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.SearchCriteria!.Length, Is.EqualTo(length));
        }

        [Test]
        public void Create_WithInvalidStatusSubset_ReturnsFailureResult()
        {
            var invalidSubset = (GetStatusCommand.StatusSubset)0xFF;

            var result = GetStatusCommand.Create(invalidSubset);

            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Message, Does.Contain("Invalid status subset"));
        }

        [Test]
        public void Create_WithInvalidResponseFormat_ReturnsFailureResult()
        {
            var invalidFormat = (GetStatusCommand.ResponseFormat)0xFF;

            var result = GetStatusCommand.Create(
                GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
                invalidFormat
            );

            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Message, Does.Contain("Invalid response format"));
        }

        [Test]
        public void SearchCriteria_IsImmutable()
        {
            var originalAid = Convert.FromHexString("A0000000031010");
            var result = GetStatusCommand.Create(
                GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
                GetStatusCommand.ResponseFormat.None,
                originalAid
            );
            var command = result.Value;

            originalAid[0] = 0xFF;

            Assert.That(command.SearchCriteria![0], Is.EqualTo(0xA0));
        }

        #endregion

        #region APDU Construction Tests

        [Test]
        public void ToApdu_WithoutSearchCriteria_ReturnsCase2Apdu()
        {
            var result = GetStatusCommand.Create(
                GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
                GetStatusCommand.ResponseFormat.None
            );
            var command = result.Value;

            var apdu = command.ToApdu();

            Assert.That(apdu.Length, Is.EqualTo(5)); // CLA INS P1 P2 Le
            Assert.That(apdu[0], Is.EqualTo(0x80)); // CLA
            Assert.That(apdu[1], Is.EqualTo(0xF2)); // INS
            Assert.That(apdu[2], Is.EqualTo(0x40)); // P1 - Applications subset
            Assert.That(apdu[3], Is.EqualTo(0x00)); // P2 - No format
            Assert.That(apdu[4], Is.EqualTo(0x00)); // Le
        }

        [Test]
        public void ToApdu_WithSearchCriteria_ReturnsCase4Apdu()
        {
            var aid = Convert.FromHexString("A0000000031010");
            var result = GetStatusCommand.Create(
                GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
                GetStatusCommand.ResponseFormat.None,
                aid
            );
            var command = result.Value;

            var apdu = command.ToApdu();

            Assert.That(apdu.Length, Is.EqualTo(5 + aid.Length + 1)); // CLA INS P1 P2 Lc Data Le
            Assert.That(apdu[0], Is.EqualTo(0x80)); // CLA
            Assert.That(apdu[1], Is.EqualTo(0xF2)); // INS
            Assert.That(apdu[2], Is.EqualTo(0x40)); // P1
            Assert.That(apdu[3], Is.EqualTo(0x00)); // P2
            Assert.That(apdu[4], Is.EqualTo((byte)aid.Length)); // Lc
            Assert.That(apdu[5..(5 + aid.Length)], Is.EqualTo(aid)); // Data
            Assert.That(apdu[5 + aid.Length], Is.EqualTo(0x00)); // Le
        }

        [Test]
        [TestCase(GetStatusCommand.StatusSubset.IssuerSecurityDomain, 0x80)]
        [TestCase(GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains, 0x40)]
        [TestCase(GetStatusCommand.StatusSubset.ExecutableLoadFiles, 0x20)]
        [TestCase(GetStatusCommand.StatusSubset.ExecutableLoadFilesAndModules, 0x10)]
        public void ToApdu_WithDifferentSubsets_SetsP1Correctly(GetStatusCommand.StatusSubset subset, byte expectedP1)
        {
            var result = GetStatusCommand.Create(subset);
            var command = result.Value;

            var apdu = command.ToApdu();

            Assert.That(apdu[2], Is.EqualTo(expectedP1));
        }

        [Test]
        [TestCase(GetStatusCommand.ResponseFormat.None, 0x00)]
        [TestCase(GetStatusCommand.ResponseFormat.Tlv, 0x02)]
        public void ToApdu_WithDifferentFormats_SetsP2Correctly(GetStatusCommand.ResponseFormat format, byte expectedP2)
        {
            var result = GetStatusCommand.Create(
                GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
                format
            );
            var command = result.Value;

            var apdu = command.ToApdu();

            Assert.That(apdu[3], Is.EqualTo(expectedP2));
        }

        [Test]
        public void ToApdu_AlwaysReturnsNewArray()
        {
            var result = GetStatusCommand.Create(GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains);
            var command = result.Value;

            var apdu1 = command.ToApdu();
            var apdu2 = command.ToApdu();

            Assert.That(apdu1, Is.Not.SameAs(apdu2));
            Assert.That(apdu2, Is.EqualTo(apdu1));
        }

        #endregion

        #region Interface Implementation Tests

        [Test]
        public void IApduCommand_Properties_ReturnCorrectValues()
        {
            var result = GetStatusCommand.Create(
                GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
                GetStatusCommand.ResponseFormat.Tlv
            );
            var command = result.Value;
            var iApduCommand = (IApduCommand)command;

            Assert.That(iApduCommand.Cla, Is.EqualTo(0x80));
            Assert.That(iApduCommand.Ins, Is.EqualTo(0xF2));
            Assert.That(command.P1, Is.EqualTo(0x40));
            Assert.That(command.P2, Is.EqualTo(0x02));
            Assert.That(command.Data, Is.Null);
            Assert.That(command.ExpectedResponseLength, Is.EqualTo(256));
            Assert.That(command.IsExtendedLength, Is.False);
        }

        [Test]
        public void IApduCommand_WithSearchCriteria_ReturnsCorrectData()
        {
            var aid = Convert.FromHexString("A0000000031010");
            var result = GetStatusCommand.Create(
                GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
                GetStatusCommand.ResponseFormat.None,
                aid
            );
            var command = result.Value;

            Assert.That(command.Data, Is.EqualTo(aid));
        }

        #endregion

        #region Response Parsing Tests

        [Test]
        public void GetStatusResponse_Parse_WithValidSingleEntry_ReturnsSuccess()
        {
            var response = Convert.FromHexString(
                "07" +               // AID length
                "A0000000031010" +   // AID
                "07" +               // Lifecycle state (Selectable)
                "01" +               // Privileges length
                "80"                 // Privileges
            );

            var result = GetStatusResponse.Parse(response);

            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.Applications.Count, Is.EqualTo(1));

            var app = result.Value.Applications[0];
            Assert.That(app.Aid, Is.EqualTo(Convert.FromHexString("A0000000031010")));
            Assert.That(app.State, Is.EqualTo(ApplicationStatusEntry.LifecycleState.Selectable));
            Assert.That(app.Privileges, Is.EqualTo(new byte[] { 0x80 }));
        }

        [Test]
        public void GetStatusResponse_Parse_WithMultipleEntries_ReturnsSuccess()
        {
            var response = Convert.FromHexString(
                "07" + "A0000000031010" + "07" + "01" + "80" +  // First app
                "08" + "A000000003101001" + "0F" + "02" + "C040" // Second app
            );

            var result = GetStatusResponse.Parse(response);

            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.Applications.Count, Is.EqualTo(2));

            var app1 = result.Value.Applications[0];
            Assert.That(app1.Aid, Is.EqualTo(Convert.FromHexString("A0000000031010")));
            Assert.That(app1.State, Is.EqualTo(ApplicationStatusEntry.LifecycleState.Selectable));

            var app2 = result.Value.Applications[1];
            Assert.That(app2.Aid, Is.EqualTo(Convert.FromHexString("A000000003101001")));
            Assert.That(app2.State, Is.EqualTo(ApplicationStatusEntry.LifecycleState.Personalized));
            Assert.That(app2.Privileges, Is.EqualTo(Convert.FromHexString("C040")));
        }

        [Test]
        [TestCase(0x03, ApplicationStatusEntry.LifecycleState.Installed)]
        [TestCase(0x07, ApplicationStatusEntry.LifecycleState.Selectable)]
        [TestCase(0x0F, ApplicationStatusEntry.LifecycleState.Personalized)]
        [TestCase(0x83, ApplicationStatusEntry.LifecycleState.Blocked)]
        [TestCase(0x87, ApplicationStatusEntry.LifecycleState.Locked)]
        public void GetStatusResponse_Parse_WithDifferentLifecycleStates_ParsesCorrectly(
            byte stateValue,
            ApplicationStatusEntry.LifecycleState expectedState)
        {
            var response = new List<byte>();
            response.Add(0x07); // AID length
            response.AddRange(Convert.FromHexString("A0000000031010")); // AID
            response.Add(stateValue); // Lifecycle state
            response.Add(0x00); // No privileges

            var result = GetStatusResponse.Parse(response.ToArray());

            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.Applications[0].State, Is.EqualTo(expectedState));
        }

        [Test]
        public void GetStatusResponse_Parse_WithInvalidLifecycleState_ReturnsFailure()
        {
            var response = Convert.FromHexString(
                "07" +               // AID length
                "A0000000031010" +   // AID
                "FF" +               // Invalid lifecycle state
                "01" +               // Privileges length
                "80"                 // Privileges
            );

            var result = GetStatusResponse.Parse(response);

            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Message, Does.Contain("Invalid lifecycle state: 0xFF"));
        }

        [Test]
        public void GetStatusResponse_Parse_WithEmptyResponse_ReturnsEmptyList()
        {
            var response = new byte[0];

            var result = GetStatusResponse.Parse(response);

            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.Applications.Count, Is.EqualTo(0));
        }

        [Test]
        public void GetStatusResponse_Parse_WithNullResponse_ReturnsFailure()
        {
            var result = GetStatusResponse.Parse(null);

            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Message, Does.Contain("Response data cannot be null"));
        }

        [Test]
        public void GetStatusResponse_Parse_WithTruncatedData_StopsGracefully()
        {
            var response = Convert.FromHexString(
                "07" +               // AID length
                "A0000000031010" +   // AID
                "07"                 // Lifecycle state - missing privileges
            );

            var result = GetStatusResponse.Parse(response);

            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.Applications.Count, Is.EqualTo(0));
        }

        [Test]
        public void GetStatusResponse_Parse_WithZeroLengthAid_StopsGracefully()
        {
            var response = new byte[] { 0x00 }; // Zero AID length

            var result = GetStatusResponse.Parse(response);

            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.Applications.Count, Is.EqualTo(0));
        }

        [Test]
        public void GetStatusResponse_Parse_WithNoPrivileges_ParsesCorrectly()
        {
            var response = Convert.FromHexString(
                "07" +               // AID length
                "A0000000031010" +   // AID
                "07" +               // Lifecycle state
                "00"                 // No privileges
            );

            var result = GetStatusResponse.Parse(response);

            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.Applications.Count, Is.EqualTo(1));
            Assert.That(result.Value.Applications[0].Privileges, Is.Empty);
        }

        #endregion

        #region ApplicationStatusEntry Tests

        [Test]
        public void ApplicationStatusEntry_Constructor_CreatesImmutableCopies()
        {
            var originalAid = Convert.FromHexString("A0000000031010");
            var originalPrivileges = new byte[] { 0x80, 0x40 };

            var entry = new ApplicationStatusEntry(
                originalAid,
                ApplicationStatusEntry.LifecycleState.Selectable,
                originalPrivileges
            );

            originalAid[0] = 0xFF;
            originalPrivileges[0] = 0xFF;

            Assert.That(entry.Aid[0], Is.EqualTo(0xA0));
            Assert.That(entry.Privileges[0], Is.EqualTo(0x80));
        }

        #endregion

        #region Miscellaneous Tests

        [Test]
        public void ToString_ReturnsDescriptiveString()
        {
            var result = GetStatusCommand.Create(GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains);
            var command = result.Value;

            var str = command.ToString();

            Assert.That(str, Is.EqualTo("GET STATUS"));
        }

        [Test]
        public void Constants_HaveCorrectValues()
        {
            Assert.That(GetStatusCommand.Cla, Is.EqualTo(0x80));
            Assert.That(GetStatusCommand.Ins, Is.EqualTo(0xF2));
        }

        [Test]
        public void GetStatusResponse_Applications_ReturnsReadOnlyList()
        {
            var apps = new List<ApplicationStatusEntry>
            {
                new ApplicationStatusEntry(
                    Convert.FromHexString("A0000000031010"),
                    ApplicationStatusEntry.LifecycleState.Selectable,
                    new byte[] { 0x80 }
                )
            };

            var response = new GetStatusResponse(apps);

            Assert.That(response.Applications, Is.Not.SameAs(apps));
            Assert.That(response.Applications.Count, Is.EqualTo(1));
        }

        #endregion
    }
}