using System;
using Gp4Net.Domain.Commands;
using Gp4Net.Utils;

namespace Gp4Net.Tests.Domain.Commands
{
    /// <summary>
    /// Tests for the GetStatusCommand class.
    /// </summary>
    [TestFixture]
    public class GetStatusCommandTests
    {
        #region Constructor Tests

        [Test]
        public void Constructor_ValidParameters_CreatesInstance()
        {
            // Act
            var command = new GetStatusCommand(
                GetStatusCommand.StatusSubset.IssuerSecurityDomain,
                GetStatusCommand.ResponseFormat.Tlv);

            // Assert
            Assert.That(command.Subset, Is.EqualTo(GetStatusCommand.StatusSubset.IssuerSecurityDomain));
            Assert.That(command.Format, Is.EqualTo(GetStatusCommand.ResponseFormat.Tlv));
            Assert.That(command.SearchCriteria, Is.Null);
        }

        [Test]
        public void Constructor_WithSearchCriteria_CreatesInstance()
        {
            // Arrange
            var searchCriteria = ConvertCompat.FromHexString("A000000003000000");

            // Act
            var command = new GetStatusCommand(
                GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
                GetStatusCommand.ResponseFormat.None,
                searchCriteria);

            // Assert
            Assert.That(command.SearchCriteria, Is.EqualTo(searchCriteria));
        }

        [Test]
        public void Constructor_SearchCriteriaTooShort_ThrowsArgumentException()
        {
            // Arrange
            var shortCriteria = new byte[4];

            // Act & Assert
            var ex = Assert.Throws<ArgumentException>(() =>
                new GetStatusCommand(GetStatusCommand.StatusSubset.IssuerSecurityDomain, searchCriteria: shortCriteria));
            Assert.That(ex.ParamName, Is.EqualTo("searchCriteria"));
        }

        [Test]
        public void Constructor_SearchCriteriaTooLong_ThrowsArgumentException()
        {
            // Arrange
            var longCriteria = new byte[17];

            // Act & Assert
            var ex = Assert.Throws<ArgumentException>(() =>
                new GetStatusCommand(GetStatusCommand.StatusSubset.IssuerSecurityDomain, searchCriteria: longCriteria));
            Assert.That(ex.ParamName, Is.EqualTo("searchCriteria"));
        }

        #endregion

        #region ToApdu Tests

        [Test]
        public void ToApdu_NoSearchCriteria_ReturnsCorrectApdu()
        {
            // Arrange
            var command = new GetStatusCommand(
                GetStatusCommand.StatusSubset.ExecutableLoadFiles,
                GetStatusCommand.ResponseFormat.Tlv);

            // Act
            var apdu = command.ToApdu();

            // Assert
            var expected = new byte[] { 0x80, 0xF2, 0x20, 0x02, 0x00 };
            Assert.That(apdu, Is.EqualTo(expected));
        }

        [Test]
        public void ToApdu_WithSearchCriteria_ReturnsCorrectApdu()
        {
            // Arrange
            var searchCriteria = ConvertCompat.FromHexString("A000000003000000");
            var command = new GetStatusCommand(
                GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
                GetStatusCommand.ResponseFormat.None,
                searchCriteria);

            // Act
            var apdu = command.ToApdu();

            // Assert
            var expected = new byte[] { 0x80, 0xF2, 0x40, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00 };
            Assert.That(apdu, Is.EqualTo(expected));
        }

        #endregion

        #region ApplicationStatusEntry Tests

        [Test]
        public void ApplicationStatusEntry_Constructor_CreatesInstance()
        {
            // Arrange
            var aid = ConvertCompat.FromHexString("A000000003000000");
            var privileges = new byte[] { 0x00, 0x00, 0x00 };

            // Act
            var entry = new ApplicationStatusEntry(aid, ApplicationStatusEntry.LifecycleState.Selectable, privileges);

            // Assert
            Assert.That(entry.Aid, Is.EqualTo(aid));
            Assert.That(entry.State, Is.EqualTo(ApplicationStatusEntry.LifecycleState.Selectable));
            Assert.That(entry.Privileges, Is.EqualTo(privileges));
        }

        #endregion

        #region GetStatusResponse Tests

        [Test]
        public void GetStatusResponse_Parse_EmptyResponse_ReturnsEmptyList()
        {
            // Act
            var response = GetStatusResponse.Parse(Array.Empty<byte>());

            // Assert
            Assert.That(response.Applications, Is.Not.Null);
            Assert.That(response.Applications.Count, Is.EqualTo(0));
        }

        [Test]
        public void GetStatusResponse_Parse_ValidResponse_ParsesApplications()
        {
            // Arrange
            var responseData = new byte[]
            {
                0x08, // AID length
                0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, // AID
                0x07, // Lifecycle state (Selectable)
                0x03, // Privileges length
                0x00, 0x00, 0x00 // Privileges
            };

            // Act
            var response = GetStatusResponse.Parse(responseData);

            // Assert
            Assert.That(response.Applications.Count, Is.EqualTo(1));
            var app = response.Applications[0];
            Assert.That(app.Aid, Is.EqualTo(ConvertCompat.FromHexString("A000000003000000")));
            Assert.That(app.State, Is.EqualTo(ApplicationStatusEntry.LifecycleState.Selectable));
            Assert.That(app.Privileges, Is.EqualTo(new byte[] { 0x00, 0x00, 0x00 }));
        }

        [Test]
        public void GetStatusResponse_Parse_MultipleApplications_ParsesAll()
        {
            // Arrange
            var responseData = new byte[]
            {
                0x08, // First AID length
                0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, // First AID
                0x07, // First lifecycle state
                0x03, // First privileges length
                0x00, 0x00, 0x00, // First privileges
                
                0x05, // Second AID length
                0xA0, 0x00, 0x00, 0x00, 0x04, // Second AID
                0x0F, // Second lifecycle state (Personalized)
                0x01, // Second privileges length
                0x80 // Second privileges
            };

            // Act
            var response = GetStatusResponse.Parse(responseData);

            // Assert
            Assert.That(response.Applications.Count, Is.EqualTo(2));
            
            var firstApp = response.Applications[0];
            Assert.That(firstApp.Aid, Is.EqualTo(ConvertCompat.FromHexString("A000000003000000")));
            Assert.That(firstApp.State, Is.EqualTo(ApplicationStatusEntry.LifecycleState.Selectable));
            
            var secondApp = response.Applications[1];
            Assert.That(secondApp.Aid, Is.EqualTo(ConvertCompat.FromHexString("A000000004")));
            Assert.That(secondApp.State, Is.EqualTo(ApplicationStatusEntry.LifecycleState.Personalized));
        }

        [Test]
        public void GetStatusResponse_Parse_NullResponse_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => GetStatusResponse.Parse(null));
        }

        [Test]
        public void GetStatusResponse_Parse_TruncatedResponse_StopsAtIncompleteEntry()
        {
            // Arrange
            var responseData = new byte[]
            {
                0x08, // AID length
                0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, // AID
                0x07, // Lifecycle state
                0x03, // Privileges length
                0x00, 0x00, 0x00, // Privileges
                
                0x05, // Second AID length (but incomplete data follows)
                0xA0, 0x00 // Incomplete second AID
            };

            // Act
            var response = GetStatusResponse.Parse(responseData);

            // Assert
            Assert.That(response.Applications.Count, Is.EqualTo(1));
        }

        #endregion
    }
}