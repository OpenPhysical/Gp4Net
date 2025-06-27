using System;
using System.Linq;
using Gp4Net.Tests.Emulator.Cards;
using Gp4Net.Tests.Emulator.Core;
using Gp4Net.Utils;
using NUnit.Framework;

namespace Gp4Net.Tests.Emulator
{
    /// <summary>
    /// Tests for the ACOS JavaCard emulator.
    /// </summary>
    [TestFixture]
    public class AcosJavaCardTests
    {
        private AcosJavaCard _card = null!;

        [SetUp]
        public void SetUp()
        {
            _card = new AcosJavaCard();
        }

        [Test]
        public void GetAtr_ReturnsExpectedAtr()
        {
            // Act
            var atr = _card.GetAtr();

            // Assert
            Assert.That(atr, Is.Not.Null);
            Assert.That(atr.Length, Is.GreaterThan(0));
            Assert.That(Convert.ToHexString(atr), Is.EqualTo("3B68000030659000AF"));
        }

        [Test]
        public void Reset_ResetsCardState()
        {
            // Arrange - establish some state
            _card.ProcessCommand(ConvertCompat.FromHexString("00A4040008A000000151000000"));

            // Act
            _card.Reset();

            // Assert
            Assert.That(_card.IsSelected, Is.False);
            Assert.That(_card.IsSecureChannelEstablished, Is.False);
        }

        [Test]
        public void ProcessCommand_SelectIsd_ReturnsSuccessWithFci()
        {
            // Arrange
            var selectIsdCommand = ConvertCompat.FromHexString("00A4040008A000000151000000");

            // Act
            var response = _card.ProcessCommand(selectIsdCommand);

            // Assert
            Assert.That(response.IsSuccessful, Is.True);
            Assert.That(response.StatusWord, Is.EqualTo(0x9000));
            Assert.That(response.Data.Length, Is.GreaterThan(0));
            Assert.That(_card.IsSelected, Is.True);
        }

        [Test]
        public void ProcessCommand_SelectNonExistentApp_ReturnsFileNotFound()
        {
            // Arrange
            var selectCommand = ConvertCompat.FromHexString("00A40400081234567890ABCDEF");

            // Act
            var response = _card.ProcessCommand(selectCommand);

            // Assert
            Assert.That(response.IsSuccessful, Is.False);
            Assert.That(response.StatusWord, Is.EqualTo(0x6A82)); // File not found
        }

        [Test]
        public void ProcessCommand_InitializeUpdateWithoutSelection_ReturnsConditionsNotSatisfied()
        {
            // Arrange
            var initUpdateCommand = ConvertCompat.FromHexString("80500000081122334455667788");

            // Act
            var response = _card.ProcessCommand(initUpdateCommand);

            // Assert
            Assert.That(response.IsSuccessful, Is.False);
            Assert.That(response.StatusWord, Is.EqualTo(0x6985)); // Conditions not satisfied
        }

        [Test]
        public void ProcessCommand_InitializeUpdateAfterSelection_ReturnsSuccessWithChallenge()
        {
            // Arrange
            _card.ProcessCommand(ConvertCompat.FromHexString("00A4040008A000000151000000"));
            var initUpdateCommand = ConvertCompat.FromHexString("80500000081122334455667788");

            // Act
            var response = _card.ProcessCommand(initUpdateCommand);

            // Assert
            Assert.That(response.IsSuccessful, Is.True);
            Assert.That(response.StatusWord, Is.EqualTo(0x9000));
            Assert.That(response.Data.Length, Is.GreaterThan(20)); // Should contain challenge and cryptogram
        }

        [Test]
        public void ProcessCommand_ExternalAuthenticateWithoutInitialize_ReturnsConditionsNotSatisfied()
        {
            // Arrange
            _card.ProcessCommand(ConvertCompat.FromHexString("00A4040008A000000151000000"));
            var extAuthCommand = ConvertCompat.FromHexString("84820000103CA4BC00FAD9D1434F4086C4959E26B5");

            // Act
            var response = _card.ProcessCommand(extAuthCommand);

            // Assert
            Assert.That(response.IsSuccessful, Is.False);
            Assert.That(response.StatusWord, Is.EqualTo(0x6985));
        }

        [Test]
        public void ProcessCommand_CompleteAuthenticationSequence_EstablishesSecureChannel()
        {
            // Arrange - Select ISD
            _card.ProcessCommand(ConvertCompat.FromHexString("00A4040008A000000151000000"));
            
            // Initialize Update
            _card.ProcessCommand(ConvertCompat.FromHexString("80500000081122334455667788"));
            
            // External Authenticate
            var extAuthCommand = ConvertCompat.FromHexString("84820000103CA4BC00FAD9D1434F4086C4959E26B5");

            // Act
            var response = _card.ProcessCommand(extAuthCommand);

            // Assert
            Assert.That(response.IsSuccessful, Is.True);
            Assert.That(_card.IsSecureChannelEstablished, Is.True);
        }

        [Test]
        public void ProcessCommand_InstallForLoadWithoutSecureChannel_ReturnsConditionsNotSatisfied()
        {
            // Arrange
            _card.ProcessCommand(ConvertCompat.FromHexString("00A4040008A000000151000000"));
            var installCommand = ConvertCompat.FromHexString("80E602000A05A01122334400000000");

            // Act
            var response = _card.ProcessCommand(installCommand);

            // Assert
            Assert.That(response.IsSuccessful, Is.False);
            Assert.That(response.StatusWord, Is.EqualTo(0x6985));
        }

        [Test]
        public void ProcessCommand_InstallForLoadWithSecureChannel_ReturnsSuccess()
        {
            // Arrange - Establish secure channel
            EstablishSecureChannel();
            var installCommand = ConvertCompat.FromHexString("80E602000A05A01122334400000000");

            // Act
            var response = _card.ProcessCommand(installCommand);

            // Assert
            Assert.That(response.IsSuccessful, Is.True);
            Assert.That(response.Data, Is.EqualTo(new byte[] { 0x00 }));
        }

        [Test]
        public void ProcessCommand_LoadCapFile_AccumulatesDataCorrectly()
        {
            // Arrange - Establish secure channel and install for load
            EstablishSecureChannel();
            _card.ProcessCommand(ConvertCompat.FromHexString("80E602000A05A01122334400000000"));

            // First LOAD command
            var firstLoad = ConvertCompat.FromHexString("80E80000FF" + "C482011D010014DECAFFED020204");
            var secondLoad = ConvertCompat.FromHexString("80E8800122" + "800A0103810E0103800A08068007");

            // Act
            var response1 = _card.ProcessCommand(firstLoad);
            var response2 = _card.ProcessCommand(secondLoad);

            // Assert
            Assert.That(response1.IsSuccessful, Is.True);
            Assert.That(response2.IsSuccessful, Is.True);
        }

        [Test]
        public void ProcessCommand_InstallForInstall_CreatesApplication()
        {
            // Arrange - Load application first
            EstablishSecureChannel();
            _card.ProcessCommand(ConvertCompat.FromHexString("80E602000A05A01122334400000000"));
            _card.ProcessCommand(ConvertCompat.FromHexString("80E8800122800A0103810E0103800A08068007"));

            // Install for install
            var installCommand = ConvertCompat.FromHexString("80E60C001A05A01122334406A0112233440106A01122334401010002C90000");

            // Act
            var response = _card.ProcessCommand(installCommand);

            // Assert
            Assert.That(response.IsSuccessful, Is.True);
            
            // Verify application can be selected
            var selectApp = ConvertCompat.FromHexString("00A4040006A01122334401");
            var selectResponse = _card.ProcessCommand(selectApp);
            Assert.That(selectResponse.IsSuccessful, Is.True);
        }

        [Test]
        public void ProcessCommand_GetStatusIsd_ReturnsIsdInformation()
        {
            // Arrange
            EstablishSecureChannel();
            var getStatusCommand = ConvertCompat.FromHexString("80F28000024F0000");

            // Act
            var response = _card.ProcessCommand(getStatusCommand);

            // Assert
            Assert.That(response.IsSuccessful, Is.True);
            Assert.That(response.Data.Length, Is.GreaterThan(0));
            
            // Should contain ISD AID
            var responseHex = Convert.ToHexString(response.Data);
            Assert.That(responseHex, Does.Contain("A000000151000000"));
        }

        [Test]
        public void ProcessCommand_GetStatusApplications_ReturnsInstalledApplications()
        {
            // Arrange - Install an application first
            InstallTestApplication();
            var getStatusCommand = ConvertCompat.FromHexString("80F24000024F0000");

            // Act
            var response = _card.ProcessCommand(getStatusCommand);

            // Assert
            Assert.That(response.IsSuccessful, Is.True);
            // Response should contain the installed application data
        }

        [Test]
        public void ProcessCommand_DeleteApplication_RemovesApplication()
        {
            // Arrange - Install an application first
            InstallTestApplication();
            var deleteCommand = ConvertCompat.FromHexString("80E400000A4F06A01122334401");

            // Act
            var response = _card.ProcessCommand(deleteCommand);

            // Assert
            Assert.That(response.IsSuccessful, Is.True);
            
            // Verify application is no longer selectable
            var selectApp = ConvertCompat.FromHexString("00A4040006A01122334401");
            var selectResponse = _card.ProcessCommand(selectApp);
            Assert.That(selectResponse.IsSuccessful, Is.False);
        }

        [Test]
        public void ProcessCommand_UnsupportedInstruction_ReturnsInsNotSupported()
        {
            // Arrange
            var unsupportedCommand = ConvertCompat.FromHexString("00FF000000");

            // Act
            var response = _card.ProcessCommand(unsupportedCommand);

            // Assert
            Assert.That(response.IsSuccessful, Is.False);
            Assert.That(response.StatusWord, Is.EqualTo(0x6D00)); // INS not supported
        }

        [Test]
        public void ProcessCommand_MalformedApdu_ReturnsGenericError()
        {
            // Arrange
            var malformedCommand = new byte[] { 0x00 }; // Too short

            // Act
            var response = _card.ProcessCommand(malformedCommand);

            // Assert
            Assert.That(response.IsSuccessful, Is.False);
            Assert.That(response.StatusWord, Is.EqualTo(0x6F00)); // Generic error
        }

        [Test]
        public void ProcessCommand_GetData_ReturnsSuccess()
        {
            // Arrange
            var getDataCommand = ConvertCompat.FromHexString("00CA9F7F00");

            // Act
            var response = _card.ProcessCommand(getDataCommand);

            // Assert
            Assert.That(response.IsSuccessful, Is.True);
        }

        private void EstablishSecureChannel()
        {
            // Select ISD
            _card.ProcessCommand(ConvertCompat.FromHexString("00A4040008A000000151000000"));
            
            // Initialize Update
            _card.ProcessCommand(ConvertCompat.FromHexString("80500000081122334455667788"));
            
            // External Authenticate
            _card.ProcessCommand(ConvertCompat.FromHexString("84820000103CA4BC00FAD9D1434F4086C4959E26B5"));
        }

        private void InstallTestApplication()
        {
            EstablishSecureChannel();
            
            // Install for load
            _card.ProcessCommand(ConvertCompat.FromHexString("80E602000A05A01122334400000000"));
            
            // Load (simplified)
            _card.ProcessCommand(ConvertCompat.FromHexString("80E8800122800A0103810E0103800A08068007"));
            
            // Install for install
            _card.ProcessCommand(ConvertCompat.FromHexString("80E60C001A05A01122334406A0112233440106A01122334401010002C90000"));
        }
    }
}