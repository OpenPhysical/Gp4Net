using System;
using System.Linq;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.CapFile;
using Gp4Net.Tests.Emulator.Services;
using Gp4Net.Utils;
using NUnit.Framework;

namespace Gp4Net.Tests.Emulator
{
    /// <summary>
    /// Integration tests demonstrating the use of the virtual card emulator
    /// with the GP4Net library commands and functionality.
    /// </summary>
    [TestFixture]
    public class IntegrationTests
    {
        private VirtualCardService _cardService = null!;

        [SetUp]
        public void SetUp()
        {
            _cardService = new VirtualCardService();
            _cardService.SetupTestEnvironment();
            _cardService.Connect("Virtual ACOS Reader 00 00");
        }

        [TearDown]
        public void TearDown()
        {
            _cardService.Dispose();
        }

        [Test]
        public void SelectCommand_SelectIsd_WorksWithVirtualCard()
        {
            // Arrange
            var isdAid = ConvertCompat.FromHexString("A000000151000000");
            var selectCommand = new SelectCommand(isdAid);

            // Act
            var response = _cardService.SendCommand(selectCommand.ToApdu());

            // Assert
            Assert.That(response.IsSuccessful, Is.True);
            
            // Parse the response
            var selectResponse = SelectResponse.Parse(response.Data);
            Assert.That(selectResponse, Is.Not.Null);
            Assert.That(selectResponse.RawData.Length, Is.GreaterThan(0));
        }

        [Test]
        public void GetStatusCommand_GetIsdStatus_ReturnsIsdInformation()
        {
            // Arrange
            EstablishSecureChannel();
            var getStatusCommand = new GetStatusCommand(GetStatusCommand.StatusSubset.IssuerSecurityDomain);

            // Act
            var response = _cardService.SendCommand(getStatusCommand.ToApdu());

            // Assert
            Assert.That(response.IsSuccessful, Is.True);
            
            // Parse the response
            var statusResponse = GetStatusResponse.Parse(response.Data);
            Assert.That(statusResponse, Is.Not.Null);
            Assert.That(statusResponse.Applications.Count, Is.GreaterThan(0));
            
            // Verify ISD is present
            var isdApp = statusResponse.Applications.FirstOrDefault(a => 
                Convert.ToHexString(a.Aid).Equals("A000000151000000", StringComparison.OrdinalIgnoreCase));
            Assert.That(isdApp, Is.Not.Null);
        }

        [Test]
        public void InstallCommand_InstallForLoad_WorksWithVirtualCard()
        {
            // Arrange
            EstablishSecureChannel();
            var packageAid = ConvertCompat.FromHexString("A011223344");
            var installCommand = InstallCommand.CreateForLoad(packageAid);

            // Act
            var response = _cardService.SendCommand(installCommand.ToApdu());

            // Assert
            Assert.That(response.IsSuccessful, Is.True);
        }

        [Test]
        public void LoadCommand_LoadCapFileData_WorksWithVirtualCard()
        {
            // Arrange
            EstablishSecureChannel();
            
            // Install for load first
            var packageAid = ConvertCompat.FromHexString("A011223344");
            var installCommand = InstallCommand.CreateForLoad(packageAid);
            _cardService.SendCommand(installCommand.ToApdu());

            // Create sample CAP data
            var capData = ConvertCompat.FromHexString("C482011D010014DECAFFED020204000105A011223344047041707002002100140021000A0015002E000E0058000A00100000006A01F400000000000002010004001502030107A0000006200101030107A000000062010203000A0106A01122334401");
            var loadCommands = LoadCommand.CreateFromCapFile(capData);

            // Act
            foreach (var loadCommand in loadCommands)
            {
                var response = _cardService.SendCommand(loadCommand.ToApdu());
                Assert.That(response.IsSuccessful, Is.True);
            }

            // Assert - All commands should succeed
            Assert.That(loadCommands.Count, Is.GreaterThan(0));
        }

        [Test]
        public void CompleteAppletInstallation_WorksEndToEnd()
        {
            // Arrange
            EstablishSecureChannel();

            var packageAid = ConvertCompat.FromHexString("A011223344");
            var moduleAid = ConvertCompat.FromHexString("A01122334401");
            var appletAid = ConvertCompat.FromHexString("A01122334401");

            // Act & Assert

            // Step 1: Install for load
            var installForLoad = InstallCommand.CreateForLoad(packageAid);
            var installResponse = _cardService.SendCommand(installForLoad.ToApdu());
            Assert.That(installResponse.IsSuccessful, Is.True);

            // Step 2: Load CAP file data
            var capData = ConvertCompat.FromHexString("C482011D010014DECAFFED020204");
            var loadCommands = LoadCommand.CreateFromCapFile(capData);
            foreach (var loadCommand in loadCommands)
            {
                var loadResponse = _cardService.SendCommand(loadCommand.ToApdu());
                Assert.That(loadResponse.IsSuccessful, Is.True);
            }

            // Step 3: Install for install
            var installForInstall = new InstallCommand(
                InstallCommand.InstallType.ForInstallAndMakeSelectable,
                packageAid,
                appletAid,
                moduleAid);
            var installAppResponse = _cardService.SendCommand(installForInstall.ToApdu());
            Assert.That(installAppResponse.IsSuccessful, Is.True);

            // Step 4: Verify application is installed by selecting it
            var selectApplet = new SelectCommand(appletAid);
            var selectResponse = _cardService.SendCommand(selectApplet.ToApdu());
            Assert.That(selectResponse.IsSuccessful, Is.True);

            // Step 5: Verify application appears in GET STATUS
            var getStatusApps = new GetStatusCommand(GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains);
            var statusResponse = _cardService.SendCommand(getStatusApps.ToApdu());
            Assert.That(statusResponse.IsSuccessful, Is.True);

            var parsedStatus = GetStatusResponse.Parse(statusResponse.Data);
            var installedApp = parsedStatus.Applications.FirstOrDefault(a => 
                Convert.ToHexString(a.Aid).Equals(Convert.ToHexString(appletAid), StringComparison.OrdinalIgnoreCase));
            Assert.That(installedApp, Is.Not.Null);
        }

        [Test]
        public void DeleteCommand_RemoveApplication_WorksWithVirtualCard()
        {
            // Arrange
            InstallTestApplication();
            var appletAid = ConvertCompat.FromHexString("A01122334401");
            var deleteCommand = DeleteCommand.CreateForApplication(appletAid);

            // Act
            var response = _cardService.SendCommand(deleteCommand.ToApdu());

            // Assert
            Assert.That(response.IsSuccessful, Is.True);
            
            // Verify application is no longer selectable
            var selectApplet = new SelectCommand(appletAid);
            var selectResponse = _cardService.SendCommand(selectApplet.ToApdu());
            Assert.That(selectResponse.IsSuccessful, Is.False);
        }

        [Test]
        public void CapFileWorkflow_ValidateAndInstall_WorksEndToEnd()
        {
            // Arrange - Create a minimal valid CAP file structure
            var capFileData = CreateMinimalCapFile();
            
            // Validate CAP file
            var validationResult = CapFileLoadingWorkflow.ValidateCapFile(capFileData);
            Assert.That(validationResult.IsValid, Is.True);
            Assert.That(validationResult.CapFile, Is.Not.Null);

            // Create loading commands
            var commands = CapFileLoadingWorkflow.CreateLoadingCommands(capFileData);
            Assert.That(commands.Count, Is.GreaterThan(0));

            // Establish secure channel
            EstablishSecureChannel();

            // Act - Execute all commands
            foreach (var command in commands)
            {
                byte[] apduBytes;
                
                if (command is InstallCommand installCmd)
                {
                    apduBytes = installCmd.ToApdu();
                }
                else if (command is LoadCommand loadCmd)
                {
                    apduBytes = loadCmd.ToApdu();
                }
                else
                {
                    Assert.Fail($"Unexpected command type: {command.GetType()}");
                    return;
                }

                var response = _cardService.SendCommand(apduBytes);
                Assert.That(response.IsSuccessful, Is.True, 
                    $"Command failed with SW={response.StatusWord:X4}");
            }

            // Assert - Verify successful installation
            // The CAP file contains an applet that should now be selectable
        }

        [Test]
        public void MultipleReaders_CanSwitchBetweenCards()
        {
            // Arrange
            var readers = _cardService.GetReaders();
            Assert.That(readers.Count, Is.GreaterThanOrEqualTo(2));

            var reader1 = readers[0];
            var reader2 = readers[1];

            // Act & Assert - Connect to first reader
            var result1 = _cardService.Connect(reader1);
            Assert.That(result1, Is.True);
            
            var atr1 = _cardService.GetAtr();
            Assert.That(atr1, Is.Not.Null);

            // Switch to second reader
            var result2 = _cardService.Connect(reader2);
            Assert.That(result2, Is.True);
            
            var atr2 = _cardService.GetAtr();
            Assert.That(atr2, Is.Not.Null);

            // Both should have the same ATR (both are ACOS cards)
            Assert.That(atr1, Is.EqualTo(atr2));
        }

        [Test]
        public void ErrorConditions_HandleCorrectly()
        {
            // Test various error conditions

            // 1. Command without secure channel when required
            var installWithoutAuth = InstallCommand.CreateForLoad(ConvertCompat.FromHexString("A011223344"));
            var response1 = _cardService.SendCommand(installWithoutAuth.ToApdu());
            Assert.That(response1.IsSuccessful, Is.False);
            Assert.That(response1.StatusWord, Is.EqualTo(0x6985)); // Conditions not satisfied

            // 2. Select non-existent application
            var selectNonExistent = new SelectCommand(ConvertCompat.FromHexString("1234567890ABCDEF"));
            var response2 = _cardService.SendCommand(selectNonExistent.ToApdu());
            Assert.That(response2.IsSuccessful, Is.False);
            Assert.That(response2.StatusWord, Is.EqualTo(0x6A82)); // File not found

            // 3. Malformed command
            var malformedCommand = new byte[] { 0x00, 0xFF, 0x00, 0x00 }; // Invalid INS
            var response3 = _cardService.SendCommand(malformedCommand);
            Assert.That(response3.IsSuccessful, Is.False);
            Assert.That(response3.StatusWord, Is.EqualTo(0x6D00)); // INS not supported
        }

        private void EstablishSecureChannel()
        {
            // Select ISD
            var isdAid = ConvertCompat.FromHexString("A000000151000000");
            var selectCommand = new SelectCommand(isdAid);
            _cardService.SendCommand(selectCommand.ToApdu());

            // Initialize Update
            _cardService.SendCommand(ConvertCompat.FromHexString("80500000081122334455667788"));

            // External Authenticate
            _cardService.SendCommand(ConvertCompat.FromHexString("84820000103CA4BC00FAD9D1434F4086C4959E26B5"));
        }

        private void InstallTestApplication()
        {
            EstablishSecureChannel();

            var packageAid = ConvertCompat.FromHexString("A011223344");
            var appletAid = ConvertCompat.FromHexString("A01122334401");

            // Install for load
            var installForLoad = InstallCommand.CreateForLoad(packageAid);
            _cardService.SendCommand(installForLoad.ToApdu());

            // Load (simplified)
            var capData = ConvertCompat.FromHexString("C482011D010014DECAFFED020204");
            var loadCommands = LoadCommand.CreateFromCapFile(capData);
            foreach (var loadCommand in loadCommands)
            {
                _cardService.SendCommand(loadCommand.ToApdu());
            }

            // Install for install
            var installForInstall = new InstallCommand(
                InstallCommand.InstallType.ForInstallAndMakeSelectable,
                packageAid,
                appletAid);
            _cardService.SendCommand(installForInstall.ToApdu());
        }

        private static byte[] CreateMinimalCapFile()
        {
            // Create a minimal valid CAP file structure for testing
            // This is a simplified version - a real CAP file would be much larger
            var capData = new System.Collections.Generic.List<byte>();

            // Header component (tag 0x01)
            capData.Add(0x01); // Tag
            capData.Add(0x00); // Size high
            capData.Add(0x10); // Size low (16 bytes)
            
            // Header data (simplified)
            capData.AddRange(ConvertCompat.FromHexString("DECAFFED")); // Magic
            capData.Add(0x01); // Flags
            capData.Add(0x05); // Package info (AID length = 5)
            capData.AddRange(ConvertCompat.FromHexString("A011223344")); // Package AID
            capData.Add(0x01); // Major version
            capData.Add(0x00); // Minor version
            capData.AddRange(new byte[5]); // Padding to reach 16 bytes

            // Directory component (tag 0x02)
            capData.Add(0x02); // Tag
            capData.Add(0x00); // Size high
            capData.Add(0x08); // Size low (8 bytes)
            capData.AddRange(new byte[8]); // Dummy directory data

            return capData.ToArray();
        }
    }
}