using System;
using System.Collections.Generic;
using System.Linq;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.CapFile;
using Gp4Net.Utils;
using JetBrains.Annotations;
using log4net;

namespace Gp4Net.Tool.Services
{
    /// <summary>
    /// Implementation of GlobalPlatform operations using the GP4Net library.
    /// </summary>
    [PublicAPI]
    public class GlobalPlatformService : IGlobalPlatformService
    {
        private static readonly ILog Logger = LogManager.GetLogger(typeof(GlobalPlatformService));
        private readonly ICardService _cardService;

        /// <summary>
        /// Initializes a new instance of the GlobalPlatformService class.
        /// </summary>
        /// <param name="cardService">The card service for communication.</param>
        public GlobalPlatformService(ICardService cardService)
        {
            _cardService = cardService ?? throw new ArgumentNullException(nameof(cardService));
        }

        /// <inheritdoc />
        public SelectResponse SelectIsd()
        {
            Logger.Info("Selecting Issuer Security Domain");

            try
            {
                // Select the ISD with default AID (A000000003000000)
                var isdAid = ConvertCompat.FromHexString("A000000003000000");
                var selectCommand = new SelectCommand(isdAid);
                var response = _cardService.SendCommand(selectCommand.ToApdu());

                var selectResponse = SelectResponse.Parse(response.Data);
                
                if (response.IsSuccessful)
                {
                    Logger.Info("Successfully selected ISD");
                }
                else
                {
                    Logger.Warn($"Failed to select ISD: SW={response.StatusWord:X4}");
                }

                return selectResponse;
            }
            catch (Exception ex)
            {
                Logger.Error("Error selecting ISD", ex);
                throw;
            }
        }

        /// <inheritdoc />
        public GetStatusResponse GetStatus(GetStatusCommand.StatusSubset statusSubset = GetStatusCommand.StatusSubset.IssuerSecurityDomain)
        {
            Logger.Info($"Getting status for: {statusSubset}");

            try
            {
                var getStatusCommand = new GetStatusCommand(statusSubset);
                var response = _cardService.SendCommand(getStatusCommand.ToApdu());

                if (!response.IsSuccessful)
                {
                    Logger.Warn($"Failed to get status: SW={response.StatusWord:X4}");
                    return new GetStatusResponse(new List<ApplicationStatusEntry>());
                }

                var statusResponse = GetStatusResponse.Parse(response.Data);
                Logger.Info($"Successfully retrieved status for {statusResponse.Applications.Count} applications");
                return statusResponse;
            }
            catch (Exception ex)
            {
                Logger.Error($"Error getting status for {statusSubset}", ex);
                throw;
            }
        }

        /// <inheritdoc />
        public IList<ApplicationInfo> GetApplications()
        {
            Logger.Info("Getting all applications on card");

            var applications = new List<ApplicationInfo>();

            try
            {
                // Get ISD information
                var isdStatus = GetStatus(GetStatusCommand.StatusSubset.IssuerSecurityDomain);
                foreach (var app in isdStatus.Applications)
                {
                    applications.Add(new ApplicationInfo(
                        app.Aid,
                        (LifecycleState)app.State,
                        app.Privileges.Length > 0 ? app.Privileges[0] : (byte)0,
                        ApplicationType.IssuerSecurityDomain));
                }

                // Get applications and security domains
                var appStatus = GetStatus(GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains);
                foreach (var app in appStatus.Applications)
                {
                    var firstPrivilege = app.Privileges.Length > 0 ? app.Privileges[0] : (byte)0;
                    var appType = (firstPrivilege & 0x80) != 0 
                        ? ApplicationType.SupplementarySecurityDomain 
                        : ApplicationType.Applet;

                    applications.Add(new ApplicationInfo(
                        app.Aid,
                        (LifecycleState)app.State,
                        firstPrivilege,
                        appType));
                }

                // Get load files
                var loadFileStatus = GetStatus(GetStatusCommand.StatusSubset.ExecutableLoadFiles);
                foreach (var app in loadFileStatus.Applications)
                {
                    applications.Add(new ApplicationInfo(
                        app.Aid,
                        (LifecycleState)app.State,
                        app.Privileges.Length > 0 ? app.Privileges[0] : (byte)0,
                        ApplicationType.LoadFile));
                }

                Logger.Info($"Found {applications.Count} total applications/load files");
                return applications;
            }
            catch (Exception ex)
            {
                Logger.Error("Error getting applications", ex);
                throw;
            }
        }

        /// <inheritdoc />
        public InstallationResult InstallCapFile(byte[] capFileData, bool installApplets = true, bool makeSelectable = true)
        {
            if (capFileData == null)
                throw new ArgumentNullException(nameof(capFileData));

            Logger.Info($"Installing CAP file ({capFileData.Length} bytes)");

            try
            {
                // Validate CAP file first
                var validationResult = CapFileLoadingWorkflow.ValidateCapFile(capFileData);
                if (!validationResult.IsValid)
                {
                    var error = $"Invalid CAP file: {validationResult.ErrorMessage}";
                    Logger.Error(error);
                    return new InstallationResult(false, error);
                }

                var capFile = validationResult.CapFile!;
                Logger.Info($"Installing package AID: {Convert.ToHexString(capFile.PackageAid)}");

                // Create loading commands
                var commands = CapFileLoadingWorkflow.CreateLoadingCommands(
                    capFileData, 
                    securityDomainAid: null, 
                    installApplets, 
                    makeSelectable);

                var installedApplets = new List<byte[]>();

                // Execute commands
                foreach (var command in commands)
                {
                    if (command is InstallCommand installCmd)
                    {
                        Logger.Debug($"Executing INSTALL command: {installCmd.Type}");
                        var response = _cardService.SendCommand(installCmd.ToApdu());
                        
                        if (!response.IsSuccessful)
                        {
                            var error = $"INSTALL command failed: SW={response.StatusWord:X4}";
                            Logger.Error(error);
                            return new InstallationResult(false, error);
                        }

                        if (installCmd.Type == InstallCommand.InstallType.ForInstall ||
                            installCmd.Type == InstallCommand.InstallType.ForInstallAndMakeSelectable)
                        {
                            if (installCmd.AppletAid != null)
                            {
                                installedApplets.Add(installCmd.AppletAid);
                            }
                        }
                    }
                    else if (command is LoadCommand loadCmd)
                    {
                        Logger.Debug($"Executing LOAD command: block {loadCmd.BlockNumber}");
                        var response = _cardService.SendCommand(loadCmd.ToApdu());
                        
                        if (!response.IsSuccessful)
                        {
                            var error = $"LOAD command failed: SW={response.StatusWord:X4}";
                            Logger.Error(error);
                            return new InstallationResult(false, error);
                        }
                    }
                }

                Logger.Info($"Successfully installed CAP file with {installedApplets.Count} applets");
                return new InstallationResult(true, packageAid: capFile.PackageAid, installedApplets: installedApplets);
            }
            catch (Exception ex)
            {
                Logger.Error("Error installing CAP file", ex);
                return new InstallationResult(false, $"Installation failed: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public DeletionResult DeleteApplication(byte[] aid, bool deleteRelated = true)
        {
            if (aid == null)
                throw new ArgumentNullException(nameof(aid));

            Logger.Info($"Deleting application: {Convert.ToHexString(aid)}");

            try
            {
                var deleteCommand = DeleteCommand.CreateForApplication(aid, deleteRelated);
                var response = _cardService.SendCommand(deleteCommand.ToApdu());

                var deleteResponse = DeleteResponse.Parse(response.Data, response.StatusWord);

                if (deleteResponse.IsSuccessful)
                {
                    var deletedAids = deleteResponse.DeletionReceipts.Select(r => r.Aid).ToList();
                    Logger.Info($"Successfully deleted {deletedAids.Count} objects");
                    return new DeletionResult(true, deletedAids: deletedAids);
                }
                else
                {
                    var error = deleteResponse.GetResultDescription();
                    Logger.Error($"Deletion failed: {error}");
                    return new DeletionResult(false, error);
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Error deleting application {Convert.ToHexString(aid)}", ex);
                return new DeletionResult(false, $"Deletion failed: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public bool SetLifecycleState(byte[] aid, LifecycleState newState)
        {
            if (aid == null)
                throw new ArgumentNullException(nameof(aid));

            Logger.Info($"Setting lifecycle state for {Convert.ToHexString(aid)} to {newState}");

            try
            {
                // Create SET STATUS command
                var setStatusData = new List<byte>();
                setStatusData.Add(0x4F); // AID tag
                setStatusData.Add((byte)aid.Length);
                setStatusData.AddRange(aid);
                setStatusData.Add((byte)newState);

                var apdu = new List<byte>
                {
                    0x80, // CLA
                    0xF0, // INS (SET STATUS)
                    0x00, // P1
                    0x00, // P2
                    (byte)setStatusData.Count // Lc
                };
                apdu.AddRange(setStatusData);
                apdu.Add(0x00); // Le

                var response = _cardService.SendCommand(apdu.ToArray());

                if (response.IsSuccessful)
                {
                    Logger.Info($"Successfully set lifecycle state to {newState}");
                    return true;
                }
                else
                {
                    Logger.Error($"Failed to set lifecycle state: SW={response.StatusWord:X4}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Error setting lifecycle state for {Convert.ToHexString(aid)}", ex);
                return false;
            }
        }
    }
}