using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Gp4Net.Domain.CapFile;
using Gp4Net.Domain.CardInfo;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Transport;
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
        private readonly ISecureChannelManager _secureChannelManager;
        private readonly ISecureChannelProtocolFactory _scpFactory;

        /// <summary>
        /// Initializes a new instance of the GlobalPlatformService class.
        /// </summary>
        /// <param name="cardService">The card service for communication.</param>
        /// <param name="secureChannelManager">The secure channel manager.</param>
        /// <param name="scpFactory">The secure channel protocol factory.</param>
        public GlobalPlatformService(
            ICardService cardService,
            ISecureChannelManager secureChannelManager,
            ISecureChannelProtocolFactory scpFactory
        )
        {
            _cardService = cardService ?? throw new ArgumentNullException(nameof(cardService));
            _secureChannelManager = secureChannelManager;
            _scpFactory = scpFactory;
        }

        /// <inheritdoc />
        public SelectResponse SelectIsd()
        {
            Logger.Info("Selecting Issuer Security Domain with auto-detection");

            try
            {
                // First try empty SELECT for auto-detection (like GP Pro)
                var emptySelectCommand = SelectCommand.CreateEmptySelect();
                var response = _cardService.SendCommand(emptySelectCommand);

                if (response.IsSuccessful)
                {
                    var selectResponse = SelectResponse.Parse(response.Data);

                    // Check if we got an AID from the FCI
                    if (selectResponse.Fci?.ApplicationAid != null)
                    {
                        var detectedAid = selectResponse.Fci.ApplicationAid;
                        Logger.Info($"Auto-detected ISD: {Convert.ToHexString(detectedAid)}");
                        return selectResponse;
                    }
                }

                // If empty SELECT didn't work or didn't return an AID, try known ISD AIDs
                var knownIsdAids = new[]
                {
                    "A000000003000000", // Standard GP ISD
                    "A000000151000000", // Common alternative ISD
                    "A000000018434D00", // Another common ISD variant
                };

                foreach (var aidHex in knownIsdAids)
                {
                    try
                    {
                        var aid = Convert.FromHexString(aidHex);
                        var selectCommand = new SelectCommand(aid);
                        response = _cardService.SendCommand(selectCommand);

                        if (response.IsSuccessful)
                        {
                            var selectResponse = SelectResponse.Parse(response.Data);
                            Logger.Info($"Successfully selected ISD with AID: {aidHex}");
                            return selectResponse;
                        }
                    }
                    catch
                    {
                        // Try next AID
                    }
                }

                // If we get here, no ISD was found
                Logger.Error("Failed to select any ISD");
                throw new InvalidOperationException(
                    "Could not select ISD - tried auto-detection and known AIDs"
                );
            }
            catch (InvalidOperationException)
            {
                // Already logged, just rethrow
                throw;
            }
            catch (Exception ex)
            {
                Logger.Error("Unexpected error while selecting ISD", ex);
                throw new InvalidOperationException("Failed to select ISD", ex);
            }
        }

        /// <inheritdoc />
        public GetStatusResponse GetStatus(
            GetStatusCommand.StatusSubset statusSubset =
                GetStatusCommand.StatusSubset.IssuerSecurityDomain
        )
        {
            Logger.Info($"Getting status for: {statusSubset}");

            try
            {
                var getStatusCommand = new GetStatusCommand(statusSubset);
                var response = _cardService.SendCommand(getStatusCommand.ToApdu());

                if (!response.IsSuccessful)
                {
                    Logger.Warn($"Failed to get status: SW={response.StatusWord:X4}");
                    return new GetStatusResponse([]);
                }

                var statusResponse = GetStatusResponse.Parse(response.Data);
                Logger.Info(
                    $"Successfully retrieved status for {statusResponse.Applications.Count} applications"
                );
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
                    var privileges = ParsePrivileges(app.Privileges);
                    applications.Add(
                        new ApplicationInfo(
                            app.Aid,
                            GetLifecycleStateName((LifecycleState)app.State),
                            privileges,
                            "ISD"
                        )
                    );
                }

                // Get applications and security domains
                var appStatus = GetStatus(
                    GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains
                );
                foreach (var app in appStatus.Applications)
                {
                    var privileges = ParsePrivileges(app.Privileges);
                    var firstPrivilege = app.Privileges.Length > 0 ? app.Privileges[0] : (byte)0;
                    var appType = (firstPrivilege & 0x80) != 0 ? "SSD" : "Application";

                    applications.Add(
                        new ApplicationInfo(
                            app.Aid,
                            GetLifecycleStateName((LifecycleState)app.State),
                            privileges,
                            appType
                        )
                    );
                }

                // Get load files
                var loadFileStatus = GetStatus(GetStatusCommand.StatusSubset.ExecutableLoadFiles);
                foreach (var app in loadFileStatus.Applications)
                {
                    var privileges = ParsePrivileges(app.Privileges);
                    applications.Add(
                        new ApplicationInfo(
                            app.Aid,
                            GetLifecycleStateName((LifecycleState)app.State),
                            privileges,
                            "Package"
                        )
                    );
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
        public InstallationResult InstallCapFile(
            byte[] capFileData,
            bool installApplets = true,
            bool makeSelectable = true
        )
        {
            ArgumentNullException.ThrowIfNull(capFileData);

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
                    makeSelectable
                );

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

                        if (
                            installCmd.Type == InstallCommand.InstallType.ForInstall
                            || installCmd.Type
                                == InstallCommand.InstallType.ForInstallAndMakeSelectable
                        )
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

                Logger.Info(
                    $"Successfully installed CAP file with {installedApplets.Count} applets"
                );
                return new InstallationResult(
                    true,
                    packageAid: capFile.PackageAid,
                    installedApplets: installedApplets
                );
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
            ArgumentNullException.ThrowIfNull(aid);

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
            ArgumentNullException.ThrowIfNull(aid);

            Logger.Info($"Setting lifecycle state for {Convert.ToHexString(aid)} to {newState}");

            try
            {
                // Create SET STATUS command
                var setStatusData = new List<byte>
                {
                    0x4F, // AID tag
                    (byte)aid.Length
                };
                setStatusData.AddRange(aid);
                setStatusData.Add((byte)newState);

                var apdu = new List<byte>
                {
                    0x80, // CLA
                    0xF0, // INS (SET STATUS)
                    0x00, // P1
                    0x00, // P2
                    (byte)setStatusData.Count, // Lc
                };
                apdu.AddRange(setStatusData);
                apdu.Add(0x00); // Le

                var response = _cardService.SendCommand([.. apdu]);

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

        /// <inheritdoc />
        public CplcData? GetCplc()
        {
            Logger.Info("Getting CPLC data");

            try
            {
                var response = GetData(GetDataCommand.DataObjects.CardProductionLifeCycle);
                return response?.ParseAsCplc();
            }
            catch (Exception ex)
            {
                Logger.Error("Error getting CPLC data", ex);
                return null;
            }
        }

        /// <inheritdoc />
        public CardDataInfo? GetCardData()
        {
            Logger.Info("Getting Card Data");

            try
            {
                var response = GetData(GetDataCommand.DataObjects.CardData);
                return response?.ParseAsCardData();
            }
            catch (Exception ex)
            {
                Logger.Error("Error getting Card Data", ex);
                return null;
            }
        }

        /// <inheritdoc />
        public CardCapabilities? GetCardCapabilities()
        {
            Logger.Info("Getting Card Capabilities");

            try
            {
                var response = GetData(GetDataCommand.DataObjects.CardCapabilities);
                return response?.ParseAsCardCapabilities();
            }
            catch (Exception ex)
            {
                Logger.Error("Error getting Card Capabilities", ex);
                return null;
            }
        }

        /// <inheritdoc />
        public GetDataResponse? GetData(ushort dataObjectIdentifier)
        {
            Logger.Debug($"Getting data for tag: {dataObjectIdentifier:X4}");

            try
            {
                var command = new GetDataCommand(dataObjectIdentifier);
                var (data, statusWord) = SendCommand(command);

                if (statusWord == 0x9000)
                {
                    return GetDataResponse.Parse(dataObjectIdentifier, data);
                }
                else if (statusWord == 0x6A88 || statusWord == 0x6982)
                {
                    // Data not found or security status not satisfied
                    Logger.Debug(
                        $"GET DATA not supported for tag {dataObjectIdentifier:X4}: SW={statusWord:X4}"
                    );
                    return null;
                }
                else
                {
                    Logger.Warn(
                        $"GET DATA failed for tag {dataObjectIdentifier:X4}: SW={statusWord:X4}"
                    );
                    return null;
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Error getting data for tag {dataObjectIdentifier:X4}", ex);
                throw;
            }
        }

        /// <inheritdoc />
        public (byte[] Data, ushort StatusWord) SendCommand(IApduCommand command)
        {
            ArgumentNullException.ThrowIfNull(command);

            // For now, we need to handle different command types differently
            // This is a temporary workaround until all commands implement IApduCommand
            var response = _cardService.SendCommand(command);
            return (response.Data, response.StatusWord);
        }

        private List<string> ParsePrivileges(byte[] privileges)
        {
            var result = new List<string>();

            if (privileges == null || privileges.Length == 0)
            {
                return result;
            }

            var priv = privileges[0];

            if ((priv & 0x80) != 0)
            {
                result.Add("Security Domain");
            }

            if ((priv & 0x40) != 0)
            {
                result.Add("DAP Verification");
            }

            if ((priv & 0x20) != 0)
            {
                result.Add("Delegated Management");
            }

            if ((priv & 0x10) != 0)
            {
                result.Add("Card Lock");
            }

            if ((priv & 0x08) != 0)
            {
                result.Add("Card Terminate");
            }

            if ((priv & 0x04) != 0)
            {
                result.Add("Card Reset");
            }

            if ((priv & 0x02) != 0)
            {
                result.Add("CVM Management");
            }

            if ((priv & 0x01) != 0)
            {
                result.Add("Mandated DAP");
            }

            if (privileges.Length > 1)
            {
                var priv2 = privileges[1];
                if ((priv2 & 0x80) != 0)
                {
                    result.Add("Trusted Path");
                }

                if ((priv2 & 0x40) != 0)
                {
                    result.Add("Authorized Management");
                }

                if ((priv2 & 0x20) != 0)
                {
                    result.Add("Token Verification");
                }

                if ((priv2 & 0x10) != 0)
                {
                    result.Add("Global Delete");
                }

                if ((priv2 & 0x08) != 0)
                {
                    result.Add("Global Lock");
                }

                if ((priv2 & 0x04) != 0)
                {
                    result.Add("Global Registry");
                }

                if ((priv2 & 0x02) != 0)
                {
                    result.Add("Final Application");
                }

                if ((priv2 & 0x01) != 0)
                {
                    result.Add("Global Service");
                }
            }

            if (privileges.Length > 2)
            {
                var priv3 = privileges[2];
                if ((priv3 & 0x80) != 0)
                {
                    result.Add("Receipt Generation");
                }

                if ((priv3 & 0x40) != 0)
                {
                    result.Add("Ciphered Load File Data Block");
                }

                if ((priv3 & 0x20) != 0)
                {
                    result.Add("Contactless Activation");
                }

                if ((priv3 & 0x10) != 0)
                {
                    result.Add("Contactless Self-Activation");
                }
            }

            return result;
        }

        /// <inheritdoc />
        public Task<PutKeyResult> PutKeysAsync(IKeySet newKeySet, byte newKeyVersion)
        {
            Logger.Info($"Changing keys to version {newKeyVersion:X2}");

            try
            {
                // Create key data blocks based on the keyset type
                var keyDataBlocks = new List<KeyDataBlock>();

                if (newKeySet is Scp02KeySet scp02KeySet)
                {
                    // For SCP02, create 3DES key blocks
                    keyDataBlocks.Add(KeyDataBlock.CreateTripleDes2Key(scp02KeySet.EncKey));
                    keyDataBlocks.Add(KeyDataBlock.CreateTripleDes2Key(scp02KeySet.MacKey));
                    keyDataBlocks.Add(KeyDataBlock.CreateTripleDes2Key(scp02KeySet.DekKey));
                }
                else if (newKeySet is Scp03KeySet scp03KeySet)
                {
                    // For SCP03, create AES key blocks
                    keyDataBlocks.Add(KeyDataBlock.CreateAes128Key(scp03KeySet.EncKey));
                    keyDataBlocks.Add(KeyDataBlock.CreateAes128Key(scp03KeySet.MacKey));
                    keyDataBlocks.Add(KeyDataBlock.CreateAes128Key(scp03KeySet.DekKey));
                }
                else
                {
                    return Task.FromResult(new PutKeyResult(
                        false,
                        $"Unsupported keyset type: {newKeySet.GetType().Name}"
                    ));
                }

                // Create PUT KEY command with multiple keys
                var putKeyCommand = new PutKeyCommand(
                    PutKeyCommand.KeyUsageQualifier.MultipleKeys,
                    PutKeyCommand.KeyEncryptionKeyIdentifier.None, // Plain text keys for now
                    keyDataBlocks
                );

                // Send the command
                var (responseData, statusWord) = SendCommand(putKeyCommand);

                if (statusWord == 0x9000)
                {
                    // Parse key check values from response
                    List<byte[]>? keyCheckValues = null;
                    if (responseData?.Length > 0)
                    {
                        var putKeyResponse = PutKeyResponse.Parse(responseData);
                        keyCheckValues = [.. putKeyResponse.KeyCheckValues];
                    }

                    Logger.Info("Keys changed successfully");
                    return Task.FromResult(new PutKeyResult(true, null, keyCheckValues));
                }
                else
                {
                    var errorMessage = $"PUT KEY failed with status word: {statusWord:X4}";
                    Logger.Error(errorMessage);
                    return Task.FromResult(new PutKeyResult(false, errorMessage));
                }
            }
            catch (Exception ex)
            {
                Logger.Error("PUT KEY operation failed", ex);
                return Task.FromResult(new PutKeyResult(false, ex.Message));
            }
        }

        private string GetLifecycleStateName(LifecycleState state)
        {
            return state switch
            {
                LifecycleState.OpReady => "OP_READY",
                LifecycleState.Initialized => "INITIALIZED",
                LifecycleState.Selectable => "SELECTABLE",
                LifecycleState.Personalized => "PERSONALIZED",
                LifecycleState.Blocked => "BLOCKED",
                LifecycleState.Locked => "LOCKED",
                _ => $"UNKNOWN ({(byte)state:X2})",
            };
        }
    }
}
