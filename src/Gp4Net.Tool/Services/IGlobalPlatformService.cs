using System;
using System.Collections.Generic;
using System.Linq;
using Gp4Net.Domain.Commands;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Services
{
    /// <summary>
    /// Interface for GlobalPlatform operations.
    /// </summary>
    [PublicAPI]
    public interface IGlobalPlatformService
    {
        /// <summary>
        /// Selects the Issuer Security Domain (ISD).
        /// </summary>
        /// <returns>The select response.</returns>
        SelectResponse SelectIsd();

        /// <summary>
        /// Gets the status of applications on the card.
        /// </summary>
        /// <param name="statusSubset">The type of objects to list.</param>
        /// <returns>The status response.</returns>
        GetStatusResponse GetStatus(GetStatusCommand.StatusSubset statusSubset = GetStatusCommand.StatusSubset.IssuerSecurityDomain);

        /// <summary>
        /// Gets detailed information about applications.
        /// </summary>
        /// <returns>List of application information.</returns>
        IList<ApplicationInfo> GetApplications();

        /// <summary>
        /// Installs a CAP file on the card.
        /// </summary>
        /// <param name="capFileData">The CAP file data.</param>
        /// <param name="installApplets">Whether to install applets after loading.</param>
        /// <param name="makeSelectable">Whether to make applets selectable.</param>
        /// <returns>The installation result.</returns>
        InstallationResult InstallCapFile(byte[] capFileData, bool installApplets = true, bool makeSelectable = true);

        /// <summary>
        /// Deletes an application or package from the card.
        /// </summary>
        /// <param name="aid">The AID to delete.</param>
        /// <param name="deleteRelated">Whether to delete related objects.</param>
        /// <returns>The deletion result.</returns>
        DeletionResult DeleteApplication(byte[] aid, bool deleteRelated = true);

        /// <summary>
        /// Changes the lifecycle state of an application.
        /// </summary>
        /// <param name="aid">The application AID.</param>
        /// <param name="newState">The new lifecycle state.</param>
        /// <returns>True if successful.</returns>
        bool SetLifecycleState(byte[] aid, LifecycleState newState);
    }

    /// <summary>
    /// Represents information about an application on the card.
    /// </summary>
    [PublicAPI]
    public class ApplicationInfo
    {
        /// <summary>
        /// Gets the application AID.
        /// </summary>
        public byte[] Aid { get; }

        /// <summary>
        /// Gets the application lifecycle state.
        /// </summary>
        public LifecycleState LifecycleState { get; }

        /// <summary>
        /// Gets the application privileges.
        /// </summary>
        public byte Privileges { get; }

        /// <summary>
        /// Gets the application type.
        /// </summary>
        public ApplicationType Type { get; }

        /// <summary>
        /// Initializes a new instance of the ApplicationInfo class.
        /// </summary>
        public ApplicationInfo(byte[] aid, LifecycleState lifecycleState, byte privileges, ApplicationType type)
        {
            Aid = (byte[])aid.Clone();
            LifecycleState = lifecycleState;
            Privileges = privileges;
            Type = type;
        }
    }

    /// <summary>
    /// Application types.
    /// </summary>
    public enum ApplicationType
    {
        /// <summary>
        /// Issuer Security Domain.
        /// </summary>
        IssuerSecurityDomain,

        /// <summary>
        /// Supplementary Security Domain.
        /// </summary>
        SupplementarySecurityDomain,

        /// <summary>
        /// Applet.
        /// </summary>
        Applet,

        /// <summary>
        /// Load file.
        /// </summary>
        LoadFile
    }

    /// <summary>
    /// Lifecycle states.
    /// </summary>
    public enum LifecycleState : byte
    {
        /// <summary>
        /// OP_READY state.
        /// </summary>
        OpReady = 0x01,

        /// <summary>
        /// INITIALIZED state.
        /// </summary>
        Initialized = 0x03,

        /// <summary>
        /// SELECTABLE state.
        /// </summary>
        Selectable = 0x07,

        /// <summary>
        /// PERSONALIZED state.
        /// </summary>
        Personalized = 0x0F,

        /// <summary>
        /// BLOCKED state.
        /// </summary>
        Blocked = 0x83,

        /// <summary>
        /// LOCKED state.
        /// </summary>
        Locked = 0x87
    }

    /// <summary>
    /// Represents the result of an installation operation.
    /// </summary>
    [PublicAPI]
    public class InstallationResult
    {
        /// <summary>
        /// Gets a value indicating whether the installation was successful.
        /// </summary>
        public bool IsSuccessful { get; }

        /// <summary>
        /// Gets the error message if the installation failed.
        /// </summary>
        public string? ErrorMessage { get; }

        /// <summary>
        /// Gets the loaded package AID.
        /// </summary>
        public byte[]? PackageAid { get; }

        /// <summary>
        /// Gets the installed applet AIDs.
        /// </summary>
        public IReadOnlyList<byte[]> InstalledApplets { get; }

        /// <summary>
        /// Initializes a new instance of the InstallationResult class.
        /// </summary>
        public InstallationResult(bool isSuccessful, string? errorMessage = null, 
            byte[]? packageAid = null, IList<byte[]>? installedApplets = null)
        {
            IsSuccessful = isSuccessful;
            ErrorMessage = errorMessage;
            PackageAid = packageAid?.Clone() as byte[];
            InstalledApplets = installedApplets?.ToList().AsReadOnly() ?? new List<byte[]>().AsReadOnly();
        }
    }

    /// <summary>
    /// Represents the result of a deletion operation.
    /// </summary>
    [PublicAPI]
    public class DeletionResult
    {
        /// <summary>
        /// Gets a value indicating whether the deletion was successful.
        /// </summary>
        public bool IsSuccessful { get; }

        /// <summary>
        /// Gets the error message if the deletion failed.
        /// </summary>
        public string? ErrorMessage { get; }

        /// <summary>
        /// Gets the deleted AIDs.
        /// </summary>
        public IReadOnlyList<byte[]> DeletedAids { get; }

        /// <summary>
        /// Initializes a new instance of the DeletionResult class.
        /// </summary>
        public DeletionResult(bool isSuccessful, string? errorMessage = null, IList<byte[]>? deletedAids = null)
        {
            IsSuccessful = isSuccessful;
            ErrorMessage = errorMessage;
            DeletedAids = deletedAids?.ToList().AsReadOnly() ?? new List<byte[]>().AsReadOnly();
        }
    }
}