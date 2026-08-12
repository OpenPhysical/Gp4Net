using System.Collections.Generic;
using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Transport;
using JetBrains.Annotations;
using WSCT.ISO7816;
using static Gp4Net.Constants.Constants;

namespace Gp4Net.Domain.Commands;

/// <summary>
/// Immutable record representing the INSTALL command for loading and installing applications.
/// Supports INSTALL [for load] and INSTALL [for install] operations.
/// </summary>
[PublicAPI]
public abstract record InstallCommand : IApduCommand
{
    /// <summary>
    /// The command class byte.
    /// </summary>
    public const byte COMMAND_CLA = 0x80;

    /// <summary>
    /// The command instruction byte.
    /// </summary>
    public const byte COMMAND_INS = 0xE6;

    /// <summary>
    /// Gets the install type.
    /// </summary>
    public abstract InstallType Type { get; }

    /// <summary>
    /// Gets the package AID.
    /// </summary>
    public ImmutableArray<byte> PackageAid { get; }

    /// <inheritdoc />
    public byte Cla => COMMAND_CLA;

    /// <inheritdoc />
    public byte Ins => COMMAND_INS;

    /// <summary>
    /// Converts this command to a CommandAPDU.
    /// </summary>
    /// <returns>A result containing the CommandAPDU or an error.</returns>
    public abstract Result<CommandAPDU, SmartCardError> ToCommandApdu();

    // GP Card Specification v2.3.1, Table 11-41.
    /// <inheritdoc/>
    public byte P1 => (byte)((byte)Type | (MoreCommands ? 0x80 : 0x00));

    // GP Card Specification v2.3.1, section 11.5.2.2.
    /// <inheritdoc/>
    public byte P2 => (byte)Sequence;

    /// <summary>
    /// Gets whether another INSTALL command component follows.
    /// </summary>
    public bool MoreCommands { get; }

    /// <summary>
    /// Gets the combined-operation position encoded in P2.
    /// </summary>
    public InstallSequence Sequence { get; }

    /// <inheritdoc/>
    public abstract byte[] Data { get; }

    /// <inheritdoc/>
    public Maybe<int> ExpectedResponseLength
    {
        get
        {
            return Maybe<int>.From(0);

            // Le=00 for INSTALL commands
        }
    }

    /// <inheritdoc/>
    public bool IsExtendedLength
    {
        get { return false; }
    }

    /// <inheritdoc />
    public CommandAPDU ToApdu()
    {
        return ToCommandApdu()
            .Match(
                onSuccess: apdu => apdu,
                onFailure: _ => new CommandAPDU(
                    GlobalPlatform.Cla.GP_STANDARD,
                    GlobalPlatform.Ins.INSTALL,
                    0x00,
                    0x00
                )
            );
    }

    /// <inheritdoc />
    public byte[] ToBytes()
    {
        return ToCommandApdu()
            .Match(
                onSuccess: cmd => cmd.ToBytes(),
                onFailure: _ =>
                    new CommandAPDU(
                        GlobalPlatform.Cla.GP_STANDARD,
                        GlobalPlatform.Ins.INSTALL,
                        0x00,
                        0x00
                    ).ToBytes()
            );
    }

    /// <summary>
    /// Base constructor for InstallCommand.
    /// </summary>
    private protected InstallCommand(
        ImmutableArray<byte> packageAid,
        bool moreCommands = false,
        InstallSequence sequence = InstallSequence.NoInformation
    )
    {
        PackageAid = packageAid;
        MoreCommands = moreCommands;
        Sequence = sequence;
    }

    /// <summary>
    /// Validates that the provided package AID is not null or empty.
    /// </summary>
    /// <param name="packageAid">The package AID to validate.</param>
    /// <returns>A Result indicating success or failure with a SmartCardError.</returns>
    protected static Result<ImmutableArray<byte>, SmartCardError> ValidatePackageAid(
        byte[] packageAid
    )
    {
        if (packageAid == null)
        {
            return Result.Failure<ImmutableArray<byte>, SmartCardError>(
                SmartCardError.InvalidArgument("Package AID cannot be null.")
            );
        }

        if (packageAid.Length == 0)
        {
            return Result.Failure<ImmutableArray<byte>, SmartCardError>(
                SmartCardError.InvalidArgument("Package AID cannot be empty.")
            );
        }

        return Result.Success<ImmutableArray<byte>, SmartCardError>([.. packageAid]);
    }

    private static ImmutableArray<byte> ToImmutableByteArray(Maybe<byte[]> source)
    {
        return source.Match(
            value =>
                value.Length == 0
                    ? ImmutableArray<byte>.Empty
                    : ImmutableArray.Create((byte[])value.Clone()),
            () => ImmutableArray<byte>.Empty
        );
    }

    private static bool HasEncodableBerLength(Maybe<byte[]> value) =>
        value.Match(bytes => bytes.Length <= 0xFFFF, () => true);

    private static SmartCardError InvalidBerLength(string fieldName) =>
        SmartCardError.InvalidArgument($"{fieldName} cannot exceed 65535 bytes.");

    /// <summary>
    /// INSTALL [for load] command implementation.
    /// </summary>
    public sealed record InstallForLoadCommand : InstallCommand
    {
        /// <inheritdoc/>
        public override InstallType Type { get; }

        /// <summary>
        /// Gets the security domain AID (optional).
        /// </summary>
        public ImmutableArray<byte> SecurityDomainAid { get; }

        /// <summary>
        /// Gets the hash of the load file (optional).
        /// </summary>
        public ImmutableArray<byte> Hash { get; }

        /// <summary>
        /// Gets the load parameters (optional).
        /// </summary>
        public ImmutableArray<byte> LoadParameters { get; }

        /// <summary>
        /// Gets the install token (optional).
        /// </summary>
        public ImmutableArray<byte> InstallToken { get; }

        /// <summary>
        /// Initializes a new instance of InstallForLoadCommand.
        /// </summary>
        private InstallForLoadCommand(
            InstallType type,
            ImmutableArray<byte> packageAid,
            ImmutableArray<byte> securityDomainAid,
            ImmutableArray<byte> hash,
            ImmutableArray<byte> loadParameters,
            ImmutableArray<byte> installToken,
            bool moreCommands,
            InstallSequence sequence
        )
            : base(packageAid, moreCommands, sequence)
        {
            Type = type;
            SecurityDomainAid = securityDomainAid;
            Hash = hash;
            LoadParameters = loadParameters;
            InstallToken = installToken;
        }

        /// <summary>
        /// Creates a new INSTALL [for load] command with validation.
        /// </summary>
        /// <param name="packageAid">The package AID.</param>
        /// <param name="loadParameters">Optional Load Parameters TLVs.</param>
        /// <param name="securityDomainAid">Optional security domain AID.</param>
        /// <param name="hash">Optional hash of the load file.</param>
        /// <param name="installToken">Optional install token.</param>
        /// <param name="moreCommands">Whether another INSTALL component follows.</param>
        /// <returns>A Result containing the command or an error.</returns>
        public static Result<InstallForLoadCommand, SmartCardError> Create(
            byte[] packageAid,
            Maybe<byte[]> loadParameters = default,
            Maybe<byte[]> securityDomainAid = default,
            Maybe<byte[]> hash = default,
            Maybe<byte[]> installToken = default,
            bool moreCommands = false
        )
        {
            return CreateCore(
                InstallType.ForLoad,
                InstallSequence.NoInformation,
                packageAid,
                loadParameters,
                securityDomainAid,
                hash,
                installToken,
                moreCommands
            );
        }

        /// <summary>
        /// Creates the first command of a combined load, install, and make-selectable operation.
        /// </summary>
        public static Result<InstallForLoadCommand, SmartCardError> CreateCombined(
            byte[] packageAid,
            Maybe<byte[]> loadParameters = default,
            Maybe<byte[]> securityDomainAid = default,
            Maybe<byte[]> hash = default,
            Maybe<byte[]> installToken = default,
            bool moreCommands = false
        )
        {
            return CreateCore(
                InstallType.ForLoadInstallAndMakeSelectable,
                InstallSequence.BeginCombinedOperation,
                packageAid,
                loadParameters,
                securityDomainAid,
                hash,
                installToken,
                moreCommands
            );
        }

        private static Result<InstallForLoadCommand, SmartCardError> CreateCore(
            InstallType type,
            InstallSequence sequence,
            byte[] packageAid,
            Maybe<byte[]> loadParameters,
            Maybe<byte[]> securityDomainAid,
            Maybe<byte[]> hash,
            Maybe<byte[]> installToken,
            bool moreCommands
        )
        {
            var packageAidResult = ValidatePackageAid(packageAid);
            if (packageAidResult.IsFailure)
            {
                return Result.Failure<InstallForLoadCommand, SmartCardError>(
                    packageAidResult.Error
                );
            }

            if (!HasEncodableBerLength(loadParameters))
            {
                return Result.Failure<InstallForLoadCommand, SmartCardError>(
                    InvalidBerLength("Load Parameters")
                );
            }

            if (!HasEncodableBerLength(installToken))
            {
                return Result.Failure<InstallForLoadCommand, SmartCardError>(
                    InvalidBerLength("Install Token")
                );
            }

            if (hash.Match(value => value.Length > 0x7F, () => false))
            {
                return Result.Failure<InstallForLoadCommand, SmartCardError>(
                    SmartCardError.InvalidArgument(
                        "Load File Data Block Hash cannot exceed 127 bytes."
                    )
                );
            }

            var command = new InstallForLoadCommand(
                type,
                packageAidResult.Value,
                ToImmutableByteArray(securityDomainAid),
                ToImmutableByteArray(hash),
                ToImmutableByteArray(loadParameters),
                ToImmutableByteArray(installToken),
                moreCommands,
                sequence
            );

            return Result.Success<InstallForLoadCommand, SmartCardError>(command);
        }

        /// <inheritdoc/>
        public override byte[] Data
        {
            get { return BuildData(); }
        }

        private byte[] BuildData()
        {
            List<byte> builder = [(byte)PackageAid.Length];

            // Package AID
            builder.AddRange(PackageAid);

            // Security Domain AID
            if (!SecurityDomainAid.IsDefaultOrEmpty)
            {
                builder.Add((byte)SecurityDomainAid.Length);
                builder.AddRange(SecurityDomainAid);
            }
            else
            {
                builder.Add(0x00);
            }

            // Hash
            if (!Hash.IsDefaultOrEmpty)
            {
                builder.Add((byte)Hash.Length);
                builder.AddRange(Hash);
            }
            else
            {
                builder.Add(0x00);
            }

            // Load Parameters - mandatory field per GP spec
            if (!LoadParameters.IsDefaultOrEmpty)
            {
                builder.AddRange(
                    GlobalPlatformLengthEncoding.EncodeBerLength(LoadParameters.Length)
                );
                builder.AddRange(LoadParameters);
            }
            else
            {
                builder.Add(0x00);
            }

            // Install Token
            if (!InstallToken.IsDefaultOrEmpty)
            {
                builder.AddRange(GlobalPlatformLengthEncoding.EncodeBerLength(InstallToken.Length));
                builder.AddRange(InstallToken);
            }
            else
            {
                builder.Add(0x00);
            }

            return [.. builder];
        }

        /// <summary>
        /// Converts this command to a CommandAPDU.
        /// </summary>
        /// <returns>A result containing the CommandAPDU or an error.</returns>
        public override Result<CommandAPDU, SmartCardError> ToCommandApdu()
        {
            return Result.Success<CommandAPDU, SmartCardError>(
                new CommandAPDU(COMMAND_CLA, COMMAND_INS, P1, P2, (uint)Data.Length, Data)
            );
        }

        /// <summary>
        /// Returns a string representation of this command.
        /// </summary>
        public override string ToString()
        {
            return "INSTALL [for load]";
        }
    }

    /// <summary>
    /// INSTALL [for install] command implementation.
    /// </summary>
    public sealed record InstallForInstallCommand : InstallCommand
    {
        /// <inheritdoc/>
        public override InstallType Type { get; }

        /// <summary>
        /// Gets the module AID (optional).
        /// </summary>
        public ImmutableArray<byte> ModuleAid { get; }

        /// <summary>
        /// Gets the applet AID.
        /// </summary>
        public ImmutableArray<byte> AppletAid { get; }

        /// <summary>
        /// Gets the privileges.
        /// </summary>
        public ImmutableArray<byte> Privileges { get; }

        /// <summary>
        /// Gets the install parameters (optional).
        /// </summary>
        public ImmutableArray<byte> InstallParameters { get; }

        /// <summary>
        /// Gets the install token (optional).
        /// </summary>
        public ImmutableArray<byte> InstallToken { get; }

        /// <summary>
        /// Initializes a new instance of InstallForInstallCommand.
        /// </summary>
        private InstallForInstallCommand(
            InstallType type,
            ImmutableArray<byte> packageAid,
            ImmutableArray<byte> appletAid,
            ImmutableArray<byte> moduleAid,
            ImmutableArray<byte> privileges,
            ImmutableArray<byte> installParameters,
            ImmutableArray<byte> installToken,
            bool moreCommands,
            InstallSequence sequence
        )
            : base(packageAid, moreCommands, sequence)
        {
            Type = type;
            AppletAid = appletAid;
            ModuleAid = moduleAid;
            Privileges = privileges.IsDefaultOrEmpty ? [0x00] : privileges;
            // GP Card Specification v2.3.1, Table 11-49: C9 is mandatory.
            InstallParameters = installParameters.IsDefaultOrEmpty
                ? [0xC9, 0x00]
                : installParameters;
            InstallToken = installToken;
        }

        /// <summary>
        /// Creates a new INSTALL [for install] command with validation.
        /// </summary>
        /// <param name="packageAid">The package AID.</param>
        /// <param name="moduleAid">The module AID (can be same as packageAid).</param>
        /// <param name="applicationAid">The application AID.</param>
        /// <param name="privileges">The application privileges.</param>
        /// <param name="installParameters">Optional install parameters.</param>
        /// <param name="installToken">Optional install token.</param>
        /// <param name="moreCommands">Whether another INSTALL component follows.</param>
        /// <returns>A Result containing the command or an error.</returns>
        public static Result<InstallForInstallCommand, SmartCardError> Create(
            byte[] packageAid,
            byte[] moduleAid,
            byte[] applicationAid,
            byte[] privileges,
            Maybe<byte[]> installParameters = default,
            Maybe<byte[]> installToken = default,
            bool moreCommands = false
        )
        {
            var packageAidResult = ValidatePackageAid(packageAid);
            if (packageAidResult.IsFailure)
            {
                return Result.Failure<InstallForInstallCommand, SmartCardError>(
                    packageAidResult.Error
                );
            }

            if (moduleAid == null || moduleAid.Length == 0)
            {
                return Result.Failure<InstallForInstallCommand, SmartCardError>(
                    SmartCardError.InvalidArgument("Module AID cannot be null or empty.")
                );
            }

            if (applicationAid == null || applicationAid.Length == 0)
            {
                return Result.Failure<InstallForInstallCommand, SmartCardError>(
                    SmartCardError.InvalidArgument("Application AID cannot be null or empty.")
                );
            }

            if (privileges == null)
            {
                return Result.Failure<InstallForInstallCommand, SmartCardError>(
                    SmartCardError.InvalidArgument("Privileges cannot be null.")
                );
            }

            if (!HasEncodableBerLength(installParameters))
            {
                return Result.Failure<InstallForInstallCommand, SmartCardError>(
                    InvalidBerLength("Install Parameters")
                );
            }

            if (!HasEncodableBerLength(installToken))
            {
                return Result.Failure<InstallForInstallCommand, SmartCardError>(
                    InvalidBerLength("Install Token")
                );
            }

            var command = new InstallForInstallCommand(
                InstallType.ForInstall,
                packageAidResult.Value,
                [.. applicationAid],
                [.. moduleAid],
                [.. privileges],
                ToImmutableByteArray(installParameters),
                ToImmutableByteArray(installToken),
                moreCommands,
                InstallSequence.NoInformation
            );

            return Result.Success<InstallForInstallCommand, SmartCardError>(command);
        }

        /// <summary>
        /// Creates a new INSTALL [for install and make selectable] command with validation.
        /// </summary>
        /// <param name="packageAid">The package AID.</param>
        /// <param name="moduleAid">The module AID (can be same as packageAid).</param>
        /// <param name="applicationAid">The application AID.</param>
        /// <param name="privileges">The application privileges.</param>
        /// <param name="installParameters">Optional install parameters.</param>
        /// <param name="installToken">Optional install token.</param>
        /// <param name="moreCommands">Whether another INSTALL component follows.</param>
        /// <returns>A Result containing the command or an error.</returns>
        public static Result<InstallForInstallCommand, SmartCardError> CreateAndMakeSelectable(
            byte[] packageAid,
            byte[] moduleAid,
            byte[] applicationAid,
            byte[] privileges,
            Maybe<byte[]> installParameters = default,
            Maybe<byte[]> installToken = default,
            bool moreCommands = false
        )
        {
            var packageAidResult = ValidatePackageAid(packageAid);
            if (packageAidResult.IsFailure)
            {
                return Result.Failure<InstallForInstallCommand, SmartCardError>(
                    packageAidResult.Error
                );
            }

            if (moduleAid == null || moduleAid.Length == 0)
            {
                return Result.Failure<InstallForInstallCommand, SmartCardError>(
                    SmartCardError.InvalidArgument("Module AID cannot be null or empty.")
                );
            }

            if (applicationAid == null || applicationAid.Length == 0)
            {
                return Result.Failure<InstallForInstallCommand, SmartCardError>(
                    SmartCardError.InvalidArgument("Application AID cannot be null or empty.")
                );
            }

            if (privileges == null)
            {
                return Result.Failure<InstallForInstallCommand, SmartCardError>(
                    SmartCardError.InvalidArgument("Privileges cannot be null.")
                );
            }

            var command = new InstallForInstallCommand(
                InstallType.ForInstallAndMakeSelectable,
                packageAidResult.Value,
                [.. applicationAid],
                [.. moduleAid],
                [.. privileges],
                ToImmutableByteArray(installParameters),
                ToImmutableByteArray(installToken),
                moreCommands,
                InstallSequence.NoInformation
            );

            return Result.Success<InstallForInstallCommand, SmartCardError>(command);
        }

        /// <summary>
        /// Creates the final command of a combined load, install, and make-selectable operation.
        /// </summary>
        public static Result<InstallForInstallCommand, SmartCardError> CreateCombinedFinal(
            byte[] packageAid,
            byte[] moduleAid,
            byte[] applicationAid,
            byte[] privileges,
            Maybe<byte[]> installParameters = default,
            Maybe<byte[]> installToken = default,
            bool moreCommands = false
        )
        {
            var result = CreateAndMakeSelectable(
                packageAid,
                moduleAid,
                applicationAid,
                privileges,
                installParameters,
                installToken,
                moreCommands
            );

            return result.Map(command => new InstallForInstallCommand(
                InstallType.ForLoadInstallAndMakeSelectable,
                command.PackageAid,
                command.AppletAid,
                command.ModuleAid,
                command.Privileges,
                command.InstallParameters,
                command.InstallToken,
                command.MoreCommands,
                InstallSequence.EndCombinedOperation
            ));
        }

        /// <inheritdoc/>
        public override byte[] Data
        {
            get { return BuildData(); }
        }

        private byte[] BuildData()
        {
            List<byte> builder = [(byte)PackageAid.Length];

            // Package AID
            builder.AddRange(PackageAid);

            // Module AID
            if (!ModuleAid.IsDefaultOrEmpty)
            {
                builder.Add((byte)ModuleAid.Length);
                builder.AddRange(ModuleAid);
            }
            else
            {
                builder.Add(0x00);
            }

            // Applet AID
            builder.Add((byte)AppletAid.Length);
            builder.AddRange(AppletAid);

            // Privileges
            builder.Add((byte)Privileges.Length);
            builder.AddRange(Privileges);

            // Install Parameters
            if (!InstallParameters.IsDefaultOrEmpty)
            {
                builder.AddRange(
                    GlobalPlatformLengthEncoding.EncodeBerLength(InstallParameters.Length)
                );
                builder.AddRange(InstallParameters);
            }
            else
            {
                builder.Add(0x00);
            }

            // Install Token
            if (!InstallToken.IsDefaultOrEmpty)
            {
                builder.AddRange(GlobalPlatformLengthEncoding.EncodeBerLength(InstallToken.Length));
                builder.AddRange(InstallToken);
            }
            else
            {
                builder.Add(0x00);
            }

            return [.. builder];
        }

        /// <summary>
        /// Converts this command to a CommandAPDU.
        /// </summary>
        /// <returns>A result containing the CommandAPDU or an error.</returns>
        public override Result<CommandAPDU, SmartCardError> ToCommandApdu()
        {
            return Result.Success<CommandAPDU, SmartCardError>(
                new CommandAPDU(COMMAND_CLA, COMMAND_INS, P1, P2, (uint)Data.Length, Data)
            );
        }

        /// <summary>
        /// Returns a string representation of this command.
        /// </summary>
        public override string ToString()
        {
            return "INSTALL [for install]";
        }
    }

    /// <summary>
    /// INSTALL command for make-selectable, extradition, registry-update, and personalization.
    /// </summary>
    public sealed record InstallForManagementCommand : InstallCommand
    {
        private readonly ImmutableArray<byte> data;

        /// <inheritdoc/>
        public override InstallType Type { get; }

        private InstallForManagementCommand(
            InstallType type,
            ImmutableArray<byte> applicationAid,
            ImmutableArray<byte> data,
            bool moreCommands
        )
            : base(applicationAid, moreCommands)
        {
            Type = type;
            this.data = data;
        }

        /// <inheritdoc/>
        public override byte[] Data => [.. data];

        /// <summary>
        /// Creates INSTALL [for make selectable].
        /// </summary>
        public static Result<InstallForManagementCommand, SmartCardError> CreateForMakeSelectable(
            byte[] applicationAid,
            byte[] privileges,
            Maybe<byte[]> parameters = default,
            Maybe<byte[]> token = default,
            bool moreCommands = false
        )
        {
            var aidResult = ValidateRequiredAid(applicationAid, "Application AID");
            if (aidResult.IsFailure)
            {
                return Result.Failure<InstallForManagementCommand, SmartCardError>(aidResult.Error);
            }

            if (privileges is null || privileges.Length is not (1 or 3))
            {
                return Result.Failure<InstallForManagementCommand, SmartCardError>(
                    SmartCardError.InvalidArgument("Privileges must contain one or three bytes.")
                );
            }

            if (!HasEncodableBerLength(parameters) || !HasEncodableBerLength(token))
            {
                return Result.Failure<InstallForManagementCommand, SmartCardError>(
                    InvalidBerLength("Parameters or Token")
                );
            }

            // GP Card Specification v2.3.1, Table 11-44.
            var data = BuildLvData(
                ImmutableArray<byte>.Empty,
                ImmutableArray<byte>.Empty,
                aidResult.Value,
                [.. privileges],
                ToImmutableByteArray(parameters),
                ToImmutableByteArray(token)
            );

            return Result.Success<InstallForManagementCommand, SmartCardError>(
                new InstallForManagementCommand(
                    InstallType.ForMakeSelectable,
                    aidResult.Value,
                    data,
                    moreCommands
                )
            );
        }

        /// <summary>
        /// Creates INSTALL [for extradition].
        /// </summary>
        public static Result<InstallForManagementCommand, SmartCardError> CreateForExtradition(
            byte[] securityDomainAid,
            byte[] applicationOrLoadFileAid,
            Maybe<byte[]> parameters = default,
            Maybe<byte[]> token = default,
            bool moreCommands = false
        )
        {
            var securityDomainResult = ValidateRequiredAid(
                securityDomainAid,
                "Security Domain AID"
            );
            if (securityDomainResult.IsFailure)
            {
                return Result.Failure<InstallForManagementCommand, SmartCardError>(
                    securityDomainResult.Error
                );
            }

            var targetResult = ValidateRequiredAid(
                applicationOrLoadFileAid,
                "Application or Executable Load File AID"
            );
            if (targetResult.IsFailure)
            {
                return Result.Failure<InstallForManagementCommand, SmartCardError>(
                    targetResult.Error
                );
            }

            if (!HasEncodableBerLength(parameters) || !HasEncodableBerLength(token))
            {
                return Result.Failure<InstallForManagementCommand, SmartCardError>(
                    InvalidBerLength("Parameters or Token")
                );
            }

            // GP Card Specification v2.3.1, Table 11-45.
            var data = BuildLvData(
                securityDomainResult.Value,
                ImmutableArray<byte>.Empty,
                targetResult.Value,
                ImmutableArray<byte>.Empty,
                ToImmutableByteArray(parameters),
                ToImmutableByteArray(token)
            );

            return Result.Success<InstallForManagementCommand, SmartCardError>(
                new InstallForManagementCommand(
                    InstallType.ForExtradition,
                    targetResult.Value,
                    data,
                    moreCommands
                )
            );
        }

        /// <summary>
        /// Creates INSTALL [for registry update].
        /// </summary>
        public static Result<InstallForManagementCommand, SmartCardError> CreateForRegistryUpdate(
            Maybe<byte[]> securityDomainAid = default,
            Maybe<byte[]> applicationAid = default,
            Maybe<byte[]> privileges = default,
            Maybe<byte[]> parameters = default,
            Maybe<byte[]> token = default,
            bool moreCommands = false
        )
        {
            var securityDomain = ToImmutableByteArray(securityDomainAid);
            var application = ToImmutableByteArray(applicationAid);
            var privilegeBytes = ToImmutableByteArray(privileges);

            if (!IsOptionalAidValid(securityDomain) || !IsOptionalAidValid(application))
            {
                return Result.Failure<InstallForManagementCommand, SmartCardError>(
                    SmartCardError.InvalidArgument("AIDs must contain five through sixteen bytes.")
                );
            }

            if (!privilegeBytes.IsDefaultOrEmpty && privilegeBytes.Length is not (1 or 3))
            {
                return Result.Failure<InstallForManagementCommand, SmartCardError>(
                    SmartCardError.InvalidArgument(
                        "Privileges must be empty or contain one or three bytes."
                    )
                );
            }

            if (!HasEncodableBerLength(parameters) || !HasEncodableBerLength(token))
            {
                return Result.Failure<InstallForManagementCommand, SmartCardError>(
                    InvalidBerLength("Parameters or Token")
                );
            }

            // GP Card Specification v2.3.1, Table 11-46.
            var data = BuildLvData(
                securityDomain,
                ImmutableArray<byte>.Empty,
                application,
                privilegeBytes,
                ToImmutableByteArray(parameters),
                ToImmutableByteArray(token)
            );

            return Result.Success<InstallForManagementCommand, SmartCardError>(
                new InstallForManagementCommand(
                    InstallType.ForRegistryUpdate,
                    application,
                    data,
                    moreCommands
                )
            );
        }

        /// <summary>
        /// Creates INSTALL [for personalization].
        /// </summary>
        public static Result<InstallForManagementCommand, SmartCardError> CreateForPersonalization(
            byte[] applicationAid,
            bool moreCommands = false
        )
        {
            var aidResult = ValidateRequiredAid(applicationAid, "Application AID");
            if (aidResult.IsFailure)
            {
                return Result.Failure<InstallForManagementCommand, SmartCardError>(aidResult.Error);
            }

            // GP Card Specification v2.3.1, Table 11-47.
            var data = BuildLvData(
                ImmutableArray<byte>.Empty,
                ImmutableArray<byte>.Empty,
                aidResult.Value,
                ImmutableArray<byte>.Empty,
                ImmutableArray<byte>.Empty,
                ImmutableArray<byte>.Empty
            );

            return Result.Success<InstallForManagementCommand, SmartCardError>(
                new InstallForManagementCommand(
                    InstallType.ForPersonalization,
                    aidResult.Value,
                    data,
                    moreCommands
                )
            );
        }

        /// <inheritdoc/>
        public override Result<CommandAPDU, SmartCardError> ToCommandApdu()
        {
            return Result.Success<CommandAPDU, SmartCardError>(
                new CommandAPDU(COMMAND_CLA, COMMAND_INS, P1, P2, (uint)Data.Length, Data)
            );
        }

        /// <inheritdoc/>
        public override string ToString() => $"INSTALL [{Type}]";

        private static ImmutableArray<byte> BuildLvData(params ImmutableArray<byte>[] fields)
        {
            var bytes = ImmutableArray.CreateBuilder<byte>();
            for (int index = 0; index < fields.Length; index++)
            {
                var field = fields[index];
                if (index < 4)
                {
                    bytes.Add((byte)field.Length);
                }
                else
                {
                    bytes.AddRange(GlobalPlatformLengthEncoding.EncodeBerLength(field.Length));
                }
                bytes.AddRange(field);
            }

            return bytes.ToImmutable();
        }

        private static Result<ImmutableArray<byte>, SmartCardError> ValidateRequiredAid(
            byte[] aid,
            string name
        )
        {
            if (aid is null || aid.Length is < 5 or > 16)
            {
                return Result.Failure<ImmutableArray<byte>, SmartCardError>(
                    SmartCardError.InvalidArgument(
                        $"{name} must contain five through sixteen bytes."
                    )
                );
            }

            return Result.Success<ImmutableArray<byte>, SmartCardError>([.. aid]);
        }

        private static bool IsOptionalAidValid(ImmutableArray<byte> aid) =>
            aid.IsDefaultOrEmpty || aid.Length is >= 5 and <= 16;
    }
}

/// <summary>
/// Install operation types for P1 parameter.
/// </summary>
public enum InstallType : byte
{
    /// <summary>
    /// INSTALL [for load] - prepares card to receive a load file.
    /// </summary>
    ForLoad = 0x02,

    /// <summary>
    /// INSTALL [for install] - instantiates an applet.
    /// </summary>
    ForInstall = 0x04,

    /// <summary>
    /// INSTALL [for make selectable] - makes an applet selectable.
    /// </summary>
    ForMakeSelectable = 0x08,

    /// <summary>
    /// INSTALL [for install and make selectable] - combines install and make selectable.
    /// </summary>
    ForInstallAndMakeSelectable = 0x0C,

    /// <summary>
    /// INSTALL [for load, install and make selectable].
    /// </summary>
    ForLoadInstallAndMakeSelectable = 0x0E,

    /// <summary>
    /// INSTALL [for extradition].
    /// </summary>
    ForExtradition = 0x10,

    /// <summary>
    /// INSTALL [for personalization].
    /// </summary>
    ForPersonalization = 0x20,

    /// <summary>
    /// INSTALL [for registry update].
    /// </summary>
    ForRegistryUpdate = 0x40,
}

/// <summary>
/// INSTALL P2 values for combined operations.
/// </summary>
public enum InstallSequence : byte
{
    /// <summary>No combined-operation information.</summary>
    NoInformation = 0x00,

    /// <summary>Beginning of a combined operation.</summary>
    BeginCombinedOperation = 0x01,

    /// <summary>End of a combined operation.</summary>
    EndCombinedOperation = 0x03,
}

/// <summary>
/// Builder for creating InstallCommand instances with functional error handling.
/// </summary>
[PublicAPI]
public static class InstallCommandBuilder
{
    /// <summary>
    /// Creates an INSTALL [for load] command.
    /// </summary>
    /// <param name="packageAid">The package AID.</param>
    /// <param name="securityDomainAid">Optional security domain AID.</param>
    /// <param name="hash">Optional hash of the load file.</param>
    /// <param name="loadParameters">Optional Load Parameters TLVs.</param>
    /// <param name="installToken">Optional install token.</param>
    /// <returns>A Result containing the command or an error.</returns>
    public static Result<InstallCommand.InstallForLoadCommand, SmartCardError> CreateForLoad(
        byte[] packageAid,
        Maybe<byte[]> securityDomainAid = default,
        Maybe<byte[]> hash = default,
        Maybe<byte[]> loadParameters = default,
        Maybe<byte[]> installToken = default
    )
    {
        return InstallCommand.InstallForLoadCommand.Create(
            packageAid,
            loadParameters,
            securityDomainAid,
            hash,
            installToken
        );
    }

    /// <summary>
    /// Creates an INSTALL [for install] command.
    /// </summary>
    /// <param name="packageAid">The package AID.</param>
    /// <param name="appletAid">The applet AID.</param>
    /// <param name="moduleAid">The module AID (defaults to package AID if null).</param>
    /// <param name="privileges">The privileges (defaults to 0x00 if null).</param>
    /// <param name="installParameters">Optional install parameters.</param>
    /// <param name="installToken">Optional install token.</param>
    /// <returns>A Result containing the command or an error.</returns>
    public static Result<InstallCommand.InstallForInstallCommand, SmartCardError> CreateForInstall(
        byte[] packageAid,
        byte[] appletAid,
        Maybe<byte[]> moduleAid = default,
        Maybe<byte[]> privileges = default,
        Maybe<byte[]> installParameters = default,
        Maybe<byte[]> installToken = default
    )
    {
        byte[] resolvedModuleAid = moduleAid.Match(value => value, () => packageAid);
        byte[] resolvedPrivileges = privileges.Match(value => value, () => new byte[] { 0x00 });

        return InstallCommand.InstallForInstallCommand.Create(
            packageAid,
            resolvedModuleAid,
            appletAid,
            resolvedPrivileges,
            installParameters,
            installToken
        );
    }

    /// <summary>
    /// Creates an INSTALL [for install and make selectable] command.
    /// </summary>
    /// <param name="packageAid">The package AID.</param>
    /// <param name="appletAid">The applet AID.</param>
    /// <param name="moduleAid">The module AID (defaults to package AID if null).</param>
    /// <param name="privileges">The privileges (defaults to 0x00 if null).</param>
    /// <param name="installParameters">Optional install parameters.</param>
    /// <param name="installToken">Optional install token.</param>
    /// <returns>A Result containing the command or an error.</returns>
    public static Result<
        InstallCommand.InstallForInstallCommand,
        SmartCardError
    > CreateForInstallAndMakeSelectable(
        byte[] packageAid,
        byte[] appletAid,
        Maybe<byte[]> moduleAid = default,
        Maybe<byte[]> privileges = default,
        Maybe<byte[]> installParameters = default,
        Maybe<byte[]> installToken = default
    )
    {
        byte[] resolvedModuleAid = moduleAid.Match(value => value, () => packageAid);
        byte[] resolvedPrivileges = privileges.Match(value => value, () => new byte[] { 0x00 });

        return InstallCommand.InstallForInstallCommand.CreateAndMakeSelectable(
            packageAid,
            resolvedModuleAid,
            appletAid,
            resolvedPrivileges,
            installParameters,
            installToken
        );
    }
}

/// <summary>
/// Represents the response to an INSTALL APDU command.
/// </summary>
[PublicAPI]
public record InstallCommandResponse(ImmutableArray<byte> Data, StatusWord StatusWord)
{
    /// <summary>
    /// Gets a value indicating whether the install was successful.
    /// </summary>
    public bool IsSuccess
    {
        get { return StatusWord == Constants.Constants.StatusWords.Legacy.Success; }
    }

    /// <summary>
    /// Creates a successful response.
    /// </summary>
    public static InstallCommandResponse Success(Maybe<byte[]> data = default) =>
        new(
            data.Match(bytes => bytes.ToImmutableArray(), () => ImmutableArray<byte>.Empty),
            Constants.Constants.StatusWords.Legacy.Success
        );

    /// <summary>
    /// Creates a failed response.
    /// </summary>
    public static InstallCommandResponse Failure(ushort statusWord, Maybe<byte[]> data = default) =>
        new(
            data.Match(bytes => bytes.ToImmutableArray(), () => ImmutableArray<byte>.Empty),
            statusWord
        );

    /// <summary>
    /// Parses a response from raw data.
    /// </summary>
    public static InstallCommandResponse Parse(byte[] responseData, ushort statusWord)
    {
        return new([.. responseData], statusWord);
    }
}
