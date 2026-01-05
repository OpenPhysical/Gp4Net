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

    /// <inheritdoc/>
    public byte P1
    {
        get { return (byte)Type; }
    }

    /// <inheritdoc/>
    public byte P2
    {
        get { return 0x00; }
    }

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
    private protected InstallCommand(ImmutableArray<byte> packageAid)
    {
        PackageAid = packageAid;
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

    /// <summary>
    /// INSTALL [for load] command implementation.
    /// </summary>
    public sealed record InstallForLoadCommand : InstallCommand
    {
        /// <inheritdoc/>
        public override InstallType Type
        {
            get { return InstallType.ForLoad; }
        }

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
            ImmutableArray<byte> packageAid,
            ImmutableArray<byte> securityDomainAid,
            ImmutableArray<byte> hash,
            ImmutableArray<byte> loadParameters,
            ImmutableArray<byte> installToken
        )
            : base(packageAid)
        {
            SecurityDomainAid = securityDomainAid;
            Hash = hash;
            LoadParameters = loadParameters;
            InstallToken = installToken;
        }

        /// <summary>
        /// Creates a new INSTALL [for load] command with validation.
        /// </summary>
        /// <param name="packageAid">The package AID.</param>
        /// <param name="maxDataBlockSize">Optional maximum data block size parameter.</param>
        /// <param name="securityDomainAid">Optional security domain AID.</param>
        /// <param name="hash">Optional hash of the load file.</param>
        /// <param name="installToken">Optional install token.</param>
        /// <returns>A Result containing the command or an error.</returns>
        public static Result<InstallForLoadCommand, SmartCardError> Create(
            byte[] packageAid,
            Maybe<ushort> maxDataBlockSize = default,
            Maybe<byte[]> securityDomainAid = default,
            Maybe<byte[]> hash = default,
            Maybe<byte[]> installToken = default
        )
        {
            var packageAidResult = ValidatePackageAid(packageAid);
            if (packageAidResult.IsFailure)
            {
                return Result.Failure<InstallForLoadCommand, SmartCardError>(
                    packageAidResult.Error
                );
            }

            // Convert maxDataBlockSize to load parameters if provided
            Maybe<byte[]> loadParameters = maxDataBlockSize.Map(size => new byte[]
            {
                0xC9,
                0x02,
                (byte)(size >> 8),
                (byte)(size & 0xFF),
            });

            var command = new InstallForLoadCommand(
                packageAidResult.Value,
                ToImmutableByteArray(securityDomainAid),
                ToImmutableByteArray(hash),
                ToImmutableByteArray(loadParameters),
                ToImmutableByteArray(installToken)
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
                builder.Add((byte)LoadParameters.Length);
                builder.AddRange(LoadParameters);
            }
            else
            {
                builder.Add(0x00);
            }

            // Install Token
            if (!InstallToken.IsDefaultOrEmpty)
            {
                builder.Add((byte)InstallToken.Length);
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
                new CommandAPDU(
                    COMMAND_CLA,
                    COMMAND_INS,
                    (byte)InstallType.ForLoad,
                    0x00,
                    (uint)Data.Length,
                    Data
                )
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
            ImmutableArray<byte> installToken
        )
            : base(packageAid)
        {
            Type = type;
            AppletAid = appletAid;
            ModuleAid = moduleAid;
            Privileges = privileges.IsDefaultOrEmpty ? [0x00] : privileges;
            InstallParameters = installParameters;
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
        /// <returns>A Result containing the command or an error.</returns>
        public static Result<InstallForInstallCommand, SmartCardError> Create(
            byte[] packageAid,
            byte[] moduleAid,
            byte[] applicationAid,
            byte[] privileges,
            Maybe<byte[]> installParameters = default,
            Maybe<byte[]> installToken = default
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
                InstallType.ForInstall,
                packageAidResult.Value,
                [.. applicationAid],
                [.. moduleAid],
                [.. privileges],
                ToImmutableByteArray(installParameters),
                ToImmutableByteArray(installToken)
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
        /// <returns>A Result containing the command or an error.</returns>
        public static Result<InstallForInstallCommand, SmartCardError> CreateAndMakeSelectable(
            byte[] packageAid,
            byte[] moduleAid,
            byte[] applicationAid,
            byte[] privileges,
            Maybe<byte[]> installParameters = default,
            Maybe<byte[]> installToken = default
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
                ToImmutableByteArray(installToken)
            );

            return Result.Success<InstallForInstallCommand, SmartCardError>(command);
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
                builder.Add((byte)InstallParameters.Length);
                builder.AddRange(InstallParameters);
            }
            else
            {
                builder.Add(0x00);
            }

            // Install Token
            if (!InstallToken.IsDefaultOrEmpty)
            {
                builder.Add((byte)InstallToken.Length);
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
                new CommandAPDU(COMMAND_CLA, COMMAND_INS, (byte)Type, 0x00, (uint)Data.Length, Data)
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
    /// <param name="maxDataBlockSize">Optional maximum data block size.</param>
    /// <param name="installToken">Optional install token.</param>
    /// <returns>A Result containing the command or an error.</returns>
    public static Result<InstallCommand.InstallForLoadCommand, SmartCardError> CreateForLoad(
        byte[] packageAid,
        Maybe<byte[]> securityDomainAid = default,
        Maybe<byte[]> hash = default,
        Maybe<ushort> maxDataBlockSize = default,
        Maybe<byte[]> installToken = default
    )
    {
        return InstallCommand.InstallForLoadCommand.Create(
            packageAid,
            maxDataBlockSize,
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
    public static InstallCommandResponse Failure(
        ushort statusWord,
        Maybe<byte[]> data = default
    ) =>
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
