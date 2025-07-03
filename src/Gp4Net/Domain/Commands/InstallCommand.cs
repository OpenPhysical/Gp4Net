using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Commands
{
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
        public const byte CommandCla = 0x80;

        /// <summary>
        /// The command instruction byte.
        /// </summary>
        public const byte CommandIns = 0xE6;

        /// <summary>
        /// Gets the install type.
        /// </summary>
        public abstract InstallType Type { get; }

        /// <summary>
        /// Gets the package AID.
        /// </summary>
        public ImmutableArray<byte> PackageAid { get; }

        /// <inheritdoc/>
        public byte Cla => CommandCla;

        /// <inheritdoc/>
        public byte Ins => CommandIns;

        /// <inheritdoc/>
        public byte P1 => (byte)Type;

        /// <inheritdoc/>
        public byte P2 => 0x00;

        /// <inheritdoc/>
        public abstract byte[] Data { get; }

        /// <inheritdoc/>
        public int? ExpectedResponseLength => 0; // Le=00 for INSTALL commands

        /// <inheritdoc/>
        public bool IsExtendedLength => false;

        /// <summary>
        /// Base constructor for InstallCommand.
        /// </summary>
        protected InstallCommand(ImmutableArray<byte> packageAid)
        {
            if (packageAid.IsDefaultOrEmpty)
                throw new ArgumentException("Package AID cannot be empty.", nameof(packageAid));

            PackageAid = packageAid;
        }

        /// <summary>
        /// INSTALL [for load] command implementation.
        /// </summary>
        public sealed record InstallForLoadCommand : InstallCommand
        {
            /// <inheritdoc/>
            public override InstallType Type => InstallType.ForLoad;

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
            public InstallForLoadCommand(
                ImmutableArray<byte> packageAid,
                ImmutableArray<byte> securityDomainAid = default,
                ImmutableArray<byte> hash = default,
                ImmutableArray<byte> loadParameters = default,
                ImmutableArray<byte> installToken = default)
                : base(packageAid)
            {
                SecurityDomainAid = securityDomainAid;
                Hash = hash;
                LoadParameters = loadParameters;
                InstallToken = installToken;
            }

            /// <inheritdoc/>
            public override byte[] Data => BuildData();

            private byte[] BuildData()
            {
                var builder = new List<byte>();

                // Package AID
                builder.Add((byte)PackageAid.Length);
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

                return builder.ToArray();
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
            public InstallForInstallCommand(
                InstallType type,
                ImmutableArray<byte> packageAid,
                ImmutableArray<byte> appletAid,
                ImmutableArray<byte> moduleAid = default,
                ImmutableArray<byte> privileges = default,
                ImmutableArray<byte> installParameters = default,
                ImmutableArray<byte> installToken = default)
                : base(packageAid)
            {
                if (type == InstallType.ForLoad)
                    throw new ArgumentException("Use InstallForLoadCommand for INSTALL [for load].", nameof(type));

                if (appletAid.IsDefaultOrEmpty)
                    throw new ArgumentException("Applet AID cannot be empty.", nameof(appletAid));

                Type = type;
                AppletAid = appletAid;
                ModuleAid = moduleAid;
                Privileges = privileges.IsDefaultOrEmpty ? ImmutableArray.Create<byte>(0x00) : privileges;
                InstallParameters = installParameters;
                InstallToken = installToken;
            }

            /// <inheritdoc/>
            public override byte[] Data => BuildData();

            private byte[] BuildData()
            {
                var builder = new List<byte>();

                // Package AID
                builder.Add((byte)PackageAid.Length);
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

                return builder.ToArray();
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
    /// Builder for creating InstallCommand instances.
    /// </summary>
    [PublicAPI]
    public static class InstallCommandBuilder
    {
        /// <summary>
        /// Creates an INSTALL [for load] command.
        /// </summary>
        public static InstallCommand.InstallForLoadCommand CreateForLoad(
            byte[] packageAid,
            byte[]? securityDomainAid = null,
            byte[]? hash = null,
            byte[]? loadParameters = null,
            byte[]? installToken = null)
        {
            return new InstallCommand.InstallForLoadCommand(
                packageAid.ToImmutableArray(),
                securityDomainAid?.ToImmutableArray() ?? default,
                hash?.ToImmutableArray() ?? default,
                loadParameters?.ToImmutableArray() ?? default,
                installToken?.ToImmutableArray() ?? default);
        }

        /// <summary>
        /// Creates an INSTALL [for install] command.
        /// </summary>
        public static InstallCommand.InstallForInstallCommand CreateForInstall(
            byte[] packageAid,
            byte[] appletAid,
            byte[]? moduleAid = null,
            byte[]? privileges = null,
            byte[]? installParameters = null,
            byte[]? installToken = null)
        {
            return new InstallCommand.InstallForInstallCommand(
                InstallType.ForInstall,
                packageAid.ToImmutableArray(),
                appletAid.ToImmutableArray(),
                moduleAid?.ToImmutableArray() ?? default,
                privileges?.ToImmutableArray() ?? default,
                installParameters?.ToImmutableArray() ?? default,
                installToken?.ToImmutableArray() ?? default);
        }

        /// <summary>
        /// Creates an INSTALL [for install and make selectable] command.
        /// </summary>
        public static InstallCommand.InstallForInstallCommand CreateForInstallAndMakeSelectable(
            byte[] packageAid,
            byte[] appletAid,
            byte[]? moduleAid = null,
            byte[]? privileges = null,
            byte[]? installParameters = null,
            byte[]? installToken = null)
        {
            return new InstallCommand.InstallForInstallCommand(
                InstallType.ForInstallAndMakeSelectable,
                packageAid.ToImmutableArray(),
                appletAid.ToImmutableArray(),
                moduleAid?.ToImmutableArray() ?? default,
                privileges?.ToImmutableArray() ?? default,
                installParameters?.ToImmutableArray() ?? default,
                installToken?.ToImmutableArray() ?? default);
        }
    }

    /// <summary>
    /// Represents the response to an INSTALL APDU command.
    /// </summary>
    [PublicAPI]
    public record InstallCommandResponse(
        ImmutableArray<byte> Data,
        ushort StatusWord)
    {
        /// <summary>
        /// Gets a value indicating whether the install was successful.
        /// </summary>
        public bool IsSuccess => StatusWord == 0x9000;

        /// <summary>
        /// Creates a successful response.
        /// </summary>
        public static InstallCommandResponse Success(byte[]? data = null) =>
            new(data?.ToImmutableArray() ?? ImmutableArray<byte>.Empty, 0x9000);

        /// <summary>
        /// Creates a failed response.
        /// </summary>
        public static InstallCommandResponse Failure(ushort statusWord, byte[]? data = null) =>
            new(data?.ToImmutableArray() ?? ImmutableArray<byte>.Empty, statusWord);

        /// <summary>
        /// Parses a response from raw data.
        /// </summary>
        public static InstallCommandResponse Parse(byte[] responseData, ushort statusWord) =>
            new(responseData.ToImmutableArray(), statusWord);
    }
}