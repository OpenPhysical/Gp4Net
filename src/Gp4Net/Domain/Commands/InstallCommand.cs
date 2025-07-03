using System;
using System.Collections.Generic;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Commands
{
    /// <summary>
    /// Represents the INSTALL command for loading and installing applications.
    /// Supports INSTALL [for load] and INSTALL [for install] operations.
    /// </summary>
    [PublicAPI]
    public class InstallCommand : IApduCommand
    {
        /// <summary>
        /// The command class byte.
        /// </summary>
        public const byte Cla = 0x80;

        /// <summary>
        /// The command instruction byte.
        /// </summary>
        public const byte Ins = 0xE6;

        /// <summary>
        /// Install operation types for P1 parameter.
        /// </summary>
        public enum InstallType : byte
        {
            /// <summary>
            /// INSTALL [for load] - prepares card to receive a load file.
            /// </summary>
            ForLoad = 0x04,

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
        /// Gets the install type.
        /// </summary>
        public InstallType Type { get; }

        /// <summary>
        /// Gets the package AID.
        /// </summary>
        public byte[] PackageAid { get; }

        /// <summary>
        /// Gets the security domain AID (optional).
        /// </summary>
        public byte[]? SecurityDomainAid { get; }

        /// <summary>
        /// Gets the hash of the load file (optional).
        /// </summary>
        public byte[]? Hash { get; }

        /// <summary>
        /// Gets the install token (optional).
        /// </summary>
        public byte[]? InstallToken { get; }

        /// <summary>
        /// Gets the module AID (for install operations).
        /// </summary>
        public byte[]? ModuleAid { get; }

        /// <summary>
        /// Gets the applet AID (for install operations).
        /// </summary>
        public byte[]? AppletAid { get; }

        /// <summary>
        /// Gets the privileges (for install operations).
        /// </summary>
        public byte[]? Privileges { get; }

        /// <summary>
        /// Gets the install parameters (for install operations).
        /// </summary>
        public byte[]? InstallParameters { get; }

        /// <summary>
        /// Gets the class byte.
        /// </summary>
        byte IApduCommand.Cla => Cla;

        /// <summary>
        /// Gets the instruction byte.
        /// </summary>
        byte IApduCommand.Ins => Ins;

        /// <summary>
        /// Gets the parameter 1 byte.
        /// </summary>
        public byte P1 => (byte)Type;

        /// <summary>
        /// Gets the parameter 2 byte.
        /// </summary>
        public byte P2 => 0x00;

        /// <summary>
        /// Gets the command data.
        /// </summary>
        public byte[]? Data => GetInstallData();

        /// <summary>
        /// Gets the expected response length.
        /// </summary>
        public int? ExpectedResponseLength => null;

        /// <summary>
        /// Gets whether this command uses extended length.
        /// </summary>
        public bool IsExtendedLength => false;

        /// <summary>
        /// Gets the install data for the IApduCommand interface.
        /// </summary>
        private byte[] GetInstallData()
        {
            var data = new List<byte>
            {
                // Add package AID
                (byte)PackageAid.Length
            };
            data.AddRange(PackageAid);

            // Add security domain AID (or zero length if null)
            if (SecurityDomainAid != null)
            {
                data.Add((byte)SecurityDomainAid.Length);
                data.AddRange(SecurityDomainAid);
            }
            else
            {
                data.Add(0x00);
            }

            // Add hash (or zero length if null)
            if (Hash != null)
            {
                data.Add((byte)Hash.Length);
                data.AddRange(Hash);
            }
            else
            {
                data.Add(0x00);
            }

            // Add install token (or zero length if null)
            if (InstallToken != null)
            {
                data.Add((byte)InstallToken.Length);
                data.AddRange(InstallToken);
            }
            else
            {
                data.Add(0x00);
            }

            // For install operations, add additional fields
            if (Type == InstallType.ForInstall)
            {
                // Add module AID
                if (ModuleAid != null)
                {
                    data.Add((byte)ModuleAid.Length);
                    data.AddRange(ModuleAid);
                }
                else
                {
                    data.Add(0x00);
                }

                // Add applet AID
                if (AppletAid != null)
                {
                    data.Add((byte)AppletAid.Length);
                    data.AddRange(AppletAid);
                }
                else
                {
                    data.Add(0x00);
                }

                // Add privileges
                if (Privileges != null)
                {
                    data.Add((byte)Privileges.Length);
                    data.AddRange(Privileges);
                }
                else
                {
                    data.Add(0x00);
                }

                // Add install parameters
                if (InstallParameters != null)
                {
                    data.Add((byte)InstallParameters.Length);
                    data.AddRange(InstallParameters);
                }
                else
                {
                    data.Add(0x00);
                }
            }

            return [.. data];
        }

        /// <summary>
        /// Initializes a new instance of the InstallCommand class for INSTALL [for load].
        /// </summary>
        /// <param name="packageAid">The package AID.</param>
        /// <param name="securityDomainAid">The security domain AID (optional).</param>
        /// <param name="hash">The hash of the load file (optional).</param>
        /// <param name="installToken">The install token (optional).</param>
        public InstallCommand(
            byte[] packageAid,
            byte[]? securityDomainAid = null,
            byte[]? hash = null,
            byte[]? installToken = null
        )
        {
            ArgumentNullException.ThrowIfNull(packageAid);

            if (packageAid.Length == 0)
            {
                throw new ArgumentException("Package AID cannot be empty.", nameof(packageAid));
            }

            Type = InstallType.ForLoad;
            PackageAid = (byte[])packageAid.Clone();
            SecurityDomainAid = securityDomainAid?.Clone() as byte[];
            Hash = hash?.Clone() as byte[];
            InstallToken = installToken?.Clone() as byte[];
        }

        /// <summary>
        /// Initializes a new instance of the InstallCommand class for INSTALL [for install].
        /// </summary>
        /// <param name="type">The install type (ForInstall, ForMakeSelectable, or ForInstallAndMakeSelectable).</param>
        /// <param name="packageAid">The package AID.</param>
        /// <param name="appletAid">The applet AID.</param>
        /// <param name="moduleAid">The module AID (optional).</param>
        /// <param name="privileges">The privileges (optional).</param>
        /// <param name="installParameters">The install parameters (optional).</param>
        /// <param name="installToken">The install token (optional).</param>
        public InstallCommand(
            InstallType type,
            byte[] packageAid,
            byte[] appletAid,
            byte[]? moduleAid = null,
            byte[]? privileges = null,
            byte[]? installParameters = null,
            byte[]? installToken = null
        )
        {
            ArgumentNullException.ThrowIfNull(packageAid);

            ArgumentNullException.ThrowIfNull(appletAid);

            if (packageAid.Length == 0)
            {
                throw new ArgumentException("Package AID cannot be empty.", nameof(packageAid));
            }

            if (appletAid.Length == 0)
            {
                throw new ArgumentException("Applet AID cannot be empty.", nameof(appletAid));
            }

            if (type == InstallType.ForLoad)
            {
                throw new ArgumentException(
                    "Use the other constructor for INSTALL [for load].",
                    nameof(type)
                );
            }

            Type = type;
            PackageAid = (byte[])packageAid.Clone();
            AppletAid = (byte[])appletAid.Clone();
            ModuleAid = moduleAid?.Clone() as byte[];
            Privileges = privileges?.Clone() as byte[];
            InstallParameters = installParameters?.Clone() as byte[];
            InstallToken = installToken?.Clone() as byte[];
        }

        /// <summary>
        /// Creates an INSTALL [for load] command.
        /// </summary>
        /// <param name="packageAid">The package AID.</param>
        /// <param name="securityDomainAid">The security domain AID (optional).</param>
        /// <param name="hash">The hash of the load file (optional).</param>
        /// <param name="installToken">The install token (optional).</param>
        /// <returns>A new InstallCommand for load operation.</returns>
        public static InstallCommand CreateForLoad(
            byte[] packageAid,
            byte[]? securityDomainAid = null,
            byte[]? hash = null,
            byte[]? installToken = null
        )
        {
            return new InstallCommand(packageAid, securityDomainAid, hash, installToken);
        }

        /// <summary>
        /// Creates an INSTALL [for install] command.
        /// </summary>
        /// <param name="packageAid">The package AID.</param>
        /// <param name="appletAid">The applet AID.</param>
        /// <param name="moduleAid">The module AID (optional).</param>
        /// <param name="privileges">The privileges (optional, defaults to no privileges).</param>
        /// <param name="installParameters">The install parameters (optional).</param>
        /// <param name="installToken">The install token (optional).</param>
        /// <returns>A new InstallCommand for install operation.</returns>
        public static InstallCommand CreateForInstall(
            byte[] packageAid,
            byte[] appletAid,
            byte[]? moduleAid = null,
            byte[]? privileges = null,
            byte[]? installParameters = null,
            byte[]? installToken = null
        )
        {
            return new InstallCommand(
                InstallType.ForInstall,
                packageAid,
                appletAid,
                moduleAid,
                privileges ?? new byte[] { 0x00 }, // Default to no privileges
                installParameters,
                installToken
            );
        }

        /// <summary>
        /// Creates an INSTALL [for install and make selectable] command.
        /// </summary>
        /// <param name="packageAid">The package AID.</param>
        /// <param name="appletAid">The applet AID.</param>
        /// <param name="moduleAid">The module AID (optional).</param>
        /// <param name="privileges">The privileges (optional, defaults to no privileges).</param>
        /// <param name="installParameters">The install parameters (optional).</param>
        /// <param name="installToken">The install token (optional).</param>
        /// <returns>A new InstallCommand for install and make selectable operation.</returns>
        public static InstallCommand CreateForInstallAndMakeSelectable(
            byte[] packageAid,
            byte[] appletAid,
            byte[]? moduleAid = null,
            byte[]? privileges = null,
            byte[]? installParameters = null,
            byte[]? installToken = null
        )
        {
            return new InstallCommand(
                InstallType.ForInstallAndMakeSelectable,
                packageAid,
                appletAid,
                moduleAid,
                privileges ?? new byte[] { 0x00 }, // Default to no privileges
                installParameters,
                installToken
            );
        }

        /// <summary>
        /// Converts this command to an APDU byte array.
        /// </summary>
        /// <returns>The APDU command bytes.</returns>
        public byte[] ToApdu()
        {
            var data = new List<byte>();

            if (Type == InstallType.ForLoad)
            {
                // INSTALL [for load] data format:
                // <Len(PkgAID)> <PkgAID>
                // <Len(SecurityDomainAID)> <SD_AID or 00>
                // <Len(Hash)> <Hash> ; or 00
                // <Len(InstallToken)> <Token> ; or 00

                // Package AID
                data.Add((byte)PackageAid.Length);
                data.AddRange(PackageAid);

                // Security Domain AID
                if (SecurityDomainAid != null && SecurityDomainAid.Length > 0)
                {
                    data.Add((byte)SecurityDomainAid.Length);
                    data.AddRange(SecurityDomainAid);
                }
                else
                {
                    data.Add(0x00);
                }

                // Hash
                if (Hash != null && Hash.Length > 0)
                {
                    data.Add((byte)Hash.Length);
                    data.AddRange(Hash);
                }
                else
                {
                    data.Add(0x00);
                }

                // Install Token
                if (InstallToken != null && InstallToken.Length > 0)
                {
                    data.Add((byte)InstallToken.Length);
                    data.AddRange(InstallToken);
                }
                else
                {
                    data.Add(0x00);
                }
            }
            else
            {
                // INSTALL [for install] data format:
                // <Len(PkgAID)> <PkgAID>
                // <Len(ModuleAID)> <ModuleAID> ; often 00
                // <Len(AppletAID)> <AppletAID>
                // <Len(Privileges)> <PrivBytes> ; typically 01 00
                // <Len(InstallParams)> <TLV or raw> ; e.g., C9 00 or 00
                // <Len(InstallToken)> <Token> ; or 00

                // Package AID
                data.Add((byte)PackageAid.Length);
                data.AddRange(PackageAid);

                // Module AID
                if (ModuleAid != null && ModuleAid.Length > 0)
                {
                    data.Add((byte)ModuleAid.Length);
                    data.AddRange(ModuleAid);
                }
                else
                {
                    data.Add(0x00);
                }

                // Applet AID
                data.Add((byte)AppletAid!.Length);
                data.AddRange(AppletAid);

                // Privileges
                if (Privileges != null && Privileges.Length > 0)
                {
                    data.Add((byte)Privileges.Length);
                    data.AddRange(Privileges);
                }
                else
                {
                    data.Add(0x01);
                    data.Add(0x00); // No privileges
                }

                // Install Parameters
                if (InstallParameters != null && InstallParameters.Length > 0)
                {
                    data.Add((byte)InstallParameters.Length);
                    data.AddRange(InstallParameters);
                }
                else
                {
                    data.Add(0x00);
                }

                // Install Token
                if (InstallToken != null && InstallToken.Length > 0)
                {
                    data.Add((byte)InstallToken.Length);
                    data.AddRange(InstallToken);
                }
                else
                {
                    data.Add(0x00);
                }
            }

            // Build APDU
            var apdu = new List<byte>
            {
                Cla,
                Ins,
                (byte)Type,
                0x00, // P2
                (byte)data.Count, // Lc
            };

            apdu.AddRange(data);
            apdu.Add(0x00); // Le

            return [.. apdu];
        }
    }

    /// <summary>
    /// Represents the response to an INSTALL command.
    /// </summary>
    [PublicAPI]
    public class InstallResponse
    {
        /// <summary>
        /// Gets the response data (if any).
        /// </summary>
        public byte[] Data { get; }

        /// <summary>
        /// Gets a value indicating whether the install was successful.
        /// </summary>
        public bool IsSuccessful { get; }

        /// <summary>
        /// Initializes a new instance of the InstallResponse class.
        /// </summary>
        /// <param name="data">The response data.</param>
        /// <param name="isSuccessful">Whether the install was successful.</param>
        public InstallResponse(byte[] data, bool isSuccessful = true)
        {
            Data = (byte[])data.Clone();
            IsSuccessful = isSuccessful;
        }

        /// <summary>
        /// Parses an INSTALL response.
        /// </summary>
        /// <param name="response">The response data (excluding status word).</param>
        /// <param name="statusWord">The status word from the response.</param>
        /// <returns>The parsed response.</returns>
        public static InstallResponse Parse(byte[] response, ushort statusWord)
        {
            var isSuccessful = statusWord == 0x9000;
            return new InstallResponse(response ?? Array.Empty<byte>(), isSuccessful);
        }
    }
}
