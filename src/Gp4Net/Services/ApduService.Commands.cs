using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Transport;
using static Gp4Net.Constants.Constants;

namespace Gp4Net.Services;

public static partial class ApduService
{
    /// <summary>
    /// Command building operations consolidating ApduFactory + ApduBuilder + Extensions.
    /// REPLACES 28+ duplicate APDU building sites across the codebase.
    /// All methods are functionally pure and return Result&lt;T, SmartCardError&gt;.
    /// </summary>
    public static class Commands
    {
        /// <summary>
        /// Creates SELECT command per ISO 7816-4 and GP Card Specification.
        /// </summary>
        /// <param name="aid">Application Identifier to select (5-16 bytes). Empty for ISD selection.</param>
        /// <param name="selectionControl">Selection control options.</param>
        /// <param name="fileControlInformation">File control information format.</param>
        /// <returns>SELECT command or error.</returns>
        public static Result<IApduCommand, SmartCardError> CreateSelect(
            ImmutableArray<byte> aid,
            SelectCommand.SelectionControl selectionControl = SelectCommand.SelectionControl.SelectByName,
            SelectCommand.FileControlInfo fileControlInformation = SelectCommand.FileControlInfo.ReturnFci)
        {
            if (aid.Length > 16)
            {
                return Result.Failure<IApduCommand, SmartCardError>(
                    SmartCardError.InvalidArgument("AID cannot exceed 16 bytes"));
            }

            byte p1 = (byte)selectionControl;
            byte p2 = (byte)fileControlInformation;

            return Result.Success<IApduCommand, SmartCardError>(
                new UnifiedApduCommand(
                    Apdu.Classes.Standard,
                    Apdu.Instructions.Select,
                    p1,
                    p2,
                    aid.ToArray(),
                    Maybe<int>.From(0)
                )
            );
        }

        /// <summary>
        /// Creates INITIALIZE UPDATE command for SCP establishment.
        /// Per GP Card Specification Section 11.3.
        /// </summary>
        /// <param name="keyVersion">Key version number (0x00 for default).</param>
        /// <param name="keyId">Key identifier (0x00 for default).</param>
        /// <param name="hostChallenge">8-byte host challenge.</param>
        /// <returns>INITIALIZE UPDATE command or error.</returns>
        public static Result<IApduCommand, SmartCardError> CreateInitializeUpdate(
            byte keyVersion,
            byte keyId,
            Maybe<byte[]> hostChallenge)
        {
            return hostChallenge.Match(
                challenge => challenge.Length == 8
                    ? Result.Success<IApduCommand, SmartCardError>(
                        new UnifiedApduCommand(
         GlobalPlatform.Cla.GpStandard,
         GlobalPlatform.Ins.InitializeUpdate,
         keyVersion,
         keyId,
         challenge,
                            ExpectedResponseLength: Maybe<int>.From(0)
                        ))
                    : Result.Failure<IApduCommand, SmartCardError>(
                        SmartCardError.InvalidArgument("Host challenge must be exactly 8 bytes")),
                () => Result.Failure<IApduCommand, SmartCardError>(
                    SmartCardError.InvalidData("Host challenge is required"))
            );
        }

        /// <summary>
        /// Creates EXTERNAL AUTHENTICATE command for SCP establishment.
        /// Per GP Card Specification Section 11.4.
        /// </summary>
        /// <param name="securityLevel">Security level to establish.</param>
        /// <param name="hostCryptogram">Host cryptogram (8 bytes).</param>
        /// <param name="cardCryptogram">Optional card cryptogram for verification (8 bytes).</param>
        /// <returns>EXTERNAL AUTHENTICATE command or error.</returns>
        public static Result<IApduCommand, SmartCardError> CreateExternalAuthenticate(
            SecurityLevel securityLevel,
            Maybe<byte[]> hostCryptogram,
            Maybe<byte[]> cardCryptogram = default)
        {
            return hostCryptogram.Match(
                hostCrypto => hostCrypto.Length == 8
                    ? CreateExternalAuthenticateWithValidHostCryptogram(securityLevel, hostCrypto, cardCryptogram)
                    : Result.Failure<IApduCommand, SmartCardError>(
                        SmartCardError.InvalidArgument("Host cryptogram must be exactly 8 bytes")),
                () => Result.Failure<IApduCommand, SmartCardError>(
                    SmartCardError.InvalidData("Host cryptogram is required"))
            );
        }

        private static Result<IApduCommand, SmartCardError> CreateExternalAuthenticateWithValidHostCryptogram(
            SecurityLevel securityLevel,
            byte[] hostCryptogram,
            Maybe<byte[]> cardCryptogram)
        {
            byte[] data = cardCryptogram.Match(
                cardCrypto => cardCrypto.Length == 8
                    ? hostCryptogram.Concat(cardCrypto).ToArray()
                    : hostCryptogram,
                () => hostCryptogram
            );

            return Result.Success<IApduCommand, SmartCardError>(
                new UnifiedApduCommand(
 GlobalPlatform.Cla.GpStandard,
 Apdu.Instructions.ExternalAuthenticate,
 (byte)securityLevel,
 0x00,
 data
                )
            );
        }

        /// <summary>
        /// Creates GET STATUS command for retrieving card/application status.
        /// Per GP Card Specification Section 11.6.
        /// </summary>
        /// <param name="statusType">Type of status information to retrieve.</param>
        /// <param name="continuation">Continuation flag for paginated responses.</param>
        /// <returns>GET STATUS command or error.</returns>
        public static Result<IApduCommand, SmartCardError> CreateGetStatus(
            GetStatusCommand.StatusSubset statusType,
            byte continuation = 0x00)
        {
            return Result.Success<IApduCommand, SmartCardError>(
                new UnifiedApduCommand(
 GlobalPlatform.Cla.GpStandard,
 GlobalPlatform.Ins.GetStatus,
 (byte)statusType,
 (byte)continuation,
 [],
                    ExpectedResponseLength: Maybe<int>.From(0)
                )
            );
        }

        /// <summary>
        /// Creates GET DATA command for retrieving specific data objects.
        /// Per GP Card Specification Section 11.7.
        /// </summary>
        /// <param name="tag">Data object tag (2 bytes).</param>
        /// <returns>GET DATA command or error.</returns>
        public static Result<IApduCommand, SmartCardError> CreateGetData(ushort tag)
        {
            return Result.Success<IApduCommand, SmartCardError>(
                new UnifiedApduCommand(
 Apdu.Classes.Standard,
 GlobalPlatform.Ins.GetData,
 (byte)(tag >> 8),
 (byte)(tag & 0xFF),
 [],
                    ExpectedResponseLength: Maybe<int>.From(0)
                )
            );
        }

        /// <summary>
        /// Creates DELETE command for removing applications or packages.
        /// Per GP Card Specification Section 11.8.
        /// </summary>
        /// <param name="targetAid">AID of object to delete.</param>
        /// <param name="deleteRelated">Whether to delete related objects.</param>
        /// <returns>DELETE command or error.</returns>
        public static Result<IApduCommand, SmartCardError> CreateDelete(
            ImmutableArray<byte> targetAid,
            bool deleteRelated = false)
        {
            if (targetAid.IsDefaultOrEmpty || targetAid.Length > 16)
            {
                return Result.Failure<IApduCommand, SmartCardError>(
                    SmartCardError.InvalidArgument("Target AID must be 1-16 bytes"));
            }

            // Build TLV data: Tag(4F) + Length + AID
            var dataBuilder = ImmutableArray.CreateBuilder<byte>();
            dataBuilder.Add(0x4F); // AID tag
            dataBuilder.Add((byte)targetAid.Length);
            dataBuilder.AddRange(targetAid);

            return Result.Success<IApduCommand, SmartCardError>(
                new UnifiedApduCommand(
 GlobalPlatform.Cla.GpStandard,
 GlobalPlatform.Ins.Delete,
 0x00,
 deleteRelated ? (byte)0x01 : (byte)0x00,
 dataBuilder.ToArray(),
                    ExpectedResponseLength: Maybe<int>.From(0)
                )
            );
        }

        /// <summary>
        /// Creates INSTALL command for LOAD operation.
        /// Per GP Card Specification Section 11.9.
        /// </summary>
        /// <param name="packageAid">Package AID to load.</param>
        /// <param name="securityDomainAid">Security domain AID.</param>
        /// <param name="loadFileDataBlockHash">Optional hash of load file data block.</param>
        /// <param name="loadParameters">Optional load parameters.</param>
        /// <returns>INSTALL [for load] command or error.</returns>
        public static Result<IApduCommand, SmartCardError> CreateInstallForLoad(
            ImmutableArray<byte> packageAid,
            ImmutableArray<byte> securityDomainAid,
            Maybe<ImmutableArray<byte>> loadFileDataBlockHash = default,
            Maybe<ImmutableArray<byte>> loadParameters = default)
        {
            if (packageAid.IsDefaultOrEmpty || packageAid.Length > 16)
            {
                return Result.Failure<IApduCommand, SmartCardError>(
                    SmartCardError.InvalidArgument("Package AID must be 1-16 bytes"));
            }

            if (securityDomainAid.IsDefaultOrEmpty || securityDomainAid.Length > 16)
            {
                return Result.Failure<IApduCommand, SmartCardError>(
                    SmartCardError.InvalidArgument("Security Domain AID must be 1-16 bytes"));
            }

            var dataBuilder = ImmutableArray.CreateBuilder<byte>();

            // Package AID
            dataBuilder.Add((byte)packageAid.Length);
            dataBuilder.AddRange(packageAid);

            // Security Domain AID
            dataBuilder.Add((byte)securityDomainAid.Length);
            dataBuilder.AddRange(securityDomainAid);

            // Load File Data Block Hash (optional)
            loadFileDataBlockHash.Match(
                hash =>
                {
                    dataBuilder.Add((byte)hash.Length);
                    dataBuilder.AddRange(hash);
                },
                () => dataBuilder.Add(0x00));

            // Load Parameters (optional)
            loadParameters.Match(
                parameters =>
                {
                    dataBuilder.Add((byte)parameters.Length);
                    dataBuilder.AddRange(parameters);
                },
                () => dataBuilder.Add(0x00));

            // Load Token (empty - will be implemented when token support is added)
            dataBuilder.Add(0x00);

            return Result.Success<IApduCommand, SmartCardError>(
                new UnifiedApduCommand(
 GlobalPlatform.Cla.GpStandard,
 GlobalPlatform.Ins.Install,
 GlobalPlatform.InstallParameters.InstallForLoad,
 0x00,
 dataBuilder.ToArray(),
                    ExpectedResponseLength: Maybe<int>.From(0)
                )
            );
        }

        /// <summary>
        /// Creates INSTALL command for INSTALL operation.
        /// Per GP Card Specification Section 11.9.
        /// </summary>
        /// <param name="packageAid">Package AID.</param>
        /// <param name="moduleAid">Module AID.</param>
        /// <param name="applicationAid">Application AID.</param>
        /// <param name="privileges">Privileges byte array.</param>
        /// <param name="installParameters">Optional install parameters.</param>
        /// <returns>INSTALL [for install] command or error.</returns>
        public static Result<IApduCommand, SmartCardError> CreateInstallForInstall(
            ImmutableArray<byte> packageAid,
            ImmutableArray<byte> moduleAid,
            ImmutableArray<byte> applicationAid,
            ImmutableArray<byte> privileges,
            Maybe<ImmutableArray<byte>> installParameters = default)
        {
            if (packageAid.IsDefaultOrEmpty || packageAid.Length > 16)
            {
                return Result.Failure<IApduCommand, SmartCardError>(
                    SmartCardError.InvalidArgument("Package AID must be 1-16 bytes"));
            }

            if (moduleAid.IsDefaultOrEmpty || moduleAid.Length > 16)
            {
                return Result.Failure<IApduCommand, SmartCardError>(
                    SmartCardError.InvalidArgument("Module AID must be 1-16 bytes"));
            }

            if (applicationAid.IsDefaultOrEmpty || applicationAid.Length > 16)
            {
                return Result.Failure<IApduCommand, SmartCardError>(
                    SmartCardError.InvalidArgument("Application AID must be 1-16 bytes"));
            }

            if (privileges.IsDefaultOrEmpty)
            {
                return Result.Failure<IApduCommand, SmartCardError>(
                    SmartCardError.InvalidData("Privileges cannot be empty"));
            }

            var dataBuilder = ImmutableArray.CreateBuilder<byte>();

            // Package AID
            dataBuilder.Add((byte)packageAid.Length);
            dataBuilder.AddRange(packageAid);

            // Module AID
            dataBuilder.Add((byte)moduleAid.Length);
            dataBuilder.AddRange(moduleAid);

            // Application AID
            dataBuilder.Add((byte)applicationAid.Length);
            dataBuilder.AddRange(applicationAid);

            // Privileges
            dataBuilder.Add((byte)privileges.Length);
            dataBuilder.AddRange(privileges);

            // Install Parameters (optional)
            installParameters.Match(
                parameters =>
                {
                    dataBuilder.Add((byte)parameters.Length);
                    dataBuilder.AddRange(parameters);
                },
                () => dataBuilder.Add(0x00));

            // Install Token (empty - will be implemented when token support is added)
            dataBuilder.Add(0x00);

            return Result.Success<IApduCommand, SmartCardError>(
                new UnifiedApduCommand(
 GlobalPlatform.Cla.GpStandard,
 GlobalPlatform.Ins.Install,
 GlobalPlatform.InstallParameters.InstallForInstall,
 0x00,
 dataBuilder.ToArray(),
                    ExpectedResponseLength: Maybe<int>.From(0)
                )
            );
        }

        /// <summary>
        /// Creates LOAD command for CAP file loading.
        /// Per GP Card Specification Section 11.11.
        /// </summary>
        /// <param name="blockNumber">Block number (0-based).</param>
        /// <param name="isLastBlock">Whether this is the last block.</param>
        /// <param name="blockData">Block data to load.</param>
        /// <returns>LOAD command or error.</returns>
        public static Result<IApduCommand, SmartCardError> CreateLoad(
            byte blockNumber,
            bool isLastBlock,
            ImmutableArray<byte> blockData)
        {
            if (blockData.Length > 255)
            {
                return Result.Failure<IApduCommand, SmartCardError>(
                    SmartCardError.InvalidArgument($"Block data too large: {blockData.Length} > 255"));
            }

            return Result.Success<IApduCommand, SmartCardError>(
                new UnifiedApduCommand(
 GlobalPlatform.Cla.GpStandard,
 GlobalPlatform.Ins.Load,
 blockNumber,
 (byte)(isLastBlock ? 0x80 : 0x00),
 blockData.ToArray(),
                    ExpectedResponseLength: Maybe<int>.None
                )
            );
        }

        /// <summary>
        /// Creates GET RESPONSE command for retrieving remaining response data.
        /// Per ISO 7816-4 Section 5.1.3.
        /// </summary>
        /// <param name="expectedLength">Expected length of response data.</param>
        /// <returns>GET RESPONSE command or error.</returns>
        public static Result<IApduCommand, SmartCardError> CreateGetResponse(byte expectedLength)
        {
            return Result.Success<IApduCommand, SmartCardError>(
                new UnifiedApduCommand(
 Apdu.Classes.Standard,
 Apdu.Instructions.GetResponse,
 0x00,
 0x00,
 [],
                    ExpectedResponseLength: Maybe<int>.From(expectedLength == 0 ? 256 : expectedLength)
                )
            );
        }

        /// <summary>
        /// Creates PUT KEY command for key management.
        /// Per GP Card Specification Section 11.10.
        /// </summary>
        /// <param name="keyVersionNumber">Key version number.</param>
        /// <param name="keySetVersion">Key set version.</param>
        /// <param name="keyData">Key data in GP format.</param>
        /// <returns>PUT KEY command or error.</returns>
        public static Result<IApduCommand, SmartCardError> CreatePutKey(
            byte keyVersionNumber,
            byte keySetVersion,
            ImmutableArray<byte> keyData)
        {
            if (keyData.IsDefaultOrEmpty)
            {
                return Result.Failure<IApduCommand, SmartCardError>(
                    SmartCardError.InvalidData("Key data cannot be empty"));
            }

            return Result.Success<IApduCommand, SmartCardError>(
                new UnifiedApduCommand(
 GlobalPlatform.Cla.GpStandard,
 GlobalPlatform.Ins.PutKey,
 keyVersionNumber,
 keySetVersion,
 keyData.ToArray(),
                    ExpectedResponseLength: Maybe<int>.From(0)
                )
            );
        }

        /// <summary>
        /// Creates SET STATUS command for application lifecycle management.
        /// Per GP Card Specification Section 11.5.
        /// </summary>
        /// <param name="status">New status for the application.</param>
        /// <param name="targetAid">AID of target application.</param>
        /// <returns>SET STATUS command or error.</returns>
        public static Result<IApduCommand, SmartCardError> CreateSetStatus(
            byte status,
            ImmutableArray<byte> targetAid)
        {
            if (targetAid.IsDefaultOrEmpty || targetAid.Length > 16)
            {
                return Result.Failure<IApduCommand, SmartCardError>(
                    SmartCardError.InvalidArgument("Target AID must be 1-16 bytes"));
            }

            return Result.Success<IApduCommand, SmartCardError>(
                new UnifiedApduCommand(
 GlobalPlatform.Cla.GpStandard,
 GlobalPlatform.Ins.SetStatus,
 0x40, // Application
 status,
 targetAid.ToArray(),
                    ExpectedResponseLength: Maybe<int>.From(0)
                )
            );
        }
    }
}