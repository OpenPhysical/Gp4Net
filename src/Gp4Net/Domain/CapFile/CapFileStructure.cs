using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.Domain.CapFile
{
    /// <summary>
    /// Represents a Converted Applet (CAP) file structure for Java Card applications.
    /// Based on Java Card Virtual Machine Specification and GlobalPlatform Card Specification.
    /// </summary>
    [PublicAPI]
    public class CapFileStructure
    {
        /// <summary>
        /// CAP file component tags as defined in Java Card specification.
        /// </summary>
        public static class ComponentTags
        {
            /// <summary>
            /// Header component tag.
            /// </summary>
            public const byte Header = 0x01;

            /// <summary>
            /// Directory component tag.
            /// </summary>
            public const byte Directory = 0x02;

            /// <summary>
            /// Applet component tag.
            /// </summary>
            public const byte Applet = 0x03;

            /// <summary>
            /// Import component tag.
            /// </summary>
            public const byte Import = 0x04;

            /// <summary>
            /// Constant Pool component tag.
            /// </summary>
            public const byte ConstantPool = 0x05;

            /// <summary>
            /// Class component tag.
            /// </summary>
            public const byte Class = 0x06;

            /// <summary>
            /// Method component tag.
            /// </summary>
            public const byte Method = 0x07;

            /// <summary>
            /// Static Field component tag.
            /// </summary>
            public const byte StaticField = 0x08;

            /// <summary>
            /// Reference Location component tag.
            /// </summary>
            public const byte ReferenceLocation = 0x09;

            /// <summary>
            /// Export component tag.
            /// </summary>
            public const byte Export = 0x0A;

            /// <summary>
            /// Descriptor component tag.
            /// </summary>
            public const byte Descriptor = 0x0B;

            /// <summary>
            /// Debug component tag.
            /// </summary>
            public const byte Debug = 0x0C;
        }

        /// <summary>
        /// Gets the package AID.
        /// </summary>
        public byte[] PackageAid { get; }

        /// <summary>
        /// Gets the package version.
        /// </summary>
        public CapVersion PackageVersion { get; }

        /// <summary>
        /// Gets the list of components in the CAP file.
        /// </summary>
        public IReadOnlyList<CapComponent> Components { get; }

        /// <summary>
        /// Gets the list of applets defined in this package.
        /// </summary>
        public IReadOnlyList<AppletInfo> Applets { get; }

        /// <summary>
        /// Gets the total size of the CAP file data.
        /// </summary>
        public int TotalSize { get; }

        /// <summary>
        /// Gets the manifest information (if available from ZIP format).
        /// </summary>
        public ManifestInfo? Manifest { get; }

        /// <summary>
        /// Gets the Java Card CAP file format version.
        /// </summary>
        public CapVersion CapFileVersion { get; }

        /// <summary>
        /// Gets the header flags.
        /// </summary>
        public byte HeaderFlags { get; }

        /// <summary>
        /// Initializes a new instance of the CapFileStructure class.
        /// </summary>
        /// <param name="packageAid">The package AID.</param>
        /// <param name="packageVersion">The package version.</param>
        /// <param name="components">The list of components.</param>
        /// <param name="applets">The list of applets.</param>
        /// <param name="manifest">The manifest information (optional).</param>
        /// <param name="capFileVersion">The CAP file format version.</param>
        /// <param name="headerFlags">The header flags.</param>
        public CapFileStructure(
            byte[] packageAid,
            CapVersion packageVersion,
            IList<CapComponent> components,
            IList<AppletInfo> applets,
            ManifestInfo? manifest = null,
            CapVersion? capFileVersion = null,
            byte headerFlags = 0
        )
        {
            PackageAid = (byte[])packageAid.Clone();
            PackageVersion = packageVersion;
            Components = new List<CapComponent>(components);
            Applets = new List<AppletInfo>(applets);
            TotalSize = components.Sum(c => c.Data.Length);
            Manifest = manifest;
            CapFileVersion = capFileVersion ?? new CapVersion(0, 0);
            HeaderFlags = headerFlags;
        }

        /// <summary>
        /// Parses a CAP file from byte array (ZIP/JAR format only).
        /// </summary>
        /// <param name="capFileData">The CAP file data.</param>
        /// <returns>The parsed CAP file structure.</returns>
        /// <exception cref="ArgumentNullException">Thrown when capFileData is null.</exception>
        /// <exception cref="InvalidDataException">Thrown when the CAP file format is invalid.</exception>
        public static CapFileStructure Parse(byte[] capFileData)
        {
            ArgumentNullException.ThrowIfNull(capFileData);

            // Only support ZIP/JAR format CAP files
            if (
                capFileData.Length >= 4
                && capFileData[0] == 0x50
                && capFileData[1] == 0x4B
                && capFileData[2] == 0x03
                && capFileData[3] == 0x04
            )
            {
                return ParseZipFormat(capFileData);
            }

            throw new InvalidDataException(
                "Only ZIP/JAR format CAP files are supported. Raw binary CAP format is not supported."
            );
        }

        /// <summary>
        /// Attempts to parse a CAP file from byte array (ZIP/JAR format only) using functional error handling.
        /// </summary>
        /// <param name="capFileData">The CAP file data.</param>
        /// <returns>A result containing the parsed CAP file structure or an error.</returns>
        public static Result<CapFileStructure, SmartCardError> TryParse(byte[] capFileData)
        {
            if (capFileData == null)
            {
                return Result.Failure<CapFileStructure, SmartCardError>(
                    SmartCardError.InvalidData("CAP file data cannot be null"));
            }

            // Only support ZIP/JAR format CAP files
            if (capFileData.Length < 4)
            {
                return Result.Failure<CapFileStructure, SmartCardError>(
                    SmartCardError.InvalidData("CAP file data is too short to be valid"));
            }

            if (!(capFileData[0] == 0x50 && capFileData[1] == 0x4B && 
                  capFileData[2] == 0x03 && capFileData[3] == 0x04))
            {
                return Result.Failure<CapFileStructure, SmartCardError>(
                    SmartCardError.InvalidData(
                        "Only ZIP/JAR format CAP files are supported. Raw binary CAP format is not supported."));
            }

            try
            {
                var result = ParseZipFormat(capFileData);
                return Result.Success<CapFileStructure, SmartCardError>(result);
            }
            catch (InvalidDataException ex)
            {
                return Result.Failure<CapFileStructure, SmartCardError>(
                    SmartCardError.InvalidData($"CAP file parsing failed: {ex.Message}"));
            }
            catch (Exception ex)
            {
                return Result.Failure<CapFileStructure, SmartCardError>(
                    SmartCardError.UnexpectedError("Unexpected error during CAP file parsing", ex));
            }
        }

        /// <summary>
        /// Parses a CAP file from ZIP/JAR format.
        /// </summary>
        /// <param name="capFileData">The ZIP/JAR CAP file data.</param>
        /// <returns>The parsed CAP file structure.</returns>
        private static CapFileStructure ParseZipFormat(byte[] capFileData)
        {
            using var zipStream = new MemoryStream(capFileData);
            using var archive = new ZipArchive(zipStream, ZipArchiveMode.Read);

            var components = new List<CapComponent>();
            var applets = new List<AppletInfo>();
            byte[]? packageAid = null;
            CapVersion? packageVersion = null;
            CapVersion? capFileVersion = null;
            byte headerFlags = 0;
            ManifestInfo? manifest = null;

            // Component name to tag mapping
            var componentMapping = new Dictionary<string, byte>
            {
                ["Header.cap"] = ComponentTags.Header,
                ["Directory.cap"] = ComponentTags.Directory,
                ["Applet.cap"] = ComponentTags.Applet,
                ["Import.cap"] = ComponentTags.Import,
                ["ConstantPool.cap"] = ComponentTags.ConstantPool,
                ["Class.cap"] = ComponentTags.Class,
                ["Method.cap"] = ComponentTags.Method,
                ["StaticField.cap"] = ComponentTags.StaticField,
                ["RefLocation.cap"] = ComponentTags.ReferenceLocation,
                ["Export.cap"] = ComponentTags.Export,
                ["Descriptor.cap"] = ComponentTags.Descriptor,
                ["Debug.cap"] = ComponentTags.Debug,
            };

            // Find and parse component files and manifest
            foreach (var entry in archive.Entries)
            {
                var fileName = Path.GetFileName(entry.FullName);

                // Parse manifest file
                if (entry.FullName == "META-INF/MANIFEST.MF")
                {
                    using var entryStream = entry.Open();
                    using var reader = new StreamReader(entryStream);
                    var manifestContent = reader.ReadToEnd();
                    manifest = ManifestInfo.Parse(manifestContent);
                    continue;
                }

                if (componentMapping.TryGetValue(fileName, out var expectedTag))
                {
                    using var entryStream = entry.Open();
                    using var memoryStream = new MemoryStream();
                    entryStream.CopyTo(memoryStream);
                    var fileData = memoryStream.ToArray();

                    // Parse the component from the file data (includes tag + size + data)
                    using var componentStream = new MemoryStream(fileData);
                    var component = CapComponent.Parse(componentStream);

                    // Verify tag matches expected
                    if (component.Tag != expectedTag)
                    {
                        throw new InvalidDataException(
                            $"Component file {fileName} has unexpected tag {component.Tag:X2}, expected {expectedTag:X2}"
                        );
                    }

                    components.Add(component);

                    // Extract package information from header component
                    if (component.Tag == ComponentTags.Header)
                    {
                        var header = HeaderComponent.Parse(component.Data);
                        packageAid = header.PackageAid;
                        packageVersion = header.PackageVersion;
                        capFileVersion = new CapVersion(
                            header.CapFileMajorVersion,
                            header.CapFileMinorVersion
                        );
                        headerFlags = header.Flags;
                    }

                    // Extract applet information from applet component
                    if (component.Tag == ComponentTags.Applet)
                    {
                        var appletComponent = AppletComponent.Parse(component.Data);
                        applets.AddRange(appletComponent.Applets);
                    }
                }
            }

            if (packageAid == null || packageVersion == null)
            {
                throw new InvalidDataException("CAP file missing required header component.");
            }

            return new CapFileStructure(
                packageAid,
                packageVersion.Value,
                components,
                applets,
                manifest,
                capFileVersion,
                headerFlags
            );
        }

        /// <summary>
        /// Gets components organized for loading (in the correct order).
        /// </summary>
        /// <returns>The components in loading order.</returns>
        public IEnumerable<CapComponent> GetLoadingComponents()
        {
            // Standard loading order for Java Card
            byte[] loadOrder =
            {
                ComponentTags.Header,
                ComponentTags.Directory,
                ComponentTags.Import,
                ComponentTags.Applet,
                ComponentTags.Class,
                ComponentTags.Method,
                ComponentTags.StaticField,
                ComponentTags.Export,
                ComponentTags.ConstantPool,
                ComponentTags.ReferenceLocation,
                ComponentTags.Descriptor,
            };

            var componentDict = Components.ToDictionary(c => c.Tag, c => c);

            foreach (var tag in loadOrder)
            {
                if (componentDict.TryGetValue(tag, out var component))
                {
                    yield return component;
                }
            }
        }

        /// <summary>
        /// Converts the CAP file structure back to binary format suitable for loading.
        /// </summary>
        /// <returns>The binary CAP file data.</returns>
        public byte[] ToBinaryFormat()
        {
            var binaryData = new List<byte>();

            foreach (var component in GetLoadingComponents())
            {
                // Add component tag
                binaryData.Add(component.Tag);

                // Add component size (2 bytes, big-endian)
                binaryData.Add((byte)(component.Size >> 8));
                binaryData.Add((byte)(component.Size & 0xFF));

                // Add component data
                binaryData.AddRange(component.Data);
            }

            return [.. binaryData];
        }

        /// <summary>
        /// Splits the CAP file into blocks suitable for LOAD commands.
        /// </summary>
        /// <param name="maxBlockSize">Maximum size per block (default 255 bytes).</param>
        /// <returns>The list of load blocks.</returns>
        public IList<LoadBlock> CreateLoadBlocks(int maxBlockSize = 255)
        {
            var blocks = new List<LoadBlock>();
            byte blockNumber = 0;

            foreach (var component in GetLoadingComponents())
            {
                var componentData = component.Data;
                var offset = 0;

                while (offset < componentData.Length)
                {
                    var remainingBytes = componentData.Length - offset;
                    var blockSize = Math.Min(remainingBytes, maxBlockSize);
                    var blockData = new byte[blockSize];

                    Array.Copy(componentData, offset, blockData, 0, blockSize);

                    var isLastBlock =
                        (offset + blockSize >= componentData.Length)
                        && component == GetLoadingComponents().Last();

                    blocks.Add(new LoadBlock(blockNumber++, blockData, isLastBlock));
                    offset += blockSize;
                }
            }

            return blocks;
        }
    }

    /// <summary>
    /// Represents a CAP file component.
    /// </summary>
    [PublicAPI]
    public class CapComponent
    {
        /// <summary>
        /// Gets the component tag.
        /// </summary>
        public byte Tag { get; }

        /// <summary>
        /// Gets the component size.
        /// </summary>
        public ushort Size { get; }

        /// <summary>
        /// Gets the component data.
        /// </summary>
        public byte[] Data { get; }

        /// <summary>
        /// Initializes a new instance of the CapComponent class.
        /// </summary>
        /// <param name="tag">The component tag.</param>
        /// <param name="size">The component size.</param>
        /// <param name="data">The component data.</param>
        public CapComponent(byte tag, ushort size, byte[] data)
        {
            Tag = tag;
            Size = size;
            Data = (byte[])data.Clone();
        }

        /// <summary>
        /// Parses a component from a stream.
        /// </summary>
        /// <param name="stream">The stream to parse from.</param>
        /// <returns>The parsed component.</returns>
        public static CapComponent Parse(Stream stream)
        {
            if (stream.Position >= stream.Length)
            {
                throw new InvalidDataException(
                    "Unexpected end of stream while reading component tag."
                );
            }

            var tagByte = stream.ReadByte();
            if (tagByte == -1)
            {
                throw new InvalidDataException(
                    "Unexpected end of stream while reading component tag."
                );
            }

            var tag = (byte)tagByte;

            // Read size (2 bytes, big-endian)
            if (stream.Position + 1 >= stream.Length)
            {
                throw new InvalidDataException(
                    "Unexpected end of stream while reading component size."
                );
            }

            var sizeHighByte = stream.ReadByte();
            var sizeLowByte = stream.ReadByte();
            if (sizeHighByte == -1 || sizeLowByte == -1)
            {
                throw new InvalidDataException(
                    "Unexpected end of stream while reading component size."
                );
            }

            var sizeHigh = (byte)sizeHighByte;
            var sizeLow = (byte)sizeLowByte;
            var size = (ushort)((sizeHigh << 8) | sizeLow);

            // Check if we have enough data left in the stream
            if (stream.Position + size > stream.Length)
            {
                throw new InvalidDataException(
                    $"Component claims size of {size} bytes, but only {stream.Length - stream.Position} bytes remaining in stream."
                );
            }

            // Read component data
            var data = new byte[size];
            var bytesRead = stream.Read(data, 0, size);
            if (bytesRead != size)
            {
                throw new InvalidDataException(
                    "Unexpected end of stream while reading component data."
                );
            }

            return new CapComponent(tag, size, data);
        }
    }

    /// <summary>
    /// Represents CAP file version information.
    /// </summary>
    [PublicAPI]
    public struct CapVersion
    {
        /// <summary>
        /// Gets the major version.
        /// </summary>
        public byte Major { get; }

        /// <summary>
        /// Gets the minor version.
        /// </summary>
        public byte Minor { get; }

        /// <summary>
        /// Initializes a new instance of the CapVersion struct.
        /// </summary>
        /// <param name="major">The major version.</param>
        /// <param name="minor">The minor version.</param>
        public CapVersion(byte major, byte minor)
        {
            Major = major;
            Minor = minor;
        }

        /// <summary>
        /// Returns a string representation of the version.
        /// </summary>
        /// <returns>The version string.</returns>
        public override string ToString()
        {
            return $"{Major}.{Minor}";
        }
    }

    /// <summary>
    /// Represents applet information from the CAP file.
    /// </summary>
    [PublicAPI]
    public class AppletInfo
    {
        /// <summary>
        /// Gets the applet AID.
        /// </summary>
        public byte[] Aid { get; }

        /// <summary>
        /// Gets the install method offset.
        /// </summary>
        public ushort InstallMethodOffset { get; }

        /// <summary>
        /// Initializes a new instance of the AppletInfo class.
        /// </summary>
        /// <param name="aid">The applet AID.</param>
        /// <param name="installMethodOffset">The install method offset.</param>
        public AppletInfo(byte[] aid, ushort installMethodOffset)
        {
            Aid = (byte[])aid.Clone();
            InstallMethodOffset = installMethodOffset;
        }
    }

    /// <summary>
    /// Represents a load block for LOAD commands.
    /// </summary>
    [PublicAPI]
    public class LoadBlock
    {
        /// <summary>
        /// Gets the block number.
        /// </summary>
        public byte BlockNumber { get; }

        /// <summary>
        /// Gets the block data.
        /// </summary>
        public byte[] Data { get; }

        /// <summary>
        /// Gets a value indicating whether this is the last block.
        /// </summary>
        public bool IsLastBlock { get; }

        /// <summary>
        /// Initializes a new instance of the LoadBlock class.
        /// </summary>
        /// <param name="blockNumber">The block number.</param>
        /// <param name="data">The block data.</param>
        /// <param name="isLastBlock">Whether this is the last block.</param>
        public LoadBlock(byte blockNumber, byte[] data, bool isLastBlock)
        {
            BlockNumber = blockNumber;
            Data = (byte[])data.Clone();
            IsLastBlock = isLastBlock;
        }
    }

    /// <summary>
    /// Represents the header component data.
    /// </summary>
    internal class HeaderComponent
    {
        public byte[] PackageAid { get; }
        public CapVersion PackageVersion { get; }
        public byte CapFileMinorVersion { get; }
        public byte CapFileMajorVersion { get; }
        public byte Flags { get; }

        private HeaderComponent(
            byte[] packageAid,
            CapVersion packageVersion,
            byte capFileMinorVersion,
            byte capFileMajorVersion,
            byte flags
        )
        {
            PackageAid = packageAid;
            PackageVersion = packageVersion;
            CapFileMinorVersion = capFileMinorVersion;
            CapFileMajorVersion = capFileMajorVersion;
            Flags = flags;
        }

        public static HeaderComponent Parse(byte[] data)
        {
            if (data.Length < 10) // Minimum header size
            {
                throw new InvalidDataException("Invalid header component data.");
            }

            var offset = 0;

            // Check for magic number (4 bytes: 0xDECAFFED)
            if (
                data.Length >= 4
                && data[0] == 0xDE
                && data[1] == 0xCA
                && data[2] == 0xFF
                && data[3] == 0xED
            )
            {
                offset = 4; // Skip magic number
            }

            // Read CAP file minor version (1 byte)
            var capMinorVersion = data[offset++];

            // Read CAP file major version (1 byte)
            var capMajorVersion = data[offset++];

            // Read flags (1 byte)
            var flags = data[offset++];

            // Skip package info (2 bytes - package name length and reserved)
            offset += 2;

            // Read package AID length
            var packageAidLength = data[offset++];

            if (offset + packageAidLength > data.Length)
            {
                throw new InvalidDataException(
                    $"Invalid header component data: need {offset + packageAidLength} bytes for AID, have {data.Length}."
                );
            }

            var packageAid = new byte[packageAidLength];
            Array.Copy(data, offset, packageAid, 0, packageAidLength);
            offset += packageAidLength;

            // Package version may not be present in all formats
            byte packageMajor = 1;
            byte packageMinor = 0;

            if (offset + 1 < data.Length)
            {
                packageMajor = data[offset++];
                if (offset < data.Length)
                {
                    packageMinor = data[offset++];
                }
            }

            return new HeaderComponent(
                packageAid,
                new CapVersion(packageMajor, packageMinor),
                capMinorVersion,
                capMajorVersion,
                flags
            );
        }
    }

    /// <summary>
    /// Represents the applet component data.
    /// </summary>
    internal class AppletComponent
    {
        public IList<AppletInfo> Applets { get; }

        private AppletComponent(IList<AppletInfo> applets)
        {
            Applets = applets;
        }

        public static AppletComponent Parse(byte[] data)
        {
            var applets = new List<AppletInfo>();
            var offset = 0;

            // Read count
            if (data.Length < 1)
            {
                return new AppletComponent(applets);
            }

            var count = data[offset++];

            for (int i = 0; i < count; i++)
            {
                if (offset >= data.Length)
                {
                    break;
                }

                // Read AID length
                var aidLength = data[offset++];
                if (offset + aidLength + 2 > data.Length)
                {
                    break;
                }

                // Read AID
                var aid = new byte[aidLength];
                Array.Copy(data, offset, aid, 0, aidLength);
                offset += aidLength;

                // Read install method offset
                var installMethodOffset = (ushort)((data[offset] << 8) | data[offset + 1]);
                offset += 2;

                applets.Add(new AppletInfo(aid, installMethodOffset));
            }

            return new AppletComponent(applets);
        }
    }

    /// <summary>
    /// Represents manifest information from ZIP/JAR CAP files.
    /// </summary>
    [PublicAPI]
    public class ManifestInfo
    {
        /// <summary>
        /// Gets the Java Card CAP file version.
        /// </summary>
        public string? CapFileVersion { get; }

        /// <summary>
        /// Gets the Java Card converter version.
        /// </summary>
        public string? ConverterVersion { get; }

        /// <summary>
        /// Gets the converter provider.
        /// </summary>
        public string? ConverterProvider { get; }

        /// <summary>
        /// Gets the creation time.
        /// </summary>
        public string? CreationTime { get; }

        /// <summary>
        /// Gets the package name.
        /// </summary>
        public string? PackageName { get; }

        /// <summary>
        /// Gets the imported packages.
        /// </summary>
        public IReadOnlyList<ImportedPackage> ImportedPackages { get; }

        /// <summary>
        /// Gets whether integer support is required.
        /// </summary>
        public bool? IntegerSupportRequired { get; }

        /// <summary>
        /// Initializes a new instance of the ManifestInfo class.
        /// </summary>
        public ManifestInfo(
            string? capFileVersion = null,
            string? converterVersion = null,
            string? converterProvider = null,
            string? creationTime = null,
            string? packageName = null,
            IList<ImportedPackage>? importedPackages = null,
            bool? integerSupportRequired = null
        )
        {
            CapFileVersion = capFileVersion;
            ConverterVersion = converterVersion;
            ConverterProvider = converterProvider;
            CreationTime = creationTime;
            PackageName = packageName;
            ImportedPackages =
                importedPackages != null
                    ? new List<ImportedPackage>(importedPackages)
                    : Array.Empty<ImportedPackage>();
            IntegerSupportRequired = integerSupportRequired;
        }

        /// <summary>
        /// Parses manifest data from text content.
        /// </summary>
        /// <param name="manifestContent">The manifest file content.</param>
        /// <returns>The parsed manifest information.</returns>
        public static ManifestInfo Parse(string manifestContent)
        {
            var lines = manifestContent.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            var properties = new Dictionary<string, string>();

            string? currentKey = null;
            string? currentValue = null;

            foreach (var line in lines)
            {
                var trimmedLine = line.Trim();
                if (
                    string.IsNullOrEmpty(trimmedLine)
                    || trimmedLine.StartsWith("Manifest-Version")
                    || trimmedLine.StartsWith("Name:")
                )
                {
                    continue;
                }

                if (trimmedLine.StartsWith(' ') && currentKey != null)
                {
                    // Continuation line
                    currentValue += trimmedLine.Trim();
                }
                else
                {
                    // Save previous property
                    if (currentKey != null && currentValue != null)
                    {
                        properties[currentKey] = currentValue;
                    }

                    // Parse new property
                    var colonIndex = trimmedLine.IndexOf(':');
                    if (colonIndex > 0)
                    {
                        currentKey = trimmedLine.Substring(0, colonIndex).Trim();
                        currentValue = trimmedLine.Substring(colonIndex + 1).Trim();
                    }
                }
            }

            // Save last property
            if (currentKey != null && currentValue != null)
            {
                properties[currentKey] = currentValue;
            }

            // Extract imported packages
            var importedPackages = new List<ImportedPackage>();
            for (int i = 1; i <= 10; i++) // Check up to 10 imported packages
            {
                var aidKey = $"Java-Card-Imported-Package-{i}-AID";
                var versionKey = $"Java-Card-Imported-Package-{i}-Version";

                if (
                    properties.TryGetValue(aidKey, out var aidValue)
                    && properties.TryGetValue(versionKey, out var versionValue)
                )
                {
                    importedPackages.Add(new ImportedPackage(aidValue, versionValue));
                }
            }

            return new ManifestInfo(
                capFileVersion: properties.GetValueOrDefault("Java-Card-CAP-File-Version"),
                converterVersion: properties.GetValueOrDefault("Java-Card-Converter-Version"),
                converterProvider: properties.GetValueOrDefault("Java-Card-Converter-Provider"),
                creationTime: properties.GetValueOrDefault("Java-Card-CAP-Creation-Time"),
                packageName: properties.GetValueOrDefault("Java-Card-Package-Name"),
                importedPackages: importedPackages,
                integerSupportRequired: properties.GetValueOrDefault(
                    "Java-Card-Integer-Support-Required"
                ) == "TRUE"
            );
        }
    }

    /// <summary>
    /// Represents an imported package.
    /// </summary>
    [PublicAPI]
    public class ImportedPackage
    {
        /// <summary>
        /// Gets the package AID.
        /// </summary>
        public string Aid { get; }

        /// <summary>
        /// Gets the package version.
        /// </summary>
        public string Version { get; }

        /// <summary>
        /// Initializes a new instance of the ImportedPackage class.
        /// </summary>
        /// <param name="aid">The package AID.</param>
        /// <param name="version">The package version.</param>
        public ImportedPackage(string aid, string version)
        {
            Aid = aid;
            Version = version;
        }
    }
}
