using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.Domain.CapFile;

/// <summary>
/// Represents a Converted Applet (CAP) file structure for Java Card applications.
/// Based on Java Card Virtual Machine Specification and GlobalPlatform Card Specification.
/// </summary>
[PublicAPI]

public class CapFileStructure
{

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
    public ManifestInfo Manifest { get; }

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
        ManifestInfo manifest = null,
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
    /// <returns>A Result containing the parsed CAP file structure, or an error if the data is invalid.</returns>
    public static Result<CapFileStructure, SmartCardError> Parse(byte[] capFileData)
    {
        if (capFileData is null)
            return Result.Failure<CapFileStructure, SmartCardError>(
                SmartCardError.InvalidArgument("CAP file data cannot be null")
            );

        // Only support ZIP/JAR format CAP files
        if (
            capFileData.Length >= Constants.Constants.FileFormats.Zip.MinimumHeaderSize
            && capFileData[0] == Constants.Constants.FileFormats.Zip.LocalFileHeaderSignature.Byte1
            && capFileData[1] == Constants.Constants.FileFormats.Zip.LocalFileHeaderSignature.Byte2
            && capFileData[2] == Constants.Constants.FileFormats.Zip.LocalFileHeaderSignature.Byte3
            && capFileData[3] == Constants.Constants.FileFormats.Zip.LocalFileHeaderSignature.Byte4
        )
        {
            return ParseZipFormat(capFileData);
        }

        return Result.Failure<CapFileStructure, SmartCardError>(
            SmartCardError.Unsupported(
                "Only ZIP/JAR format CAP files are supported. Raw binary CAP format is not supported."
            )
        );
    }

    /// <summary>
    /// Attempts to parse a CAP file from byte array (ZIP/JAR format only).
    /// </summary>
    /// <param name="capFileData">The CAP file data.</param>
    /// <returns>A result containing the parsed CAP file structure or an error.</returns>
    public static Result<CapFileStructure, SmartCardError> TryParse(byte[] capFileData)
    {
        if (capFileData == null)
        {
            return Result.Failure<CapFileStructure, SmartCardError>(
                SmartCardError.InvalidData("CAP file data cannot be null")
            );
        }

        // Only support ZIP/JAR format CAP files
        if (capFileData.Length < Constants.Constants.FileFormats.Zip.MinimumHeaderSize)
        {
            return Result.Failure<CapFileStructure, SmartCardError>(
                SmartCardError.InvalidData("CAP file data is too short to be valid")
            );
        }

        if (
            !(
                capFileData[0] == Constants.Constants.FileFormats.Zip.LocalFileHeaderSignature.Byte1
                && capFileData[1] == Constants.Constants.FileFormats.Zip.LocalFileHeaderSignature.Byte2
                && capFileData[2] == Constants.Constants.FileFormats.Zip.LocalFileHeaderSignature.Byte3
                && capFileData[3] == Constants.Constants.FileFormats.Zip.LocalFileHeaderSignature.Byte4
            )
        )
        {
            return Result.Failure<CapFileStructure, SmartCardError>(
                SmartCardError.InvalidData(
                    "Only ZIP/JAR format CAP files are supported. Raw binary CAP format is not supported."
                )
            );
        }

        try
        {
            CapFileStructure result = ParseZipFormat(capFileData);
            return Result.Success<CapFileStructure, SmartCardError>(result);
        }
        catch (InvalidDataException ex)
        {
            return Result.Failure<CapFileStructure, SmartCardError>(
                SmartCardError.InvalidData($"CAP file parsing failed: {ex.Message}")
            );
        }
        catch (Exception ex)
        {
            return Result.Failure<CapFileStructure, SmartCardError>(
                SmartCardError.UnexpectedError("Unexpected error during CAP file parsing", ex)
            );
        }
    }

    /// <summary>
    /// Parses a CAP file from ZIP/JAR format.
    /// </summary>
    /// <param name="capFileData">The ZIP/JAR CAP file data.</param>
    /// <returns>The parsed CAP file structure.</returns>
    private static CapFileStructure ParseZipFormat(byte[] capFileData)
    {
        using MemoryStream zipStream = new MemoryStream(capFileData);
        using ZipArchive archive = new ZipArchive(zipStream, ZipArchiveMode.Read);

        List<CapComponent> components = [];
        List<AppletInfo> applets = [];
        byte[] packageAid = null;
        CapVersion? packageVersion = null;
        CapVersion? capFileVersion = null;
        byte headerFlags = 0;
        ManifestInfo manifest = null;

        // Component name to tag mapping
        Dictionary<string, byte> componentMapping = new Dictionary<string, byte>
        {
            [Constants.Constants.JavaCard.ComponentFilenames.Header] = Constants.Constants.JavaCard.ComponentTags.Header,
            [Constants.Constants.JavaCard.ComponentFilenames.Directory] = Constants.Constants.JavaCard.ComponentTags.Directory,
            [Constants.Constants.JavaCard.ComponentFilenames.Applet] = Constants.Constants.JavaCard.ComponentTags.Applet,
            [Constants.Constants.JavaCard.ComponentFilenames.Import] = Constants.Constants.JavaCard.ComponentTags.Import,
            [Constants.Constants.JavaCard.ComponentFilenames.ConstantPool] = Constants.Constants.JavaCard.ComponentTags.ConstantPool,
            [Constants.Constants.JavaCard.ComponentFilenames.Class] = Constants.Constants.JavaCard.ComponentTags.Class,
            [Constants.Constants.JavaCard.ComponentFilenames.Method] = Constants.Constants.JavaCard.ComponentTags.Method,
            [Constants.Constants.JavaCard.ComponentFilenames.StaticField] = Constants.Constants.JavaCard.ComponentTags.StaticField,
            [Constants.Constants.JavaCard.ComponentFilenames.ReferenceLocation] = Constants.Constants.JavaCard.ComponentTags.ReferenceLocation,
            [Constants.Constants.JavaCard.ComponentFilenames.Export] = Constants.Constants.JavaCard.ComponentTags.Export,
            [Constants.Constants.JavaCard.ComponentFilenames.Descriptor] = Constants.Constants.JavaCard.ComponentTags.Descriptor,
            [Constants.Constants.JavaCard.ComponentFilenames.Debug] = Constants.Constants.JavaCard.ComponentTags.Debug,
        };

        // Find and parse component files and manifest
        foreach (ZipArchiveEntry entry in archive.Entries)
        {
            string fileName = Path.GetFileName(entry.FullName);

            // Parse manifest file
            if (entry.FullName == Constants.Constants.FileFormats.Zip.ManifestPath)
            {
                using Stream entryStream = entry.Open();
                using StreamReader reader = new StreamReader(entryStream);
                string manifestContent = reader.ReadToEnd();
                manifest = ManifestInfo.Parse(manifestContent);
                continue;
            }

            if (componentMapping.TryGetValue(fileName, out byte expectedTag))
            {
                using Stream entryStream = entry.Open();
                using MemoryStream memoryStream = new MemoryStream();
                entryStream.CopyTo(memoryStream);
                byte[] fileData = memoryStream.ToArray();

                // Parse the component from the file data (includes tag + size + data)
                using MemoryStream componentStream = new MemoryStream(fileData);
                CapComponent component = CapComponent.Parse(componentStream);

                // Verify tag matches expected
                if (component.Tag != expectedTag)
                {
                    throw new InvalidDataException(
                        $"Component file {fileName} has unexpected tag {component.Tag:X2}, expected {expectedTag:X2}"
                    );
                }

                components.Add(component);

                switch (component.Tag)
                {
                    // Extract package information from header component
                    case Constants.Constants.JavaCard.ComponentTags.Header:
                    {
                        HeaderComponent header = HeaderComponent.Parse(component.Data);
                        packageAid = header.PackageAid;
                        packageVersion = header.PackageVersion;
                        capFileVersion = new CapVersion(
                            header.CapFileMajorVersion,
                            header.CapFileMinorVersion
                        );
                        headerFlags = header.Flags;
                        break;
                    }

                    // Extract applet information from applet component
                    case Constants.Constants.JavaCard.ComponentTags.Applet:
                    {
                        AppletComponent appletComponent = AppletComponent.Parse(component.Data);
                        applets.AddRange(appletComponent.Applets);
                        break;
                    }
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
        [
            Constants.Constants.JavaCard.ComponentTags.Header,
            Constants.Constants.JavaCard.ComponentTags.Directory,
            Constants.Constants.JavaCard.ComponentTags.Import,
            Constants.Constants.JavaCard.ComponentTags.Applet,
            Constants.Constants.JavaCard.ComponentTags.Class,
            Constants.Constants.JavaCard.ComponentTags.Method,
            Constants.Constants.JavaCard.ComponentTags.StaticField,
            Constants.Constants.JavaCard.ComponentTags.Export,
            Constants.Constants.JavaCard.ComponentTags.ConstantPool,
            Constants.Constants.JavaCard.ComponentTags.ReferenceLocation,
            Constants.Constants.JavaCard.ComponentTags.Descriptor,
        ];

        Dictionary<byte, CapComponent> componentDict = Components.ToDictionary(c => c.Tag, c => c);

        foreach (byte tag in loadOrder)
        {
            if (componentDict.TryGetValue(tag, out CapComponent component))
            {
                yield return component;
            }
        }
    }

    /// <summary>
    /// Converts the CAP file structure back to binary format suitable for loading.
    /// </summary>
    /// <returns>The binary CAP file data.</returns>
    public byte[] ToBinaryFormat() =>
        GetLoadingComponents()
            .SelectMany(SerializeComponent)
            .ToArray();

    /// <summary>
    /// Serializes a single CAP component into binary format.
    /// </summary>
    /// <param name="component">The component to serialize.</param>
    /// <returns>The serialized bytes for the component.</returns>
    private static IEnumerable<byte> SerializeComponent(CapComponent component) =>
        new[] { component.Tag }
            .Concat(new[]
            {
                (byte)(component.Size >> 8),
                (byte)(component.Size & Constants.Constants.GlobalPlatform.CommonBytes.Max)
            })
            .Concat(component.Data);

    /// <summary>
    /// Splits the CAP file into blocks suitable for LOAD commands.
    /// </summary>
    /// <param name="maxBlockSize">Maximum size per block (default 255 bytes).</param>
    /// <returns>The list of load blocks.</returns>
    public IList<LoadBlock> CreateLoadBlocks(int maxBlockSize = Constants.Constants.GlobalPlatform.ApduLimits.MaxShortDataLength)
    {
        List<LoadBlock> blocks = [];
        byte blockNumber = 0;

        foreach (CapComponent component in GetLoadingComponents())
        {
            byte[] componentData = component.Data;
            int offset = 0;

            while (offset < componentData.Length)
            {
                int remainingBytes = componentData.Length - offset;
                int blockSize = Math.Min(remainingBytes, maxBlockSize);
                byte[] blockData = new byte[blockSize];

                Array.Copy(componentData, offset, blockData, 0, blockSize);

                bool isLastBlock =
                    offset + blockSize >= componentData.Length
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
            throw new InvalidDataException("Unexpected end of stream while reading component tag.");
        }

        int tagByte = stream.ReadByte();
        if (tagByte == -1)
        {
            throw new InvalidDataException("Unexpected end of stream while reading component tag.");
        }

        byte tag = (byte)tagByte;

        // Read size (2 bytes, big-endian)
        if (stream.Position + 1 >= stream.Length)
        {
            throw new InvalidDataException(
                "Unexpected end of stream while reading component size."
            );
        }

        int sizeHighByte = stream.ReadByte();
        int sizeLowByte = stream.ReadByte();
        if (sizeHighByte == -1 || sizeLowByte == -1)
        {
            throw new InvalidDataException(
                "Unexpected end of stream while reading component size."
            );
        }

        byte sizeHigh = (byte)sizeHighByte;
        byte sizeLow = (byte)sizeLowByte;
        ushort size = (ushort)(sizeHigh << 8 | sizeLow);

        // Check if we have enough data left in the stream
        if (stream.Position + size > stream.Length)
        {
            throw new InvalidDataException(
                $"Component claims size of {size} bytes, but only {stream.Length - stream.Position} bytes remaining in stream."
            );
        }

        // Read component data
        byte[] data = new byte[size];
        int bytesRead = stream.Read(data, 0, size);
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
        if (data.Length < Constants.Constants.JavaCard.CapHeader.MinimumSize) // Minimum header size
        {
            throw new InvalidDataException("Invalid header component data.");
        }

        int offset = 0;

        // Check for magic number (4 bytes: 0xDECAFFED)
        if (
            data.Length >= 4
            && data[0] == Constants.Constants.JavaCard.CapHeader.MagicNumber.Byte1
            && data[1] == Constants.Constants.JavaCard.CapHeader.MagicNumber.Byte2
            && data[2] == Constants.Constants.JavaCard.CapHeader.MagicNumber.Byte3
            && data[3] == Constants.Constants.JavaCard.CapHeader.MagicNumber.Byte4
        )
        {
            offset = 4; // Skip magic number
        }

        // Read CAP file minor version (1 byte)
        byte capMinorVersion = data[offset++];

        // Read CAP file major version (1 byte)
        byte capMajorVersion = data[offset++];

        // Read flags (1 byte)
        byte flags = data[offset++];

        // Skip package info (2 bytes - package name length and reserved)
        offset += 2;

        // Read package AID length
        byte packageAidLength = data[offset++];

        if (offset + packageAidLength > data.Length)
        {
            throw new InvalidDataException(
                $"Invalid header component data: need {offset + packageAidLength} bytes for AID, have {data.Length}."
            );
        }

        byte[] packageAid = new byte[packageAidLength];
        Array.Copy(data, offset, packageAid, 0, packageAidLength);
        offset += packageAidLength;

        // Package version may not be present in all formats
        byte packageMajor = Constants.Constants.JavaCard.DefaultVersion.PackageMajor;
        byte packageMinor = Constants.Constants.JavaCard.DefaultVersion.PackageMinor;

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
        List<AppletInfo> applets = [];
        int offset = 0;

        // Read count
        if (data.Length < 1)
        {
            return new AppletComponent(applets);
        }

        byte count = data[offset++];

        for (int i = 0; i < count; i++)
        {
            if (offset >= data.Length)
            {
                break;
            }

            // Read AID length
            byte aidLength = data[offset++];
            if (offset + aidLength + 2 > data.Length)
            {
                break;
            }

            // Read AID
            byte[] aid = new byte[aidLength];
            Array.Copy(data, offset, aid, 0, aidLength);
            offset += aidLength;

            // Read install method offset
            ushort installMethodOffset = (ushort)(data[offset] << 8 | data[offset + 1]);
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
    public string CapFileVersion { get; }

    /// <summary>
    /// Gets the Java Card converter version.
    /// </summary>
    public string ConverterVersion { get; }

    /// <summary>
    /// Gets the converter provider.
    /// </summary>
    public string ConverterProvider { get; }

    /// <summary>
    /// Gets the creation time.
    /// </summary>
    public string CreationTime { get; }

    /// <summary>
    /// Gets the package name.
    /// </summary>
    public string PackageName { get; }

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
        string capFileVersion = null,
        string converterVersion = null,
        string converterProvider = null,
        string creationTime = null,
        string packageName = null,
        IList<ImportedPackage> importedPackages = null,
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
        string[] lines = manifestContent.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Dictionary<string, string> properties = new Dictionary<string, string>();

        string currentKey = null;
        string currentValue = null;

        foreach (string line in lines)
        {
            string trimmedLine = line.Trim();
            if (
                string.IsNullOrEmpty(trimmedLine)
                || trimmedLine.StartsWith(Constants.Constants.JavaCard.IgnoredManifestHeaders.ManifestVersion)
                || trimmedLine.StartsWith(Constants.Constants.JavaCard.IgnoredManifestHeaders.Name)
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
                int colonIndex = trimmedLine.IndexOf(':');
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

        // Extract imported packages by searching through all properties for matching patterns
        var importedPackages = properties.Keys
            .Where(key => key.StartsWith(Constants.Constants.JavaCard.ManifestAttributes.ImportedPackageAidBase) 
                         && key.EndsWith(Constants.Constants.JavaCard.ManifestAttributes.ImportedPackageAidSuffix))
            .Select(aidKey => 
            {
                var prefix = aidKey.Substring(0, aidKey.Length - Constants.Constants.JavaCard.ManifestAttributes.ImportedPackageAidSuffix.Length);
                var versionKey = prefix + Constants.Constants.JavaCard.ManifestAttributes.ImportedPackageVersionSuffix;
                return new { AidKey = aidKey, VersionKey = versionKey };
            })
            .Where(keys => properties.ContainsKey(keys.VersionKey))
            .Select(keys => new ImportedPackage(properties[keys.AidKey], properties[keys.VersionKey]))
            .ToList();

        return new ManifestInfo(
            capFileVersion: properties.GetValueOrDefault(Constants.Constants.JavaCard.ManifestAttributes.CapFileVersion),
            converterVersion: properties.GetValueOrDefault(Constants.Constants.JavaCard.ManifestAttributes.ConverterVersion),
            converterProvider: properties.GetValueOrDefault(Constants.Constants.JavaCard.ManifestAttributes.ConverterProvider),
            creationTime: properties.GetValueOrDefault(Constants.Constants.JavaCard.ManifestAttributes.CreationTime),
            packageName: properties.GetValueOrDefault(Constants.Constants.JavaCard.ManifestAttributes.PackageName),
            importedPackages: importedPackages,
            integerSupportRequired: properties.GetValueOrDefault(
                Constants.Constants.JavaCard.ManifestAttributes.IntegerSupportRequired
            ) == Constants.Constants.JavaCard.ManifestAttributes.TrueValue
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
