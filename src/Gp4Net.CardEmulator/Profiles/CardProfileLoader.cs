using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Shared;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Profiles;

/// <summary>
/// Loads card emulator profiles from declarative JSON documents.
/// </summary>
/// <remarks>
/// Profile documents define ATR, static keys, data objects, and capability metadata used by the
/// virtual card emulator. See <c>specs/002-coverage-docs-enhancement/quickstart.md</c> for the JSON
/// schema conventions mirrored by the nested model types in this file.
/// </remarks>
[PublicAPI]
public static class CardProfileLoader
{
    /// <summary>
    /// Loads a card configuration from a JSON file on disk.
    /// </summary>
    /// <param name="jsonPath">Absolute or relative path to the JSON profile file.</param>
    /// <returns>
    /// A <see cref="Result{TValue,TError}"/> that yields a fully validated
    /// <see cref="CardConfiguration"/> on success, or a <see cref="SmartCardError"/> describing why
    /// the profile could not be consumed (missing file, invalid JSON, or semantic validation error).
    /// </returns>
    /// <example>
    /// var configuration = CardProfileLoader.LoadFromFile(\"profiles/p71.json\");
    /// configuration.Should().BeSuccess();
    /// </example>
    public static Result<CardConfiguration, SmartCardError> LoadFromFile(string jsonPath) =>
        Maybe<string>
            .From(jsonPath)
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .ToResult(Errors.EmptyArgument("JSON path"))
            .Ensure(
                File.Exists,
                SmartCardError.InvalidArgument($"Profile file not found: {jsonPath}")
            )
            .Bind(path =>
                Result.Try(
                    () => File.ReadAllText(path),
                    ex => SmartCardError.InvalidData($"Failed to read profile file: {ex.Message}")
                )
            )
            .Bind(LoadFromJson);

    /// <summary>
    /// Loads a card configuration from an in-memory JSON string.
    /// </summary>
    /// <param name="json">Raw JSON content that follows the card profile schema.</param>
    /// <returns>
    /// A <see cref="Result{TValue,TError}"/> describing whether deserialization and semantic
    /// validation were successful.
    /// </returns>
    /// <example>
    /// const string profileJson = """
    /// {
    ///   \"cardProfile\": { \"name\": \"Virtual Test\", \"description\": \"Integration demo\" },
    ///   \"cardData\": { \"atr\": \"3B00\", \"isdAid\": \"A000000151000000\" }
    /// }
    /// """;
    /// var configuration = CardProfileLoader.LoadFromJson(profileJson);
    /// </example>
    public static Result<CardConfiguration, SmartCardError> LoadFromJson(string json) =>
        Maybe<string>
            .From(json)
            .Where(content => !string.IsNullOrWhiteSpace(content))
            .ToResult(Errors.EmptyArgument("JSON content"))
            .Bind(ParseCardConfiguration);

    private static Result<CardConfiguration, SmartCardError> ParseCardConfiguration(string json)
    {
        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
        };

        return Result
            .Try(
                () => JsonSerializer.Deserialize<CardProfile>(json, options),
                ex =>
                    ex is JsonException
                        ? SmartCardError.InvalidData($"Invalid JSON format: {ex.Message}")
                        : SmartCardError.InvalidData($"Failed to load profile: {ex.Message}")
            )
            .Bind(profile =>
                Maybe<CardProfile>
                    .From(profile)
                    .ToResult(SmartCardError.InvalidData("Failed to deserialize JSON profile"))
                    .Bind(BuildConfiguration)
            );
    }

    private static Result<CardConfiguration, SmartCardError> BuildConfiguration(CardProfile profile)
    {
        // Parse ATR
        return ParseHexString(profile.CardData.Atr, "ATR")
            .Bind(atrBytes =>
                // Parse ISD AID
                ParseHexString(profile.CardData.IsdAid, "ISD AID")
                    .Bind(isdAidBytes =>
                        // Build static keys
                        BuildStaticKeys(profile.StaticKeys)
                            .Bind(staticKeys =>
                                // Build default data objects
                                BuildDataObjects(profile)
                                    .Bind(dataObjects =>
                                        DetermineScpDefaults(profile)
                                            .Bind(defaults =>
                                                BuildSupportedInstructions(
                                                        profile.CardData.Capabilities.Instructions
                                                    )
                                                    .Map(instructions => new CardConfiguration(
                                                        Atr: atrBytes,
                                                        IsdAid: isdAidBytes,
                                                        StaticKeys: staticKeys,
                                                        DefaultDataObjects: dataObjects,
                                                        SupportedInstructions: instructions,
                                                        CardType: string.IsNullOrEmpty(
                                                            profile.ProfileInfo.Description
                                                        )
                                                            ? "Custom Card"
                                                            : profile.ProfileInfo.Description,
                                                        DefaultScpVersion: defaults.scpVersion,
                                                        DefaultScpImplementation: defaults.scpImplementation,
                                                        SupportedAlgorithms: CardConfigurationAlgorithms.CreateStandardAlgorithms()
                                                    ))
                                            )
                                    )
                            )
                    )
            );
    }

    private static Result<ImmutableDictionary<byte, IKeySet>, SmartCardError> BuildStaticKeys(
        Dictionary<string, KeySetProfile> staticKeys
    )
    {
        if (staticKeys.Count == 0)
        {
            return Result.Success<ImmutableDictionary<byte, IKeySet>, SmartCardError>(
                ImmutableDictionary<byte, IKeySet>.Empty
            );
        }

        // Convert foreach loop to functional pattern using Aggregate
        return staticKeys.Aggregate(
            Result.Success<ImmutableDictionary<byte, IKeySet>, SmartCardError>(
                ImmutableDictionary<byte, IKeySet>.Empty
            ),
            (accResult, kvp) =>
                accResult.Bind(acc =>
                {
                    if (!byte.TryParse(kvp.Key, out byte keyVersion))
                    {
                        return Result.Failure<ImmutableDictionary<byte, IKeySet>, SmartCardError>(
                            SmartCardError.InvalidData($"Invalid key version: {kvp.Key}")
                        );
                    }

                    return BuildKeySet(kvp.Value, keyVersion)
                        .Map(keySet => acc.SetItem(keyVersion, keySet));
                })
        );
    }

    private static Result<IKeySet, SmartCardError> BuildKeySet(KeySetProfile profile, byte version)
    {
        // Keys is now non-nullable, no need to check

        var encResult = ParseHexString(profile.Keys.Enc, "ENC key");
        if (encResult.IsFailure)
            return Result.Failure<IKeySet, SmartCardError>(encResult.Error);

        var macResult = ParseHexString(profile.Keys.Mac, "MAC key");
        if (macResult.IsFailure)
            return Result.Failure<IKeySet, SmartCardError>(macResult.Error);

        var dekResult = ParseHexString(profile.Keys.Dek, "DEK key");
        if (dekResult.IsFailure)
            return Result.Failure<IKeySet, SmartCardError>(dekResult.Error);

        return profile.Type.ToUpperInvariant() switch
        {
            "SCP02"
                => Scp02KeySet
                    .Create(encResult.Value, macResult.Value, dekResult.Value, version)
                    .Map(ks => (IKeySet)ks),
            "SCP03"
                => Scp03KeySet
                    .Create(encResult.Value, macResult.Value, dekResult.Value, version)
                    .Map(ks => (IKeySet)ks),
            _
                => Result.Failure<IKeySet, SmartCardError>(
                    SmartCardError.InvalidData($"Unknown key set type: {profile.Type}")
                ),
        };
    }

    private static Result<ImmutableDictionary<ushort, byte[]>, SmartCardError> BuildDataObjects(
        CardProfile profile
    )
    {
        return profile
            .DataObjects.Select(kvp => ProcessDataObjectEntry(kvp.Key, kvp.Value))
            .Where(result => result.HasValue)
            .Select(maybeResult => maybeResult.Value)
            .Aggregate(
                Result.Success<ImmutableDictionary<ushort, byte[]>.Builder, SmartCardError>(
                    ImmutableDictionary.CreateBuilder<ushort, byte[]>()
                ),
                (accumulator, dataObjectResult) =>
                    accumulator.Bind(builder =>
                        dataObjectResult.Map(dataObject =>
                        {
                            builder.Add(dataObject.Tag, dataObject.Data);
                            return builder;
                        })
                    )
            )
            .Map(builder => builder.ToImmutable());
    }

    private record DataObject(ushort Tag, byte[] Data);

    private static Maybe<Result<DataObject, SmartCardError>> ProcessDataObjectEntry(
        string key,
        string value
    )
    {
        return Maybe
            .From(value)
            .Where(v => !string.IsNullOrEmpty(v))
            .Map(_ =>
                ValidateDataObjectKey(key)
                    .Bind(tag =>
                        ParseHexString(value, $"Data object {key}")
                            .Map(data => new DataObject(tag, data))
                    )
            );
    }

    private static Result<ushort, SmartCardError> ValidateDataObjectKey(string key)
    {
        if (!key.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return Result.Failure<ushort, SmartCardError>(
                SmartCardError.InvalidData($"Data object tag must be in hex format: {key}")
            );

        return Result
            .Try(() => Convert.ToUInt16(key[2..], 16))
            .MapError(_ => SmartCardError.InvalidData($"Invalid data object tag: {key}"));
    }

    private static Result<
        (byte scpVersion, ScpImplementation scpImplementation),
        SmartCardError
    > DetermineScpDefaults(CardProfile profile)
    {
        var declared = profile.CardData.Capabilities.ScpSupport;
        if (declared.Count == 0)
            return SmartCardError.InvalidData(
                "A card profile must explicitly declare a secure-channel protocol"
            );

        foreach (ScpSupportProfile support in declared)
        {
            if (support.Protocol is not ("0x02" or "0x03"))
                return SmartCardError.InvalidData($"Unsupported protocol: {support.Protocol}");

            foreach (string value in support.Implementations)
            {
                if (
                    !value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                    || !byte.TryParse(
                        value.AsSpan(2),
                        System.Globalization.NumberStyles.HexNumber,
                        null,
                        out byte implementation
                    )
                )
                    return SmartCardError.InvalidData($"Invalid SCP implementation: {value}");

                bool supported =
                    support.Protocol == "0x02"
                        ? implementation is 0x05 or 0x15 or 0x25 or 0x35
                        : implementation is 0x00 or 0x10 or 0x20 or 0x30 or 0x60 or 0x70;
                if (!supported)
                    return SmartCardError.InvalidData(
                        $"Unsupported {support.Protocol} implementation: {value}"
                    );
            }
        }

        ScpSupportProfile selected = declared[0];
        if (selected.Implementations.Count == 0)
            return SmartCardError.InvalidData("The default SCP protocol has no implementation");

        string preferred =
            selected.Protocol == "0x02" && selected.Implementations.Contains("0x15")
                ? "0x15"
                : selected.Protocol == "0x03" && selected.Implementations.Contains("0x70")
                    ? "0x70"
                    : selected.Implementations[0];
        byte selectedValue = byte.Parse(
            preferred.AsSpan(2),
            System.Globalization.NumberStyles.HexNumber
        );
        byte protocol = selected.Protocol == "0x03" ? (byte)0x03 : (byte)0x02;
        bool matchingKeys = profile.StaticKeys.Values.Any(key =>
            string.Equals(
                key.Type,
                protocol == 0x03 ? "SCP03" : "SCP02",
                StringComparison.OrdinalIgnoreCase
            )
        );
        return matchingKeys
            ? Result.Success<(byte, ScpImplementation), SmartCardError>(
                (protocol, (ScpImplementation)selectedValue)
            )
            : Result.Failure<(byte, ScpImplementation), SmartCardError>(
                SmartCardError.InvalidData(
                    $"The default {selected.Protocol} protocol has no matching static keyset"
                )
            );
    }

    private static Result<SupportedInstructions, SmartCardError> BuildSupportedInstructions(
        InstructionSupportProfile instructions
    ) =>
        instructions.ManageChannel
            ? Result.Failure<SupportedInstructions, SmartCardError>(
                SmartCardError.InvalidData(
                    "MANAGE CHANNEL cannot be advertised until logical channels are implemented"
                )
            )
            : Result.Success<SupportedInstructions, SmartCardError>(
                new SupportedInstructions(
                    Select: instructions.Select,
                    InitializeUpdate: instructions.InitializeUpdate,
                    ExternalAuthenticate: instructions.ExternalAuthenticate,
                    GetData: instructions.GetData,
                    GetStatus: instructions.GetStatus,
                    Install: instructions.Install,
                    Load: instructions.Load,
                    Delete: instructions.Delete,
                    PutKey: instructions.PutKey,
                    StoreData: instructions.StoreData,
                    SetStatus: instructions.SetStatus,
                    ManageChannel: false
                )
            );

    private static Result<byte[], SmartCardError> ParseHexString(string hex, string fieldName) =>
        Maybe<string>
            .From(hex)
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .ToResult(Errors.EmptyArgument(fieldName))
            .Map(h => h.Replace(" ", "").Replace("-", ""))
            .Ensure(
                cleaned => cleaned.Length % 2 == 0,
                SmartCardError.InvalidData($"{fieldName} must have even number of hex digits")
            )
            .Bind(cleaned => ConvertHexToBytes(cleaned, fieldName));

    private static Result<byte[], SmartCardError> ConvertHexToBytes(
        string cleaned,
        string fieldName
    )
    {
        return Result.Try(
            () => Convert.FromHexString(cleaned),
            ex => SmartCardError.InvalidData($"Failed to parse {fieldName}: {ex.Message}")
        );
    }
}

// JSON deserialization classes - All external data, so we handle nulls at boundaries
/// <summary>
/// Strongly typed representation of the top-level card profile JSON document.
/// </summary>
/// <remarks>
/// Mirrors the schema documented in <c>specs/002-coverage-docs-enhancement/quickstart.md</c>.
/// Each property targets a JSON object that describes a facet of the virtual card.
/// </remarks>
internal class CardProfile
{
    /// <summary>
    /// Gets or sets human-readable profile information metadata.
    /// </summary>
    /// <value>Maps the <c>cardProfile</c> JSON object.</value>
    [JsonPropertyName("cardProfile")]
    public CardProfileInfo ProfileInfo { get; set; } = new();

    /// <summary>
    /// Gets or sets chip-level manufacturing information.
    /// </summary>
    /// <value>Maps the <c>chipInfo</c> JSON object.</value>
    public ChipInfoProfile ChipInfo { get; set; } = new();

    /// <summary>
    /// Gets or sets card data that influences secure channel defaults.
    /// </summary>
    /// <value>Maps the <c>cardData</c> JSON object.</value>
    public CardDataProfile CardData { get; set; } = new();

    /// <summary>
    /// Gets or sets the static key sets keyed by version number.
    /// </summary>
    /// <value>Maps the <c>staticKeys</c> JSON object.</value>
    public Dictionary<string, KeySetProfile> StaticKeys { get; set; } = new();

    /// <summary>
    /// Gets or sets default data objects that should be seeded on the card.
    /// </summary>
    /// <value>Maps the <c>dataObjects</c> JSON object using tag/value pairs.</value>
    public Dictionary<string, string> DataObjects { get; set; } = new();
}

/// <summary>
/// Describes the <c>cardProfile</c> JSON object.
/// </summary>
internal class CardProfileInfo
{
    /// <summary>
    /// Gets or sets the internal identifier for the profile.
    /// </summary>
    /// <value>Matches the <c>name</c> field in JSON.</value>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets a human-readable description of the profile's purpose.
    /// </summary>
    /// <value>Matches the <c>description</c> field in JSON.</value>
    public string Description { get; set; } = string.Empty;
}

/// <summary>
/// Represents the <c>chipInfo</c> section of the card profile.
/// </summary>
internal class ChipInfoProfile
{
    /// <summary>
    /// Gets or sets the silicon manufacturer name.
    /// </summary>
    /// <value>Maps the <c>manufacturer</c> field.</value>
    public string Manufacturer { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the target platform identifier.
    /// </summary>
    /// <value>Maps the <c>platform</c> field.</value>
    public string Platform { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the chipset model identifier.
    /// </summary>
    /// <value>Maps the <c>model</c> field.</value>
    public string Model { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the memory configuration summary.
    /// </summary>
    /// <value>Maps the <c>memoryConfig</c> field.</value>
    public string MemoryConfig { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the CPU architecture description.
    /// </summary>
    /// <value>Maps the <c>architecture</c> field.</value>
    public string Architecture { get; set; } = string.Empty;
}

/// <summary>
/// Represents the <c>cardData</c> section of the JSON profile.
/// </summary>
internal class CardDataProfile
{
    /// <summary>
    /// Gets or sets the ATR string encoded in the profile.
    /// </summary>
    /// <value>Maps the <c>atr</c> field.</value>
    public string Atr { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the ISD AID string encoded in the profile.
    /// </summary>
    /// <value>Maps the <c>isdAid</c> field.</value>
    public string IsdAid { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets optional CPLC data used to tag production cards.
    /// </summary>
    /// <value>Maps the <c>cplc</c> object.</value>
    public CplcProfile Cplc { get; set; } = new();

    /// <summary>
    /// Gets or sets capability declarations that drive secure channel detection.
    /// </summary>
    /// <value>Maps the <c>capabilities</c> object.</value>
    public CapabilitiesProfile Capabilities { get; set; } = new();

    /// <summary>
    /// Gets or sets known key metadata for the physical card.
    /// </summary>
    /// <value>Maps the <c>keyInfo</c> array.</value>
    public List<KeyInfoProfile> KeyInfo { get; set; } = [];
}

/// <summary>
/// Represents the <c>cplc</c> subsection of the card profile.
/// </summary>
internal class CplcProfile
{
    /// <summary>
    /// Gets or sets the IC fabricator identifier in hexadecimal form.
    /// </summary>
    /// <value>Maps the <c>icFabricator</c> field.</value>
    public string IcFabricator { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the IC type identifier in hexadecimal form.
    /// </summary>
    /// <value>Maps the <c>icType</c> field.</value>
    public string IcType { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the operating system identifier.
    /// </summary>
    /// <value>Maps the <c>operatingSystemId</c> field.</value>
    public string OperatingSystemId { get; set; } = string.Empty;
}

/// <summary>
/// Represents the <c>capabilities</c> subsection of the card profile.
/// </summary>
internal class CapabilitiesProfile
{
    /// <summary>
    /// Gets or sets the collection of secure channel protocol declarations.
    /// </summary>
    /// <value>Maps the <c>scpSupport</c> array.</value>
    public List<ScpSupportProfile> ScpSupport { get; set; } = [];

    /// <summary>Gets or sets the APDU instructions exposed by this profile.</summary>
    public InstructionSupportProfile Instructions { get; set; } = new();
}

/// <summary>Executable APDU capabilities declared by a card profile.</summary>
internal sealed class InstructionSupportProfile
{
    public bool Select { get; set; } = true;
    public bool InitializeUpdate { get; set; } = true;
    public bool ExternalAuthenticate { get; set; } = true;
    public bool GetData { get; set; } = true;
    public bool GetStatus { get; set; } = true;
    public bool Install { get; set; } = true;
    public bool Load { get; set; } = true;
    public bool Delete { get; set; } = true;
    public bool PutKey { get; set; } = true;
    public bool StoreData { get; set; } = true;
    public bool SetStatus { get; set; } = true;
    public bool ManageChannel { get; set; }
}

/// <summary>
/// Represents an entry in the <c>scpSupport</c> array.
/// </summary>
internal class ScpSupportProfile
{
    /// <summary>
    /// Gets or sets the secure channel protocol identifier (for example <c>0x03</c>).
    /// </summary>
    /// <value>Maps the <c>protocol</c> field.</value>
    public string Protocol { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the supported implementation values for the protocol.
    /// </summary>
    /// <value>Maps the <c>implementations</c> array.</value>
    public List<string> Implementations { get; set; } = [];
}

/// <summary>
/// Represents an entry in the <c>keyInfo</c> array.
/// </summary>
internal class KeyInfoProfile
{
    /// <summary>
    /// Gets or sets the key version number.
    /// </summary>
    /// <value>Maps the <c>version</c> field.</value>
    public int Version { get; set; }

    /// <summary>
    /// Gets or sets the key identifier.
    /// </summary>
    /// <value>Maps the <c>id</c> field.</value>
    public int Id { get; set; }

    /// <summary>
    /// Gets or sets the key type (for example <c>AES</c> or <c>DES</c>).
    /// </summary>
    /// <value>Maps the <c>type</c> field.</value>
    public string Type { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the key length in bits.
    /// </summary>
    /// <value>Maps the <c>length</c> field.</value>
    public int Length { get; set; }
}

/// <summary>
/// Represents the <c>staticKeys</c> subsection for a single key version.
/// </summary>
internal class KeySetProfile
{
    /// <summary>
    /// Gets or sets the key version that the static keys belong to.
    /// </summary>
    /// <value>Maps the <c>version</c> field.</value>
    public int Version { get; set; }

    /// <summary>
    /// Gets or sets the secure channel protocol identifier expected by the key set.
    /// </summary>
    /// <value>Maps the <c>type</c> field (for example <c>SCP02</c>).</value>
    public string Type { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the ENC/MAC/DEK key values for the key set.
    /// </summary>
    /// <value>Maps the <c>keys</c> object.</value>
    public KeysProfile Keys { get; set; } = new();
}

/// <summary>
/// Represents the <c>keys</c> object attached to a static key set.
/// </summary>
internal class KeysProfile
{
    /// <summary>
    /// Gets or sets the ENC (encryption) key encoded as hexadecimal.
    /// </summary>
    /// <value>Maps the <c>enc</c> field.</value>
    public string Enc { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the MAC key encoded as hexadecimal.
    /// </summary>
    /// <value>Maps the <c>mac</c> field.</value>
    public string Mac { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the DEK (data encryption) key encoded as hexadecimal.
    /// </summary>
    /// <value>Maps the <c>dek</c> field.</value>
    public string Dek { get; set; } = string.Empty;
}
