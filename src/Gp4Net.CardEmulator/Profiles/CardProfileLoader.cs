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
                                    .Map(dataObjects =>
                                    {
                                        // Determine SCP version and implementation
                                        (byte scpVersion, var scpImplementation) =
                                            DetermineScpDefaults(profile);

                                        var config = new CardConfiguration(
                                            Atr: atrBytes,
                                            IsdAid: isdAidBytes,
                                            StaticKeys: staticKeys,
                                            DefaultDataObjects: dataObjects,
                                            SupportedInstructions: BuildSupportedInstructions(),
                                            CardType: string.IsNullOrEmpty(
                                                profile.ProfileInfo.Description
                                            )
                                                ? "Custom Card"
                                                : profile.ProfileInfo.Description,
                                            DefaultScpVersion: scpVersion,
                                            DefaultScpImplementation: scpImplementation,
                                            SupportedAlgorithms: CardConfigurationAlgorithms.CreateStandardAlgorithms()
                                        );

                                        return config;
                                    })
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

    private static (byte scpVersion, ScpImplementation scpImplementation) DetermineScpDefaults(
        CardProfile profile
    )
    {
        // Check if card has SCP03 support
        bool hasScp03 = profile.CardData.Capabilities.ScpSupport.Any(s => s.Protocol == "0x03");
        bool hasScp02 = profile.CardData.Capabilities.ScpSupport.Any(s => s.Protocol == "0x02");

        // Determine based on key type
        bool hasAesKeys = profile.CardData.KeyInfo.Any(k => k.Type == "AES");

        if (hasScp03 || hasAesKeys)
        {
            // Default to SCP03 i=70 for cards with SCP03 support
            return (0x03, ScpImplementation.Scp03I70);
        }
        if (hasScp02)
        {
            // Check if card explicitly supports SCP02 i=15 (prefer it over i=55)
            var scp02Implementations = profile
                .CardData.Capabilities.ScpSupport.Where(s => s.Protocol == "0x02")
                .SelectMany(s => s.Implementations)
                .ToList();

            if (scp02Implementations.Contains("0x15"))
            {
                return (0x02, ScpImplementation.Scp02I15);
            }
            // Default to SCP02 i=55 for SCP02-only cards
            return (0x02, ScpImplementation.Scp02I55);
        }

        // Fallback to SCP02 i=15
        return (0x02, ScpImplementation.Scp02I15);
    }

    private static SupportedInstructions BuildSupportedInstructions()
    {
        // Standard GP instructions with type safety
        return new SupportedInstructions(
            Select: true,
            InitializeUpdate: true,
            ExternalAuthenticate: true,
            GetData: true,
            GetStatus: true,
            Install: true,
            Load: true,
            Delete: true,
            PutKey: true,
            StoreData: true,
            ManageChannel: true
        );
    }

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
