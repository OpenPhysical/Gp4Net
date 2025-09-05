using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Constants;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Profiles;

/// <summary>
/// Loads card profiles from JSON files.
/// </summary>
[PublicAPI]
public static class CardProfileLoader
{
    /// <summary>
    /// Loads a card configuration from a JSON file.
    /// </summary>
    /// <param name="jsonPath">Path to the JSON profile file.</param>
    /// <returns>Result containing the card configuration or error.</returns>
    public static Result<CardConfiguration, SmartCardError> LoadFromFile(string jsonPath)
    {
        if (string.IsNullOrWhiteSpace(jsonPath))
        {
            return Result.Failure<CardConfiguration, SmartCardError>(
                SmartCardError.InvalidArgument("JSON path cannot be null or empty")
            );
        }

        if (!File.Exists(jsonPath))
        {
            return Result.Failure<CardConfiguration, SmartCardError>(
                SmartCardError.InvalidArgument($"Profile file not found: {jsonPath}")
            );
        }

        return Result
            .Try(
                () => File.ReadAllText(jsonPath),
                ex => SmartCardError.InvalidData($"Failed to read profile file: {ex.Message}")
            )
            .Bind(LoadFromJson);
    }

    /// <summary>
    /// Loads a card configuration from a JSON string.
    /// </summary>
    /// <param name="json">JSON content.</param>
    /// <returns>Result containing the card configuration or error.</returns>
    public static Result<CardConfiguration, SmartCardError> LoadFromJson(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return Result.Failure<CardConfiguration, SmartCardError>(
                SmartCardError.InvalidArgument("JSON content cannot be null or empty")
            );
        }

        JsonSerializerOptions options = new JsonSerializerOptions
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
                                        (byte scpVersion, ScpImplementation scpImplementation) =
                                            DetermineScpDefaults(profile);

                                        CardConfiguration config = new CardConfiguration(
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

        Result<byte[], SmartCardError> encResult = ParseHexString(profile.Keys.Enc, "ENC key");
        if (encResult.IsFailure)
            return Result.Failure<IKeySet, SmartCardError>(encResult.Error);

        Result<byte[], SmartCardError> macResult = ParseHexString(profile.Keys.Mac, "MAC key");
        if (macResult.IsFailure)
            return Result.Failure<IKeySet, SmartCardError>(macResult.Error);

        Result<byte[], SmartCardError> dekResult = ParseHexString(profile.Keys.Dek, "DEK key");
        if (dekResult.IsFailure)
            return Result.Failure<IKeySet, SmartCardError>(dekResult.Error);

        return profile.Type.ToUpperInvariant() switch
        {
            "SCP02" => Scp02KeySet
                .Create(encResult.Value, macResult.Value, dekResult.Value, version)
                .Map(ks => (IKeySet)ks),
            "SCP03" => Scp03KeySet
                .Create(encResult.Value, macResult.Value, dekResult.Value, version)
                .Map(ks => (IKeySet)ks),
            _ => Result.Failure<IKeySet, SmartCardError>(
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
            List<string> scp02Implementations = profile
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

    private static ImmutableList<byte> BuildSupportedInstructions()
    {
        // Standard GP instructions
        return ImmutableList.Create<byte>(
            0xA4, // SELECT
            0x50, // INITIALIZE UPDATE
            0x82, // EXTERNAL AUTHENTICATE
            0xCA, // GET DATA
            0xF2, // GET STATUS
            0xE6, // INSTALL
            0xE8, // LOAD
            0xE4, // DELETE
            0xD8, // PUT KEY
            0xDA, // PUT DATA
            0x70, // MANAGE CHANNEL
            0xF0 // MANAGE SECURE ENVIRONMENT
        );
    }

    private static Result<byte[], SmartCardError> ParseHexString(string hex, string fieldName)
    {
        if (string.IsNullOrWhiteSpace(hex))
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidData($"{fieldName} cannot be null or empty")
            );
        }

        // Remove any spaces or dashes
        string cleaned = hex.Replace(" ", "").Replace("-", "");

        // Ensure even number of characters
        if (cleaned.Length % 2 != 0)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidData($"{fieldName} must have even number of hex digits")
            );
        }

        return Result.Try(
            () => Convert.FromHexString(cleaned),
            ex => SmartCardError.InvalidData($"Failed to parse {fieldName}: {ex.Message}")
        );
    }
}

// JSON deserialization classes - All external data, so we handle nulls at boundaries
internal class CardProfile
{
    [JsonPropertyName("cardProfile")]
    public CardProfileInfo ProfileInfo { get; set; } = new();
    public ChipInfoProfile ChipInfo { get; set; } = new();
    public CardDataProfile CardData { get; set; } = new();
    public Dictionary<string, KeySetProfile> StaticKeys { get; set; } = new();
    public Dictionary<string, string> DataObjects { get; set; } = new();
}

internal class CardProfileInfo
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
}

internal class ChipInfoProfile
{
    public string Manufacturer { get; set; } = string.Empty;
    public string Platform { get; set; } = string.Empty;
    public string Model { get; set; } = string.Empty;
    public string MemoryConfig { get; set; } = string.Empty;
    public string Architecture { get; set; } = string.Empty;
}

internal class CardDataProfile
{
    public string Atr { get; set; } = string.Empty;
    public string IsdAid { get; set; } = string.Empty;
    public CplcProfile Cplc { get; set; } = new();
    public CapabilitiesProfile Capabilities { get; set; } = new();
    public List<KeyInfoProfile> KeyInfo { get; set; } = [];
}

internal class CplcProfile
{
    public string IcFabricator { get; set; } = string.Empty;
    public string IcType { get; set; } = string.Empty;
    public string OperatingSystemId { get; set; } = string.Empty;
}

internal class CapabilitiesProfile
{
    public List<ScpSupportProfile> ScpSupport { get; set; } = [];
}

internal class ScpSupportProfile
{
    public string Protocol { get; set; } = string.Empty;
    public List<string> Implementations { get; set; } = [];
}

internal class KeyInfoProfile
{
    public int Version { get; set; }
    public int Id { get; set; }
    public string Type { get; set; } = string.Empty;
    public int Length { get; set; }
}

internal class KeySetProfile
{
    public int Version { get; set; }
    public string Type { get; set; } = string.Empty;
    public KeysProfile Keys { get; set; } = new();
}

internal class KeysProfile
{
    public string Enc { get; set; } = string.Empty;
    public string Mac { get; set; } = string.Empty;
    public string Dek { get; set; } = string.Empty;
}
