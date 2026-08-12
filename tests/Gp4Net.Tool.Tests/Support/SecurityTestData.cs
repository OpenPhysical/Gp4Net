using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace Gp4Net.Tool.Tests.Support;

internal static class SecurityTestData
{
    private static readonly Lazy<string> RepoRoot = new(LocateRepositoryRoot);
    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web)
        {
            AllowTrailingCommas = true,
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
        };

    private static string TestDataRoot => Path.Combine(RepoRoot.Value, "tests", "TestData");

    public static string RepositoryRoot => RepoRoot.Value;

    public static KeySetDocument LoadGpDefaultKeys() =>
        LoadJson<KeySetDocument>("security/gp-default-keys.json");

    public static Scp02KeyDerivationDocument LoadScp02KeyDerivationVectors() =>
        LoadJson<Scp02KeyDerivationDocument>("scp02/key-derivation-vectors.json");

    public static Scp02CryptogramDocument LoadScp02CryptogramVectors() =>
        LoadJson<Scp02CryptogramDocument>("scp02/cryptogram-vectors.json");

    public static Scp03KeyDerivationDocument LoadScp03KeyDerivationVectors() =>
        LoadJson<Scp03KeyDerivationDocument>("scp03/key-derivation-vectors.json");

    public static Scp03CryptogramDocument LoadScp03CryptogramVectors() =>
        LoadJson<Scp03CryptogramDocument>("scp03/cryptogram-vectors.json");

    private static T LoadJson<T>(string relativePath)
    {
        string absolutePath = Path.Combine(
            TestDataRoot,
            relativePath.Replace('/', Path.DirectorySeparatorChar)
        );

        if (!File.Exists(absolutePath))
        {
            throw new FileNotFoundException($"Test data file not found: {absolutePath}");
        }

        using FileStream stream = File.OpenRead(absolutePath);
        return JsonSerializer.Deserialize<T>(stream, JsonOptions)
            ?? throw new InvalidOperationException(
                $"Failed to deserialize test data from {absolutePath}"
            );
    }

    private static string LocateRepositoryRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);

        while (current != null)
        {
            if (current.GetFiles("Gp4Net.sln").Any())
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate repository root (Gp4Net.sln)");
    }
}

internal sealed record KeySetDocument(
    string Description,
    string Reference,
    IReadOnlyList<KeySetEntry> Keys
);

internal sealed record KeySetEntry(
    string Name,
    string Hex,
    string Description,
    int KeyVersionNumber,
    int KeyId,
    string Usage
);

internal sealed record KeyComponents(string Enc, string Mac, string Dek);

internal sealed record Scp02Challenges(string Host, string Card, string SequenceCounter);

internal sealed record Scp03Challenges(string Host, string Card);

internal sealed record SessionKeys(string Enc, string Mac, string? Dek, string? Rmac);

internal sealed record CryptogramData(string Card, string Host);

internal sealed record CryptogramPair(string Card, string Host);

internal sealed record Scp02KeyDerivationDocument(
    string Description,
    string Reference,
    IReadOnlyList<Scp02KeyDerivationVector> Vectors
);

internal sealed record Scp02KeyDerivationVector(
    string Name,
    KeyComponents StaticKeys,
    Scp02Challenges Challenges,
    SessionKeys ExpectedSessionKeys
);

internal sealed record Scp02CryptogramDocument(
    string Description,
    string Reference,
    IReadOnlyList<Scp02CryptogramVector> Vectors
);

internal sealed record Scp02CryptogramVector(
    string Name,
    KeyComponents StaticKeys,
    SessionKeys SessionKeys,
    CryptogramData CryptogramData,
    CryptogramPair ExpectedCryptograms
);

internal sealed record Scp03KeyDerivationDocument(
    string Description,
    string Reference,
    IReadOnlyList<Scp03KeyDerivationVector> Vectors
);

internal sealed record Scp03KeyDerivationVector(
    string Name,
    KeyComponents StaticKeys,
    Scp03Challenges Challenges,
    SessionKeys ExpectedSessionKeys
);

internal sealed record Scp03CryptogramDocument(
    string Description,
    string Reference,
    IReadOnlyList<Scp03CryptogramVector> Vectors
);

internal sealed record Scp03CryptogramVector(
    string Name,
    KeyComponents StaticKeys,
    SessionKeys SessionKeys,
    Scp03Challenges Challenges,
    CryptogramPair ExpectedCryptograms
);
