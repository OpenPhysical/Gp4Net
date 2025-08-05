// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using JetBrains.Annotations;

namespace Gp4Net.Tests.TestVectors;

/// <summary>
/// Common interface for all SCP test vectors loaded from JSON files.
/// All test vectors are sourced from verified Python reference implementations.
/// </summary>
[PublicAPI]
public interface IScpTestVector
{
    /// <summary>
    /// Descriptive name for this test vector.
    /// </summary>
    string Name { get; }
    
    /// <summary>
    /// Description of what this test vector validates.
    /// </summary>
    string Description { get; }
    
    /// <summary>
    /// Source file that generated this test vector.
    /// </summary>
    string Source { get; }
    
    /// <summary>
    /// SCP protocol version (02 or 03).
    /// </summary>
    string Protocol { get; }
    
    /// <summary>
    /// Static encryption key.
    /// </summary>
    byte[] StaticEncKey { get; }
    
    /// <summary>
    /// Static MAC key.
    /// </summary>
    byte[] StaticMacKey { get; }
    
    /// <summary>
    /// Static Data Encryption Key.
    /// </summary>
    byte[] StaticDekKey { get; }
    
    /// <summary>
    /// Host challenge.
    /// </summary>
    byte[] HostChallenge { get; }
    
    /// <summary>
    /// Card challenge.
    /// </summary>
    byte[] CardChallenge { get; }
    
    /// <summary>
    /// Expected derived session encryption key.
    /// </summary>
    byte[] ExpectedSEncKey { get; }
    
    /// <summary>
    /// Expected derived session MAC key.
    /// </summary>
    byte[] ExpectedSMacKey { get; }
    
    /// <summary>
    /// Expected card cryptogram.
    /// </summary>
    byte[] ExpectedCardCryptogram { get; }
    
    /// <summary>
    /// Expected host cryptogram.
    /// </summary>
    byte[] ExpectedHostCryptogram { get; }
}

/// <summary>
/// SCP02 test vector loaded from JSON file.
/// Source: scripts/scp02_test_vectors.json (generated from scripts/SCP02_minimal.py)
/// </summary>
[PublicAPI]
public record Scp02TestVector : IScpTestVector
{
    public required string Name { get; init; }
    public required string Description { get; init; }
    public required string Source { get; init; }
    public string Protocol
    {
        get
        {
            return "SCP02";
        }
    }

    /// <summary>
    /// SCP02 implementation option (i parameter).
    /// </summary>
    public required string ImplementationOption { get; init; }
    
    public required byte[] StaticEncKey { get; init; }
    public required byte[] StaticMacKey { get; init; }
    public required byte[] StaticDekKey { get; init; }
    
    public required byte[] HostChallenge { get; init; }
    public required byte[] CardChallenge { get; init; }
    
    /// <summary>
    /// SCP02 sequence counter.
    /// </summary>
    public required byte[] SequenceCounter { get; init; }
    
    public required byte[] ExpectedSEncKey { get; init; }
    public required byte[] ExpectedSMacKey { get; init; }
    
    /// <summary>
    /// Expected derived session Data Encryption Key.
    /// </summary>
    public required byte[] ExpectedSDekKey { get; init; }
    
    /// <summary>
    /// Card cryptogram data used for calculation (24 bytes with ISO 7816-4 padding).
    /// </summary>
    public required byte[] CardCryptogramData { get; init; }
    
    /// <summary>
    /// Host cryptogram data used for calculation (24 bytes with ISO 7816-4 padding).
    /// </summary>
    public required byte[] HostCryptogramData { get; init; }
    
    public required byte[] ExpectedCardCryptogram { get; init; }
    public required byte[] ExpectedHostCryptogram { get; init; }
}

/// <summary>
/// SCP03 test vector loaded from JSON file.
/// Source: scripts/scp03_test_vectors.json (generated from scripts/SCP03_minimal.py)
/// </summary>
[PublicAPI]
public record Scp03TestVector : IScpTestVector
{
    public required string Name { get; init; }
    public required string Description { get; init; }
    public required string Source { get; init; }
    public string Protocol
    {
        get
        {
            return "SCP03";
        }
    }

    public required byte[] StaticEncKey { get; init; }
    public required byte[] StaticMacKey { get; init; }
    public required byte[] StaticDekKey { get; init; }
    
    public required byte[] HostChallenge { get; init; }
    public required byte[] CardChallenge { get; init; }
    
    public required byte[] ExpectedSEncKey { get; init; }
    public required byte[] ExpectedSMacKey { get; init; }
    
    /// <summary>
    /// Expected derived session R-MAC key.
    /// </summary>
    public required byte[] ExpectedSRMacKey { get; init; }
    
    public required byte[] ExpectedCardCryptogram { get; init; }
    public required byte[] ExpectedHostCryptogram { get; init; }
}

/// <summary>
/// SCP02 C-MAC test vector for command MAC validation.
/// </summary>
[PublicAPI]
public record Scp02CMacTestVector
{
    public required string Name { get; init; }
    public required string Description { get; init; }
    public required string Source { get; init; }
    
    public required byte[] MacKey { get; init; }
    public required byte[] CommandData { get; init; }
    public required byte[] ExpectedCMac { get; init; }
}

/// <summary>
/// Unified SCP test vector loader that reads from JSON files generated by verified Python scripts.
/// Ensures complete traceability of all test vectors to their authoritative sources.
/// </summary>
[PublicAPI]
public static class ScpTestVectors
{
    private static readonly Lazy<IReadOnlyList<Scp02TestVector>> _scp02Vectors = 
        new(() => LoadScp02Vectors().AsReadOnly());
    
    private static readonly Lazy<IReadOnlyList<Scp03TestVector>> _scp03Vectors = 
        new(() => LoadScp03Vectors().AsReadOnly());
    
    private static readonly Lazy<IReadOnlyList<Scp02CMacTestVector>> _scp02CMacVectors = 
        new(() => LoadScp02CMacVectors().AsReadOnly());

    /// <summary>
    /// All SCP02 test vectors from scripts/scp02_test_vectors.json.
    /// Generated from scripts/SCP02_minimal.py - verified reference implementation.
    /// </summary>
    public static IReadOnlyList<Scp02TestVector> Scp02Vectors
    {
        get
        {
            return _scp02Vectors.Value;
        }
    }

    /// <summary>
    /// All SCP03 test vectors from scripts/scp03_test_vectors.json.
    /// Generated from scripts/SCP03_minimal.py - verified reference implementation.
    /// </summary>
    public static IReadOnlyList<Scp03TestVector> Scp03Vectors
    {
        get
        {
            return _scp03Vectors.Value;
        }
    }

    /// <summary>
    /// All SCP02 C-MAC test vectors for command MAC validation.
    /// </summary>
    public static IReadOnlyList<Scp02CMacTestVector> Scp02CMacVectors
    {
        get
        {
            return _scp02CMacVectors.Value;
        }
    }

    /// <summary>
    /// All SCP test vectors (both SCP02 and SCP03) as common interface.
    /// </summary>
    public static IReadOnlyList<IScpTestVector> AllVectors
    {
        get
        {
            return Scp02Vectors.Cast<IScpTestVector>()
                .Concat(Scp03Vectors.Cast<IScpTestVector>())
                .ToList()
                .AsReadOnly();
        }
    }

    /// <summary>
    /// Gets a specific SCP02 test vector by name.
    /// </summary>
    public static Scp02TestVector GetScp02Vector(string name) =>
        Scp02Vectors.FirstOrDefault(v => v.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
        ?? throw new ArgumentException($"SCP02 test vector '{name}' not found");

    /// <summary>
    /// Gets a specific SCP03 test vector by name.
    /// </summary>
    public static Scp03TestVector GetScp03Vector(string name) =>
        Scp03Vectors.FirstOrDefault(v => v.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
        ?? throw new ArgumentException($"SCP03 test vector '{name}' not found");

    private static List<Scp02TestVector> LoadScp02Vectors()
    {
        var jsonPath = GetJsonFilePath("scp02_test_vectors.json");
        var jsonContent = File.ReadAllText(jsonPath);
        var document = JsonDocument.Parse(jsonContent);
        
        var root = document.RootElement;
        var source = root.GetProperty("source").GetString()!;
        var vectors = new List<Scp02TestVector>();
        
        foreach (var vectorElement in root.GetProperty("vectors").EnumerateArray())
        {
            vectors.Add(new Scp02TestVector
            {
                Name = vectorElement.GetProperty("name").GetString()!,
                Description = vectorElement.GetProperty("description").GetString()!,
                Source = source,
                ImplementationOption = vectorElement.GetProperty("implementation_option").GetString()!,
                
                StaticEncKey = Convert.FromHexString(vectorElement.GetProperty("static_keys").GetProperty("enc").GetString()!),
                StaticMacKey = Convert.FromHexString(vectorElement.GetProperty("static_keys").GetProperty("mac").GetString()!),
                StaticDekKey = Convert.FromHexString(vectorElement.GetProperty("static_keys").GetProperty("dek").GetString()!),
                
                HostChallenge = Convert.FromHexString(vectorElement.GetProperty("challenges").GetProperty("host").GetString()!),
                CardChallenge = Convert.FromHexString(vectorElement.GetProperty("challenges").GetProperty("card").GetString()!),
                SequenceCounter = Convert.FromHexString(vectorElement.GetProperty("challenges").GetProperty("sequence_counter").GetString()!),
                
                ExpectedSEncKey = Convert.FromHexString(vectorElement.GetProperty("expected_session_keys").GetProperty("s_enc").GetString()!),
                ExpectedSMacKey = Convert.FromHexString(vectorElement.GetProperty("expected_session_keys").GetProperty("s_mac").GetString()!),
                ExpectedSDekKey = Convert.FromHexString(vectorElement.GetProperty("expected_session_keys").GetProperty("s_dek").GetString()!),
                
                CardCryptogramData = Convert.FromHexString(vectorElement.GetProperty("cryptogram_data").GetProperty("card").GetString()!),
                HostCryptogramData = Convert.FromHexString(vectorElement.GetProperty("cryptogram_data").GetProperty("host").GetString()!),
                
                ExpectedCardCryptogram = Convert.FromHexString(vectorElement.GetProperty("expected_cryptograms").GetProperty("card").GetString()!),
                ExpectedHostCryptogram = Convert.FromHexString(vectorElement.GetProperty("expected_cryptograms").GetProperty("host").GetString()!)
            });
        }
        
        return vectors;
    }
    
    private static List<Scp03TestVector> LoadScp03Vectors()
    {
        var jsonPath = GetJsonFilePath("scp03_test_vectors.json");
        var jsonContent = File.ReadAllText(jsonPath);
        var document = JsonDocument.Parse(jsonContent);
        
        var root = document.RootElement;
        var source = root.GetProperty("source").GetString()!;
        var vectors = new List<Scp03TestVector>();
        
        foreach (var vectorElement in root.GetProperty("vectors").EnumerateArray())
        {
            vectors.Add(new Scp03TestVector
            {
                Name = vectorElement.GetProperty("name").GetString()!,
                Description = vectorElement.GetProperty("description").GetString()!,
                Source = source,
                
                StaticEncKey = Convert.FromHexString(vectorElement.GetProperty("static_keys").GetProperty("enc").GetString()!),
                StaticMacKey = Convert.FromHexString(vectorElement.GetProperty("static_keys").GetProperty("mac").GetString()!),
                StaticDekKey = Convert.FromHexString(vectorElement.GetProperty("static_keys").GetProperty("dek").GetString()!),
                
                HostChallenge = Convert.FromHexString(vectorElement.GetProperty("challenges").GetProperty("host").GetString()!),
                CardChallenge = Convert.FromHexString(vectorElement.GetProperty("challenges").GetProperty("card").GetString()!),
                
                ExpectedSEncKey = Convert.FromHexString(vectorElement.GetProperty("expected_session_keys").GetProperty("s_enc").GetString()!),
                ExpectedSMacKey = Convert.FromHexString(vectorElement.GetProperty("expected_session_keys").GetProperty("s_mac").GetString()!),
                ExpectedSRMacKey = Convert.FromHexString(vectorElement.GetProperty("expected_session_keys").GetProperty("s_rmac").GetString()!),
                
                ExpectedCardCryptogram = Convert.FromHexString(vectorElement.GetProperty("expected_cryptograms").GetProperty("card").GetString()!),
                ExpectedHostCryptogram = Convert.FromHexString(vectorElement.GetProperty("expected_cryptograms").GetProperty("host").GetString()!)
            });
        }
        
        return vectors;
    }
    
    private static List<Scp02CMacTestVector> LoadScp02CMacVectors()
    {
        var jsonPath = GetJsonFilePath("scp02_test_vectors.json");
        var jsonContent = File.ReadAllText(jsonPath);
        var document = JsonDocument.Parse(jsonContent);
        
        var root = document.RootElement;
        var source = root.GetProperty("source").GetString()!;
        var vectors = new List<Scp02CMacTestVector>();
        
        foreach (var vectorElement in root.GetProperty("cmac_vectors").EnumerateArray())
        {
            vectors.Add(new Scp02CMacTestVector
            {
                Name = vectorElement.GetProperty("name").GetString()!,
                Description = vectorElement.GetProperty("description").GetString()!,
                Source = source,
                
                MacKey = Convert.FromHexString(vectorElement.GetProperty("mac_key").GetString()!),
                CommandData = Convert.FromHexString(vectorElement.GetProperty("command_data").GetString()!),
                ExpectedCMac = Convert.FromHexString(vectorElement.GetProperty("expected_cmac").GetString()!)
            });
        }
        
        return vectors;
    }
    
    private static string GetJsonFilePath(string fileName)
    {
        // Find the JSON file relative to the test assembly
        var assembly = Assembly.GetExecutingAssembly();
        var assemblyDir = Path.GetDirectoryName(assembly.Location)!;
        
        // Navigate up to find the project root (look for scripts directory)
        var currentDir = new DirectoryInfo(assemblyDir);
        while (currentDir != null && !Directory.Exists(Path.Combine(currentDir.FullName, "scripts")))
        {
            currentDir = currentDir.Parent;
        }
        
        if (currentDir == null)
        {
            throw new FileNotFoundException($"Could not locate project root with scripts directory from {assemblyDir}");
        }

        var jsonPath = Path.Combine(currentDir.FullName, "scripts", fileName);
        if (!File.Exists(jsonPath))
        {
            throw new FileNotFoundException($"Test vector file not found: {jsonPath}");
        }

        return jsonPath;
    }
}