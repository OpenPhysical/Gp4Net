using System;
using System.Collections.Generic;
using System.Linq;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Tool.Scripting;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using MoonSharp.Interpreter;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Resolves keysets from script functions or explicit parameters.
/// </summary>
[PublicAPI]
public class KeysetResolver : IKeysetResolver
{
    private readonly ILogger<KeysetResolver> _logger;
    private readonly IScriptManager _scriptManager;

    /// <summary>
    /// Initializes a new instance of the KeysetResolver class.
    /// </summary>
    public KeysetResolver(ILogger<KeysetResolver> logger, IScriptManager scriptManager)
    {
        _logger = logger;
        _scriptManager = scriptManager;
    }

    /// <summary>
    /// Resolves a keyset from various sources.
    /// </summary>
    public IKeySet ResolveKeyset(
        string keysetSpec,
        Dictionary<string, string> keysetParams,
        byte[] encKey,
        byte[] macKey,
        byte[] dekKey,
        byte keyVersion,
        InitializeUpdateResponse cardResponse = null
    )
    {
        // Priority 1: Individual keys specified
        if (encKey != null || macKey != null || dekKey != null)
        {
            return CreateKeysetFromIndividualKeys(encKey, macKey, dekKey, keyVersion);
        }

        // Priority 2: Check for GP test keys (use C# implementation)
        if (string.IsNullOrEmpty(keysetSpec) || keysetSpec == "gp_test_keys")
        {
            _logger.LogDebug("Using C# GP test keys implementation");
            return ResolveGpTestKeys(cardResponse);
        }

        // Priority 3: Keyset from script
        return ResolveFromScript(keysetSpec, keysetParams, cardResponse);
    }

    private IKeySet ResolveFromScript(
        string keysetSpec,
        Dictionary<string, string> keysetParams,
        InitializeUpdateResponse cardResponse
    )
    {
        try
        {
            _logger.LogDebug("Resolving keyset from script: {KeysetSpec}", keysetSpec);

            // Parse keyset specification
            string scriptPath;
            string[] args;

            if (keysetSpec.Contains(':'))
            {
                // Format: function_name:arg1:arg2:... -> kdf/function_name.lua main([arg1, arg2, ...])
                var parts = keysetSpec.Split(':');
                var functionName = parts[0];
                scriptPath = $"kdf/{functionName}";
                args = [.. parts.Skip(1)];
            }
            else
            {
                // Format: function_name -> kdf/function_name.lua main([])
                scriptPath = $"kdf/{keysetSpec}";
                args = [];
            }

            // Create context for script
            var context = CreateScriptContext(keysetParams, cardResponse);

            // Execute script function with arguments
            var result = _scriptManager.ExecuteScriptFunction(
                scriptPath,
                "main",
                args,
                context
            );

            // Parse result
            return ParseScriptResult(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Failed to resolve keyset from script: {KeysetSpec}",
                keysetSpec
            );
            throw new InvalidOperationException(
                $"Failed to resolve keyset '{keysetSpec}': {ex.Message}",
                ex
            );
        }
    }

    private static Dictionary<string, object> CreateScriptContext(
        Dictionary<string, string> keysetParams,
        InitializeUpdateResponse cardResponse
    )
    {
        var context = new Dictionary<string, object>();

        // Add parameters
        if (keysetParams is { Count: > 0 })
        {
            context["params"] = keysetParams;
        }

        // Add card response data if available
        if (cardResponse != null)
        {
            context["key_diversification_data"] = cardResponse.KeyDiversificationData;
            context["key_version"] = cardResponse.KeyInformation;
            context["scp_id"] = cardResponse.ScpId;
            context["protocol"] = (cardResponse.ScpId & 0x03) == 0x02 ? "SCP02" : "SCP03";

            if (cardResponse.SequenceCounter != null)
            {
                context["sequence_counter"] = cardResponse.SequenceCounter;
            }
        }

        return context;
    }

    private IKeySet ParseScriptResult(DynValue result)
    {
        if (result.Type != DataType.Table)
        {
            throw new InvalidOperationException("Script must return a table with keys");
        }

        var table = result.Table;

        // Extract keys
        var encKey = GetBytesFromTable(table, "enc");
        var macKey = GetBytesFromTable(table, "mac");
        var dekKey = GetBytesFromTable(table, "dek");
        var rmacKey = GetBytesFromTable(table, "rmac");
        var version = GetByteFromTable(table, "version", 0xFF);

        // Validate keys
        if (encKey == null || macKey == null || dekKey == null)
        {
            throw new InvalidOperationException("Script must return enc, mac, and dek keys");
        }

        switch (encKey.Length)
        {
            // Determine protocol based on key length and rmac presence
            case 16 when macKey.Length == 16 && dekKey.Length == 16:
            {
                // 3DES keys - likely SCP02
                var keySetResult = Scp02KeySet.Create(encKey, macKey, dekKey, version);
                if (keySetResult.IsFailure)
                {
                    throw new InvalidOperationException($"Failed to create Scp02KeySet: {keySetResult.Error.Message}");
                }
                return keySetResult.Value;
            }
            case >= 16 when rmacKey != null:
            {
                // AES keys with RMAC - SCP03
                var keySetResult = Scp03KeySet.Create(encKey, macKey, dekKey, version);
                if (keySetResult.IsFailure)
                {
                    throw new InvalidOperationException($"Failed to create Scp03KeySet: {keySetResult.Error.Message}");
                }
                return keySetResult.Value;
            }
            default:
            {
                // Default to SCP02
                var keySetResult = Scp02KeySet.Create(encKey, macKey, dekKey, version);
                if (keySetResult.IsFailure)
                {
                    throw new InvalidOperationException($"Failed to create Scp02KeySet: {keySetResult.Error.Message}");
                }
                return keySetResult.Value;
            }
        }
    }

    private static byte[] GetBytesFromTable(Table table, string key)
    {
        var value = table.Get(key);
        if (value.IsNil())
        {
            return null;
        }

        switch (value.Type)
        {
            case DataType.UserData when value.UserData.Object is byte[] bytes:
                return bytes;
            case DataType.String:
                return Convert.FromHexString(value.String.Replace(" ", ""));
            default:
                throw new InvalidOperationException(
                    $"Invalid type for key '{key}': expected bytes or hex string"
                );
        }

    }

    private static byte GetByteFromTable(Table table, string key, byte defaultValue)
    {
        var value = table.Get(key);
        if (value.IsNil())
        {
            return defaultValue;
        }

        if (value.Type == DataType.Number)
        {
            return (byte)value.Number;
        }

        throw new InvalidOperationException($"Invalid type for key '{key}': expected number");
    }

    private IKeySet ResolveGpTestKeys(InitializeUpdateResponse cardResponse)
    {
        // Always use the GetDiversifiedTestKeySet method which handles null cardResponse
        var result = GpTestKeys.GetDiversifiedTestKeySet(cardResponse);
        
        if (result.IsSuccess)
        {
            if (cardResponse != null)
            {
                _logger.LogDebug("Using diversified GP test keys based on card response");
            }
            else
            {
                _logger.LogDebug("Using static GP test keys (no card response available)");
            }
            return result.Value;
        }
        else
        {
            throw new InvalidOperationException($"Failed to resolve GP test keys: {result.Error.Message}");
        }
    }

    private static IKeySet CreateKeysetFromIndividualKeys(
        byte[] encKey,
        byte[] macKey,
        byte[] dekKey,
        byte keyVersion
    )
    {
        // Use provided keys or default to test key
        var defaultKey = GpTestKeys.StandardTestKey;
        encKey ??= defaultKey;
        macKey ??= defaultKey;
        dekKey ??= defaultKey;

        // Determine protocol based on key length
        if (encKey.Length == 16 && macKey.Length == 16 && dekKey.Length == 16)
        {
            var keySetResult = Scp02KeySet.Create(encKey, macKey, dekKey, keyVersion);
            if (keySetResult.IsFailure)
            {
                throw new InvalidOperationException($"Failed to create Scp02KeySet: {keySetResult.Error.Message}");
            }
            return keySetResult.Value;
        }
        else
        {
            // For SCP03, RMAC defaults to MAC
            var keySetResult = Scp03KeySet.Create(encKey, macKey, dekKey, keyVersion);
            if (keySetResult.IsFailure)
            {
                throw new InvalidOperationException($"Failed to create Scp03KeySet: {keySetResult.Error.Message}");
            }
            return keySetResult.Value;
        }
    }
}