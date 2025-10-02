using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;

namespace Gp4Net.Tests.Trace;

public static class TraceDataLoader
{
    public static Result<TraceData, SmartCardError> LoadTraceFile(string relativePath)
    {
        try
        {
            var fullPath = Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                "TestData",
                relativePath
            );

            if (!File.Exists(fullPath))
            {
                return Result.Failure<TraceData, SmartCardError>(
                    SmartCardError.InvalidData($"Trace file not found: {fullPath}")
                );
            }

            var json = File.ReadAllText(fullPath);
            var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };

            return DeserializeTraceData(json, options);
        }
        catch (Exception ex)
        {
            return Result.Failure<TraceData, SmartCardError>(
                SmartCardError.InvalidData($"Error loading trace file: {ex.Message}")
            );
        }
    }

    private static Result<TraceData, SmartCardError> DeserializeTraceData(
        string json,
        JsonSerializerOptions options
    )
    {
        try
        {
            var data = JsonSerializer.Deserialize<TraceData>(json, options);
            return data switch
            {
                { } valid => Result.Success<TraceData, SmartCardError>(valid),
                _
                    => Result.Failure<TraceData, SmartCardError>(
                        SmartCardError.InvalidData("Failed to deserialize trace data")
                    )
            };
        }
        catch (Exception ex)
        {
            return Result.Failure<TraceData, SmartCardError>(
                SmartCardError.InvalidData($"Deserialization error: {ex.Message}")
            );
        }
    }

    public static Result<KeySet, SmartCardError> LoadMasterKeys(TraceSession session)
    {
        return session.MasterKeys.Match(
            Some: keys => CreateMasterKeys(session, keys),
            None: () =>
                Result.Failure<KeySet, SmartCardError>(
                    SmartCardError.InvalidData("No master keys in trace session")
                )
        );
    }

    private static Result<KeySet, SmartCardError> CreateMasterKeys(
        TraceSession session,
        TraceMasterKeys keys
    )
    {
        var encBytes = Convert.FromHexString(keys.Enc);
        var macBytes = Convert.FromHexString(keys.Mac);
        var dekBytes = Convert.FromHexString(keys.Dek);

        if (session.ScpVersion == 3)
        {
            return Scp03KeySet
                .Create(encBytes, macBytes, dekBytes, 0x00)
                .Map(keySet => keySet as KeySet);
        }
        else if (session.ScpVersion == 2)
        {
            return Scp02KeySet
                .Create(encBytes, macBytes, dekBytes, 0x00)
                .Map(keySet => keySet as KeySet);
        }

        return Result.Failure<KeySet, SmartCardError>(
            SmartCardError.Unsupported($"Unsupported SCP version: {session.ScpVersion}")
        );
    }
}

public class TraceData
{
    public TraceMetadata Metadata { get; init; } = new();
    public Dictionary<string, TraceOperation> Operations { get; init; } = new();
    public List<TraceExchange> Exchanges { get; init; } = new();
}

public class TraceMetadata
{
    public TraceSource Source { get; init; } = new();
    public TraceCard Card { get; init; } = new();
    public List<TraceSession> Sessions { get; init; } = new();
}

public class TraceSource
{
    public string File { get; init; } = "";
    public string Type { get; init; } = "";
    public string Generated { get; init; } = "";
    public string ToolVersion { get; init; } = "";
}

public class TraceCard
{
    public string Atr { get; init; } = "";
    public string IsdAid { get; init; } = "";
    public string CardType { get; init; } = "";
}

public class TraceSession
{
    public string SessionId { get; init; } = "";
    public int ScpVersion { get; init; }
    public string ScpImplementation { get; init; } = "";
    public int KeyVersion { get; init; }
    public string SecurityLevel { get; init; } = "";
    public string KeyDiversification { get; init; } = "";
    public string HostChallenge { get; init; } = "";
    public string CardChallenge { get; init; } = "";
    public string SequenceCounter { get; init; } = "";
    public TraceDerivationData DerivationData { get; init; } = new();
    public Maybe<TraceMasterKeys> MasterKeys { get; init; } = Maybe<TraceMasterKeys>.None;
    public List<string> Operations { get; init; } = new();
}

public class TraceDerivationData
{
    public string Kdd { get; init; } = "";
    public string HostChallenge { get; init; } = "";
    public string CardChallenge { get; init; } = "";
    public string CardCryptogram { get; init; } = "";
}

public class TraceMasterKeys
{
    public string Enc { get; init; } = "";
    public string Mac { get; init; } = "";
    public string Dek { get; init; } = "";
}

public class TraceOperation
{
    public string Description { get; init; } = "";
    public string SessionId { get; init; } = "";
    public int StartExchange { get; init; }
    public int EndExchange { get; init; }
    public List<string> Commands { get; init; } = new();
}

public class TraceExchange
{
    public int Index { get; init; }
    public string Operation { get; init; } = "";
    public string SessionId { get; init; } = "";
    public int StepInOperation { get; init; }
    public string Command { get; init; } = "";
    public string Response { get; init; } = "";
    public int ResponseTimeMs { get; init; }
    public string Description { get; init; } = "";
    public int SourceLine { get; init; }
    public bool SecureMessaging { get; init; }
    public Maybe<TraceScpData> ScpData { get; init; } = Maybe<TraceScpData>.None;
}

public class TraceScpData
{
    public string HostChallenge { get; init; } = "";
    public string CardChallenge { get; init; } = "";
    public string CardCryptogram { get; init; } = "";
    public int KeyVersion { get; init; }
    public string ScpId { get; init; } = "";
    public string ScpImplementation { get; init; } = "";
    public bool SessionEstablished { get; init; }
}
