using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Trace;
using NUnit.Framework;

namespace Gp4Net.Tests.Trace;

[TestFixture]
[Category("TraceValidation")]
public class TraceRepositoryConsistencyTests
{
    [Test]
    public void AllRawTraces_Should_Have_ValidatedJson()
    {
        var testDataRoot = Path.Combine(TestContext.CurrentContext.TestDirectory, "TestData");
        var rawRoot = Path.Combine(testDataRoot, "Traces", "Raw");
        Assert.That(Directory.Exists(rawRoot), Is.True, $"Raw trace directory missing: {rawRoot}");

        var rawFiles = Directory
            .GetFiles(rawRoot, "*.*", SearchOption.TopDirectoryOnly)
            .Where(path => !path.EndsWith(".DS_Store", StringComparison.OrdinalIgnoreCase))
            .ToList();

        var jsonFiles = Directory
            .GetFiles(Path.Combine(testDataRoot, "Traces"), "*.json", SearchOption.AllDirectories)
            .Where(path =>
                !path.Contains(
                    $"{Path.DirectorySeparatorChar}Raw{Path.DirectorySeparatorChar}",
                    StringComparison.OrdinalIgnoreCase
                )
            )
            .ToList();

        var jsonLookup = jsonFiles
            .Select(path => Path.GetFileNameWithoutExtension(path))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var raw in rawFiles)
        {
            var name = Path.GetFileNameWithoutExtension(raw);
            Assert.That(
                jsonLookup.Contains(name),
                Is.True,
                $"Converted JSON missing for raw trace '{name}' ({raw})."
            );
        }

        foreach (var json in jsonFiles)
        {
            ValidateTrace(json);
        }
    }

    private static void ValidateTrace(string jsonPath)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(jsonPath));

        if (!document.RootElement.TryGetProperty("exchanges", out var exchangesElement))
        {
            Assert.Fail($"Trace '{jsonPath}' should contain an exchanges array.");
        }

        byte protocol = 0x02;
        byte keyVersion = 0x00;

        if (
            document.RootElement.TryGetProperty("metadata", out var metadata)
            && metadata.TryGetProperty("sessions", out var sessions)
            && sessions.ValueKind == JsonValueKind.Array
            && sessions.GetArrayLength() > 0
        )
        {
            var firstSession = sessions[0];
            if (
                firstSession.TryGetProperty("scp_version", out var scpVersionProp)
                && scpVersionProp.TryGetInt32(out var scpVersion)
            )
            {
                protocol = scpVersion is 2 or 3 ? (byte)scpVersion : (byte)0x02;
            }

            if (
                firstSession.TryGetProperty("key_version", out var keyVersionProp)
                && keyVersionProp.TryGetInt32(out var parsedKeyVersion)
            )
            {
                keyVersion = (byte)parsedKeyVersion;
            }
        }

        var keysetResult = GpTestKeys.GetTestKeySet(protocol, keyVersion);
        Assert.That(
            keysetResult.IsSuccess,
            Is.True,
            keysetResult.IsFailure ? keysetResult.Error.Message : "Test keyset load failed"
        );

        var initialState = TraceValidationState.Create(keysetResult.Value);

        var exchangeItems = exchangesElement
            .EnumerateArray()
            .Select(
                (exchange, index) =>
                    new
                    {
                        Index = exchange.TryGetProperty("index", out var indexProp)
                            ? indexProp.GetInt32()
                            : index,
                        Command = exchange.GetProperty("command").GetString() ?? string.Empty,
                        Response = exchange.GetProperty("response").GetString() ?? string.Empty,
                    }
            );

        Result<TraceValidationState, SmartCardError> finalState = exchangeItems.Aggregate(
            Result.Success<TraceValidationState, SmartCardError>(initialState),
            (stateResult, item) =>
                stateResult.Bind(state =>
                {
                    if (
                        string.IsNullOrWhiteSpace(item.Command)
                        || string.IsNullOrWhiteSpace(item.Response)
                    )
                    {
                        return Result.Success<TraceValidationState, SmartCardError>(state);
                    }

                    var commandBytes = Result.Try(
                        () => Convert.FromHexString(item.Command.Replace(" ", string.Empty)),
                        ex =>
                            SmartCardError.InvalidArgument(
                                $"Invalid command hex in {jsonPath} exchange {item.Index}: {ex.Message}"
                            )
                    );

                    var responseBytes = Result.Try(
                        () => Convert.FromHexString(item.Response.Replace(" ", string.Empty)),
                        ex =>
                            SmartCardError.InvalidArgument(
                                $"Invalid response hex in {jsonPath} exchange {item.Index}: {ex.Message}"
                            )
                    );

                    return commandBytes.Bind(cmd =>
                        responseBytes.Bind(resp =>
                            TraceValidation.ValidateExchange(state, cmd, resp, item.Index)
                        )
                    );
                })
        );

        finalState.Match(
            state =>
            {
                List<ValidationResult> failures = state.Results.Where(r => !r.IsValid).ToList();
                Assert.That(
                    failures,
                    Is.Empty,
                    () =>
                        $"Trace '{jsonPath}' contains validation failures: {string.Join(", ", failures.Select(f => $"#{f.ExchangeIndex}:{f.ValidationType} ({f.Details})"))}"
                );
            },
            error => Assert.Fail($"Trace '{jsonPath}' validation error: {error.Message}")
        );
    }
}
