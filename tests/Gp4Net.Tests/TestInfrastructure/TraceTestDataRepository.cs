using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Trace;
using Gp4Net.Tool.Commands.Trace;
using NUnit.Framework;

namespace Gp4Net.Tests.TestInfrastructure;

public static class TraceTestDataRepository
{
    private static readonly JsonSerializerOptions SerializerOptions =
        new()
        {
            WriteIndented = false,
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

    private static readonly string TestDataRoot = Path.Combine(
        TestContext.CurrentContext.TestDirectory,
        "TestData"
    );

    private static readonly string RawTraceRoot = Path.Combine(TestDataRoot, "Traces", "Raw");

    private static readonly string RepositoryRoot = Path.GetFullPath(
        Path.Combine(TestContext.CurrentContext.TestDirectory, "..", "..", "..", "..", "..")
    );

    private static readonly string DocsTraceRoot = Path.Combine(RepositoryRoot, "docs", "traces");

    public static Result<JsonDocument, string> LoadTraceDocument(
        string relativeTracePath,
        string? formatHint = null
    )
    {
        var ensureResult = EnsureTraceFile(relativeTracePath, formatHint);
        if (ensureResult.IsFailure)
        {
            return Result.Failure<JsonDocument, string>(ensureResult.Error);
        }

        var outputPath = Path.Combine(TestDataRoot, relativeTracePath);
        try
        {
            using var stream = File.OpenRead(outputPath);
            var document = JsonDocument.Parse(stream);
            return Result.Success<JsonDocument, string>(document);
        }
        catch (Exception ex)
        {
            return Result.Failure<JsonDocument, string>(
                $"Failed to parse trace file {relativeTracePath}: {ex.Message}"
            );
        }
    }

    public static UnitResult<string> EnsureTraceFile(
        string relativeTracePath,
        string? formatHint = null
    )
    {
        if (relativeTracePath.StartsWith("TestData", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "relativeTracePath should not include the TestData prefix",
                nameof(relativeTracePath)
            );
        }

        var outputPath = Path.Combine(TestDataRoot, relativeTracePath);
        if (File.Exists(outputPath))
        {
            return UnitResult.Success<string>();
        }

        var rawTraceResult = FindRawTrace(relativeTracePath);
        if (rawTraceResult.IsFailure)
        {
            return UnitResult.Failure<string>(rawTraceResult.Error);
        }

        var rawTracePath = rawTraceResult.Value;
        var format = DetermineFormat(rawTracePath, formatHint);

        if (Path.GetExtension(rawTracePath).Equals(".json", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
                File.Copy(rawTracePath, outputPath, overwrite: true);
            }
            catch (Exception ex)
            {
                return UnitResult.Failure<string>(
                    $"Failed to copy trace from {rawTracePath}: {ex.Message}"
                );
            }

            return UnitResult.Success<string>();
        }

        var converter = new TraceConverter();
        Result<TraceData, SmartCardError> convertResult;
        try
        {
            convertResult = converter
                .ConvertAsync(
                    rawTracePath,
                    format,
                    verbose: false,
                    validate: true,
                    keysetSpec: "gp_test"
                )
                .ConfigureAwait(false)
                .GetAwaiter()
                .GetResult();
        }
        catch (Exception ex)
        {
            return UnitResult.Failure<string>(
                $"Trace conversion failed for {rawTracePath}: {ex.Message}"
            );
        }

        if (convertResult.IsFailure)
        {
            return UnitResult.Failure<string>(convertResult.Error.ToString());
        }

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);

        try
        {
            var json = JsonSerializer.Serialize(convertResult.Value, SerializerOptions);
            File.WriteAllText(outputPath, json);
        }
        catch (Exception ex)
        {
            return UnitResult.Failure<string>(
                $"Failed to write converted trace to {outputPath}: {ex.Message}"
            );
        }

        return UnitResult.Success<string>();
    }

    private static Result<string, string> FindRawTrace(string relativeTracePath)
    {
        var baseName = Path.GetFileNameWithoutExtension(relativeTracePath);
        if (string.IsNullOrEmpty(baseName))
        {
            return Result.Failure<string, string>("Invalid trace path");
        }

        var searchRoots = new[] { RawTraceRoot, DocsTraceRoot };
        var candidates = searchRoots
            .Where(Directory.Exists)
            .SelectMany(root => Directory.GetFiles(root, baseName + ".*"))
            .ToArray();

        if (candidates.Length == 0)
        {
            return Result.Failure<string, string>(
                $"Raw trace not found for {baseName} in {RawTraceRoot}"
            );
        }

        var preferred = candidates
            .OrderBy(path =>
                Path.GetExtension(path).Equals(".json", StringComparison.OrdinalIgnoreCase)
            )
            .ThenBy(path =>
                Path.GetExtension(path).Equals(".txt", StringComparison.OrdinalIgnoreCase) ? 0 : 1
            )
            .ThenBy(path => path)
            .First();

        return Result.Success<string, string>(preferred);
    }

    private static string DetermineFormat(string rawTracePath, string? formatHint)
    {
        if (!string.IsNullOrWhiteSpace(formatHint))
        {
            return formatHint;
        }

        var fileName = Path.GetFileName(rawTracePath);
        if (fileName.Contains("gpshell", StringComparison.OrdinalIgnoreCase))
        {
            return "gpshell";
        }

        return "gp_pro";
    }
}
