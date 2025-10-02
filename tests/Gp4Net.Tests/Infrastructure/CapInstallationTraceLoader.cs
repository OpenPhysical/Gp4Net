using System;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Text.Json;
using CSharpFunctionalExtensions;
using Gp4Net.Core;

namespace Gp4Net.Tests.Infrastructure;

/// <summary>
/// Loads and processes CAP installation traces for testing.
/// </summary>
public static class CapInstallationTraceLoader
{
    /// <summary>
    /// Loads a CAP installation trace from a file.
    /// </summary>
    /// <param name="tracePath">Path to the trace file</param>
    /// <returns>Result containing the installation trace or error</returns>
    public static Result<CapInstallationTrace, SmartCardError> LoadInstallationTrace(
        string tracePath
    )
    {
        return Result
            .Try(
                () => File.ReadAllText(tracePath),
                ex => SmartCardError.UnexpectedError($"Failed to read trace file: {ex.Message}")
            )
            .Bind(traceContent =>
                Result.Try(
                    () => JsonSerializer.Deserialize<JsonDocument>(traceContent),
                    ex =>
                        SmartCardError.UnexpectedError($"Failed to parse trace JSON: {ex.Message}")
                )
            )
            .Bind(jsonDoc =>
                Maybe<JsonDocument>
                    .From(jsonDoc)
                    .ToResult(SmartCardError.UnexpectedError("JSON document is null"))
                    .Map(doc => new CapInstallationTrace(doc))
            );
    }

    /// <summary>
    /// Extracts command sequence from installation trace.
    /// </summary>
    /// <param name="trace">The installation trace</param>
    /// <returns>Result containing command sequence extraction result</returns>
    public static Result<CommandSequence, SmartCardError> ExtractCommandSequence(
        CapInstallationTrace trace
    )
    {
        return Result
            .Try(
                () => trace.JsonDocument.RootElement,
                ex => SmartCardError.UnexpectedError($"Failed to access trace root: {ex.Message}")
            )
            .Bind(root =>
                root.TryGetProperty("exchanges", out var exchangesElement)
                    ? Result.Success<JsonElement, SmartCardError>(exchangesElement)
                    : Result.Failure<JsonElement, SmartCardError>(
                        SmartCardError.UnexpectedError("No exchanges property found in trace")
                    )
            )
            .Map(exchangesElement =>
            {
                var commands = exchangesElement
                    .EnumerateArray()
                    .Select(ParseExchange)
                    .Where(result => result.IsSuccess)
                    .Select(result => result.Value)
                    .ToImmutableList();

                return new CommandSequence(commands);
            });
    }

    private static Result<CommandExchange, SmartCardError> ParseExchange(JsonElement exchange)
    {
        var hasCommand = exchange.TryGetProperty("command", out var commandElement);
        var hasResponse = exchange.TryGetProperty("response", out var responseElement);

        return hasCommand && hasResponse
            ? ParseHexString(commandElement.GetString() ?? "")
                .Bind(command =>
                    ParseHexString(responseElement.GetString() ?? "")
                        .Map(response => new CommandExchange(command, response))
                )
            : Result.Failure<CommandExchange, SmartCardError>(
                SmartCardError.UnexpectedError("Missing command or response in exchange")
            );
    }

    private static Result<byte[], SmartCardError> ParseHexString(string hex)
    {
        var cleanHex = hex.Replace(" ", "").Replace("-", "");

        return cleanHex.Length % 2 != 0
            ? Result.Failure<byte[], SmartCardError>(
                SmartCardError.UnexpectedError("Hex string must have even length")
            )
            : Result.Success<byte[], SmartCardError>(
                [
                    .. Enumerable
                        .Range(0, cleanHex.Length / 2)
                        .Select(i => Convert.ToByte(cleanHex.Substring(i * 2, 2), 16)),
                ]
            );
    }
}

/// <summary>
/// Represents a CAP installation trace.
/// </summary>
public record CapInstallationTrace(JsonDocument JsonDocument);

/// <summary>
/// Represents a sequence of commands extracted from a trace.
/// </summary>
public record CommandSequence(ImmutableList<CommandExchange> Commands);

/// <summary>
/// Represents a command-response exchange.
/// </summary>
public record CommandExchange(byte[] Command, byte[] Response);
