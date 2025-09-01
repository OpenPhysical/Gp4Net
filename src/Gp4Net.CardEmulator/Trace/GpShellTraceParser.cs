using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.Core;

namespace Gp4Net.CardEmulator.Trace;

/// <summary>
/// Parser for gpshell APDU trace logs.
/// </summary>
public class GpShellTraceParser
{
    // Regex patterns for different gpshell output formats
    private static readonly Regex CommandPatterns = new Regex(
        @"(?:"
            + @"Command\s*(?:->|:)\s*([0-9A-Fa-f\s]+)|"
            + // "Command -> XX XX XX"
            @"send_APDU\s*(?:\(\))?\s*(?:->|:)?\s*([0-9A-Fa-f\s]+)|"
            + // "send_APDU() -> XX XX XX"
            @"=>\s*([0-9A-Fa-f\s]+)|"
            + // "=> XX XX XX"
            @"APDU:\s*([0-9A-Fa-f\s]+)|"
            + // "APDU: XX XX XX"
            @">>>\s*([0-9A-Fa-f\s]+)|"
            + // ">>> XX XX XX"
            @"C-APDU:\s*([0-9A-Fa-f\s]+)"
            + // "C-APDU: XX XX XX"
            @")",
        RegexOptions.IgnoreCase | RegexOptions.Compiled
    );

    private static readonly Regex ResponsePatterns = new Regex(
        @"(?:"
            + @"Response\s*(?:<-|:)\s*([0-9A-Fa-f\s]+)|"
            + // "Response <- XX XX XX"
            @"Received\s*(?:\(\))?\s*(?:<-|:)?\s*([0-9A-Fa-f\s]+)|"
            + // "Received() <- XX XX XX"
            @"<=\s*([0-9A-Fa-f\s]+)|"
            + // "<= XX XX XX"
            @"recv_APDU\s*(?:\(\))?\s*(?:<-|:)?\s*([0-9A-Fa-f\s]+)|"
            + // "recv_APDU() <- XX XX XX"
            @"<<<\s*([0-9A-Fa-f\s]+)|"
            + // "<<< XX XX XX"
            @"R-APDU:\s*([0-9A-Fa-f\s]+)|"
            + // "R-APDU: XX XX XX"
            @"SW(?:1SW2)?:\s*([0-9A-Fa-f]{4})"
            + // "SW: 9000" or "SW1SW2: 9000"
            @")",
        RegexOptions.IgnoreCase | RegexOptions.Compiled
    );

    private static readonly Regex AtrPattern = new Regex(
        @"(?:ATR|Answer to Reset)[:=]\s*([0-9A-Fa-f\s]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled
    );

    private static readonly Regex ReaderPattern = new Regex(
        @"(?:Reader|Terminal)[:=]\s*(.+?)(?:\s*\[|$)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled
    );

    /// <summary>
    /// Parses a gpshell trace from a file.
    /// </summary>
    public Result<ApduTrace, SmartCardError> ParseFile(string filePath)
    {
        return Maybe.From(filePath)
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .ToResult(SmartCardError.InvalidArgument("File path cannot be empty"))
            .Ensure(File.Exists, SmartCardError.InvalidArgument("Trace file not found"))
            .Bind(path => 
            {
                string content = File.ReadAllText(path);
                return ParseString(content);
            });
    }

    /// <summary>
    /// Parses a gpshell trace from a string.
    /// </summary>
    public Result<ApduTrace, SmartCardError> ParseString(string traceContent)
    {
        return Maybe.From(traceContent?.Trim())
            .Where(content => !string.IsNullOrEmpty(content))
            .ToResult(SmartCardError.InvalidArgument("Trace content cannot be empty"))
            .Bind(content => 
            {
                string[] lines = content.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
                ParserState initialState = ParserState.Empty;
                ApduTrace initialTrace = ApduTrace.CreateEmpty();
                
                return lines.Aggregate(
                    Result.Success<(ApduTrace trace, ParserState state), SmartCardError>((initialTrace, initialState)),
                    (accumResult, line) => accumResult.Bind(accum => 
                        ProcessLineFunctional(line, accum.trace, accum.state)
                    )
                ).Bind(final => 
                    // Handle pending command if any
                    final.state.PendingCommand.Match(
                        pendingCmd => ApduExchange.Create(pendingCmd, Maybe<ApduResponse>.None)
                            .Bind(exchange => final.trace.WithExchange(exchange)),
                        () => Result.Success<ApduTrace, SmartCardError>(final.trace)
                    )
                );
            });
    }

    private Result<(ApduTrace trace, ParserState state), SmartCardError> ProcessLineFunctional(
        string line, 
        ApduTrace currentTrace, 
        ParserState currentState)
    {
        string trimmedLine = line.Trim();

        // Skip empty lines and comments
        if (string.IsNullOrWhiteSpace(trimmedLine) || 
            trimmedLine.StartsWith("#") || 
            trimmedLine.StartsWith("//"))
        {
            return Result.Success<(ApduTrace, ParserState), SmartCardError>((currentTrace, currentState));
        }

        // Check for ATR
        Match atrMatch = AtrPattern.Match(trimmedLine);
        if (atrMatch.Success)
        {
            return ParseHexStringSafe(atrMatch.Groups[1].Value)
                .Bind(atrBytes => currentTrace.WithAtr(atrBytes))
                .Map(newTrace => (newTrace, currentState));
        }

        // Process command and response lines using existing methods but functionally
        return ProcessCommandOrResponseFunctional(trimmedLine, currentTrace, currentState);
    }

    private Result<(ApduTrace trace, ParserState state), SmartCardError> ProcessCommandOrResponseFunctional(
        string line, 
        ApduTrace currentTrace, 
        ParserState currentState)
    {
        // Check for command pattern
        Match commandMatch = CommandPatterns.Match(line);
        if (commandMatch.Success)
        {
            return ParseHexStringSafe(commandMatch.Groups[1].Value)
                .Map(commandBytes => 
                {
                    // If there's a pending command, complete it first
                    ApduTrace intermediateTrace = currentState.PendingCommand.Match(
                        pendingCmd => 
                        {
                            var exchangeResult = ApduExchange.Create(pendingCmd, Maybe<ApduResponse>.None);
                            return exchangeResult.IsSuccess 
                                ? currentTrace.WithExchange(exchangeResult.Value).GetValueOrDefault(currentTrace)
                                : currentTrace;
                        },
                        () => currentTrace);

                    ParserState newState = currentState with { PendingCommand = Maybe<byte[]>.From(commandBytes) };
                    return (intermediateTrace, newState);
                });
        }

        // Check for response pattern
        Match responseMatch = ResponsePatterns.Match(line);
        if (responseMatch.Success)
        {
            return ParseHexStringSafe(responseMatch.Groups[1].Value)
                .Bind(responseBytes =>
                {
                    return currentState.PendingCommand.Match(
                        pendingCmd =>
                        {
                            var response = new ApduResponse(responseBytes, (ushort)(responseBytes.Length >= 2 ? 
                                (responseBytes[responseBytes.Length - 2] << 8) | responseBytes[responseBytes.Length - 1] : 0));
                            return ApduExchange.Create(pendingCmd, Maybe<ApduResponse>.From(response))
                                .Bind(exchange => currentTrace.WithExchange(exchange))
                                .Map(newTrace => 
                                {
                                    ParserState newState = currentState with { PendingCommand = Maybe<byte[]>.None };
                                    return (newTrace, newState);
                                });
                        },
                        () => Result.Success<(ApduTrace, ParserState), SmartCardError>((currentTrace, currentState))
                    );
                });
        }

        return Result.Success<(ApduTrace, ParserState), SmartCardError>((currentTrace, currentState));
    }


    private static Result<byte[], SmartCardError> ParseHexStringSafe(string hex)
    {
        return Maybe.From(hex)
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .ToResult(SmartCardError.InvalidData("Hex string cannot be empty"))
            .Map(h => Regex.Replace(h, @"[\s\-:,]", ""))
            .Ensure(cleaned => cleaned.Length % 2 == 0, SmartCardError.InvalidData("Hex string must have even length"))
            .Bind(cleaned =>
            {
                var results = Enumerable.Range(0, cleaned.Length / 2)
                    .Select(i => byte.TryParse(cleaned.AsSpan(i * 2, 2), NumberStyles.HexNumber, null, out byte b) 
                        ? Result.Success<byte, SmartCardError>(b)
                        : SmartCardError.InvalidData($"Invalid hex character at position {i * 2}"))
                    .ToArray();

                // Check if all parsing succeeded
                return results.All(r => r.IsSuccess)
                    ? Result.Success<byte[], SmartCardError>(results.Select(r => r.Value).ToArray())
                    : results.First(r => r.IsFailure).Error;
            });
    }


    private static ApduResponse ParseResponse(byte[] responseBytes)
    {
        if (responseBytes.Length < 2)
        {
            // Invalid response, assume error
            return ApduResponse.Error(0x6F00);
        }

        // Extract SW from last 2 bytes
        ushort sw = (ushort)(responseBytes[^2] << 8 | responseBytes[^1]);

        // Extract data (everything except SW)
        byte[] data = new byte[responseBytes.Length - 2];
        if (data.Length > 0)
        {
            Array.Copy(responseBytes, 0, data, 0, data.Length);
        }

        return new ApduResponse(data, sw);
    }

    private static bool IsHexLine(string line)
    {
        // Check if line contains only hex characters, spaces, and common separators
        string cleaned = Regex.Replace(line, @"[\s\-:,]", "");
        return !string.IsNullOrEmpty(cleaned)
            && cleaned.All(c => "0123456789ABCDEFabcdef".Contains(c));
    }

    private static byte[] CombineArrays(byte[] first, byte[] second)
    {
        byte[] result = new byte[first.Length + second.Length];
        Array.Copy(first, 0, result, 0, first.Length);
        Array.Copy(second, 0, result, first.Length, second.Length);
        return result;
    }

    private sealed record ParserState(
        Maybe<byte[]> PendingCommand,
        Maybe<byte[]> PartialResponse, 
        Maybe<ApduExchange> LastExchange,
        string LastLine
    )
    {
        public static ParserState Empty => new(
            Maybe<byte[]>.None,
            Maybe<byte[]>.None,
            Maybe<ApduExchange>.None,
            string.Empty
        );
    }
}

/// <summary>
/// Options for parsing gpshell traces.
/// </summary>
public class GpShellParseOptions
{
    /// <summary>
    /// Gets or sets whether to be strict about format parsing.
    /// </summary>
    public bool StrictParsing { get; set; }

    /// <summary>
    /// Gets or sets whether to combine multi-line hex data.
    /// </summary>
    public bool CombineMultiLineData { get; set; } = true;
}
