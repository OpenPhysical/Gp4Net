using System;
using CSharpFunctionalExtensions;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Gp4Net.CardEmulator.Core;

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
    public ApduTrace ParseFile(string filePath)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException($"Trace file not found: {filePath}");

        string content = File.ReadAllText(filePath);
        return ParseString(content);
    }

    /// <summary>
    /// Parses a gpshell trace from a string.
    /// </summary>
    public ApduTrace ParseString(string traceContent)
    {
        if (string.IsNullOrWhiteSpace(traceContent))
            throw new ArgumentException("Trace content cannot be empty", nameof(traceContent));

        ApduTrace trace = new ApduTrace { Metadata = { Source = "gpshell" } };

        string[] lines = traceContent.Split(
            ['\r', '\n'],
            StringSplitOptions.RemoveEmptyEntries
        );
        ParserState state = new ParserState();

        foreach (string line in lines)
        {
            ProcessLine(line, trace, state);
        }

        // Handle any pending command
        if (state.PendingCommand != null)
        {
            // Add command without response (might be last command in trace)
            var exchangeResult = ApduExchange.Create(state.PendingCommand, Maybe<ApduResponse>.None);
            if (exchangeResult.IsSuccess)
                trace.AddExchange(exchangeResult.Value);
        }

        return trace;
    }

    private void ProcessLine(string line, ApduTrace trace, ParserState state)
    {
        string trimmedLine = line.Trim();

        // Skip empty lines and comments
        if (
            string.IsNullOrWhiteSpace(trimmedLine)
            || trimmedLine.StartsWith("#")
            || trimmedLine.StartsWith("//")
        )
        {
            return;
        }

        // Check for ATR
        Match atrMatch = AtrPattern.Match(trimmedLine);
        if (atrMatch.Success)
        {
            trace.Atr = ParseHexString(atrMatch.Groups[1].Value);
            return;
        }

        // Check for reader name
        Match readerMatch = ReaderPattern.Match(trimmedLine);
        if (readerMatch.Success)
        {
            trace.Metadata.ReaderName = readerMatch.Groups[1].Value.Trim();
            return;
        }

        // Check for command
        Match commandMatch = CommandPatterns.Match(trimmedLine);
        if (commandMatch.Success)
        {
            // Find first non-empty group (skip group 0 which is full match)
            string? hexData = null;
            for (int i = 1; i < commandMatch.Groups.Count; i++)
            {
                if (
                    commandMatch.Groups[i].Success
                    && !string.IsNullOrEmpty(commandMatch.Groups[i].Value)
                )
                {
                    hexData = commandMatch.Groups[i].Value;
                    break;
                }
            }

            if (!string.IsNullOrEmpty(hexData))
            {
                // If we have a pending command, add it without response
                if (state.PendingCommand != null)
                {
                    var exchangeResult = ApduExchange.Create(state.PendingCommand, Maybe<ApduResponse>.None);
                    if (exchangeResult.IsSuccess)
                        trace.AddExchange(exchangeResult.Value);
                }

                state.PendingCommand = ParseHexString(hexData);
                state.LastLine = trimmedLine;
            }
            return;
        }

        // Check for response
        Match responseMatch = ResponsePatterns.Match(trimmedLine);
        if (responseMatch.Success)
        {
            // Find first non-empty group
            string? hexData = null;
            for (int i = 1; i < responseMatch.Groups.Count; i++)
            {
                if (
                    responseMatch.Groups[i].Success
                    && !string.IsNullOrEmpty(responseMatch.Groups[i].Value)
                )
                {
                    hexData = responseMatch.Groups[i].Value;
                    break;
                }
            }

            if (!string.IsNullOrEmpty(hexData))
            {
                ApduResponse response;

                // Check if this is just a status word
                if (hexData.Replace(" ", "").Length == 4)
                {
                    // Just SW, no data
                    ushort sw = Convert.ToUInt16(hexData.Replace(" ", ""), 16);
                    response = new ApduResponse([], sw);
                }
                else
                {
                    // Full response with data
                    byte[] responseBytes = ParseHexString(hexData);
                    response = ParseResponse(responseBytes);
                }

                // If we have a pending command, create exchange
                if (state.PendingCommand != null)
                {
                    var exchangeResult = ApduExchange.Create(state.PendingCommand, Maybe<ApduResponse>.From(response));
                    if (exchangeResult.IsSuccess)
                        trace.AddExchange(exchangeResult.Value);
                    state.PendingCommand = null;
                }
                else if (state.PartialResponse != null)
                {
                    // Handle multi-line responses
                    byte[] fullData = CombineArrays(state.PartialResponse, response.Data);
                    response = new ApduResponse(fullData, response.StatusWord);

                    if (state.LastExchange != null)
                    {
                        state.LastExchange.Response = response;
                    }

                    state.PartialResponse = null;
                }
            }
            return;
        }

        // Check if this might be continuation of previous data
        if (IsHexLine(trimmedLine))
        {
            byte[] hexData = ParseHexString(trimmedLine);

            if (state.PendingCommand != null)
            {
                // Continuation of command
                state.PendingCommand = CombineArrays(state.PendingCommand, hexData);
            }
            else if (state.LastExchange is { Response: null })
            {
                // This might be response data
                state.PartialResponse = hexData;
            }
        }
    }

    private static byte[] ParseHexString(string hex)
    {
        // Remove all whitespace and common separators
        hex = Regex.Replace(hex, @"[\s\-:,]", "");

        // Ensure even length
        if (hex.Length % 2 != 0)
        {
            throw new FormatException($"Hex string has odd length: {hex}");
        }

        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }

        return bytes;
    }

    private static ApduResponse ParseResponse(byte[] responseBytes)
    {
        if (responseBytes.Length < 2)
        {
            // Invalid response, assume error
            return ApduResponse.Error(0x6F00);
        }

        // Extract SW from last 2 bytes
        ushort sw = (ushort)(
            (responseBytes[responseBytes.Length - 2] << 8)
            | responseBytes[responseBytes.Length - 1]
        );

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

    private class ParserState
    {
        public byte[]? PendingCommand { get; set; }
        public byte[]? PartialResponse { get; set; }
        public ApduExchange? LastExchange { get; set; }
        public string LastLine { get; set; } = string.Empty;
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