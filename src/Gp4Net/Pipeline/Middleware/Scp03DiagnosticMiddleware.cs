// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Pipeline;
using Gp4Net.Transport;
using Gp4Net.Utils;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Pipeline.Middleware;

/// <summary>
/// Middleware for detailed SCP03 protocol diagnostics and tracing.
/// </summary>
public class Scp03DiagnosticMiddleware : CommandMiddlewareBase
{
    private readonly ILogger<Scp03DiagnosticMiddleware> _logger;
    private readonly bool _dumpHex;
    private readonly bool _traceCrypto;
    private readonly bool _analyzeProtocol;
    private int _commandCounter;

    /// <summary>
    /// Initializes a new instance of the Scp03DiagnosticMiddleware class.
    /// </summary>
    /// <param name="logger">The logger instance.</param>
    /// <param name="dumpHex">Whether to dump hex data.</param>
    /// <param name="traceCrypto">Whether to trace cryptographic operations.</param>
    /// <param name="analyzeProtocol">Whether to analyze protocol flow.</param>
    public Scp03DiagnosticMiddleware(
        ILogger<Scp03DiagnosticMiddleware> logger,
        bool dumpHex = true,
        bool traceCrypto = false,
        bool analyzeProtocol = true)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _dumpHex = dumpHex;
        _traceCrypto = traceCrypto;
        _analyzeProtocol = analyzeProtocol;
        _commandCounter = 0;
    }

    /// <summary>
    /// Processes a command request with diagnostic logging.
    /// </summary>
    public override async Task<Result<CommandResponse, SmartCardError>> InvokeAsync(
        CommandRequest request,
        CommandDelegate next,
        CancellationToken cancellationToken = default)
    {
        _commandCounter++;
        var commandId = $"CMD{_commandCounter:D4}";

        // Log command details
        LogCommand(commandId, request.Command);

        // Analyze SCP03-specific commands
        if (_analyzeProtocol)
        {
            AnalyzeScp03Command(commandId, request.Command);
        }

        // Process command
        var startTime = DateTime.UtcNow;
        var result = await next(request, cancellationToken);
        var duration = DateTime.UtcNow - startTime;

        // Log response
        result.Match(
            response => {
                LogResponse(commandId, response, duration);
                    
                // Analyze SCP03-specific responses
                if (_analyzeProtocol)
                {
                    AnalyzeScp03Response(commandId, request.Command, response);
                }
            },
            error => LogError(commandId, error, duration)
        );

        return result;
    }

    private void LogCommand(string commandId, IApduCommand command)
    {
        _logger.LogDebug("[{CommandId}] → APDU Command", commandId);
        _logger.LogDebug("[{CommandId}]   CLA: {CLA:X2} INS: {INS:X2} P1: {P1:X2} P2: {P2:X2}",
            commandId, command.Cla, command.Ins, command.P1, command.P2);

        if (command.Data is { Length: > 0 })
        {
            _logger.LogDebug("[{CommandId}]   Lc: {Lc:X2} ({LcDec} bytes)",
                commandId, command.Data.Length, command.Data.Length);

            if (_dumpHex)
            {
                _logger.LogDebug("[{CommandId}]   Data: {Data}",
                    commandId, command.Data.ToHexString());
                LogHexDump(commandId, command.Data, "   ");
            }
        }

        if (command.ExpectedResponseLength.HasValue)
        {
            _logger.LogDebug("[{CommandId}]   Le: {Le:X2} ({LeDec} bytes expected)",
                commandId, command.ExpectedResponseLength.Value, command.ExpectedResponseLength.Value);
        }
    }

    private void LogResponse(string commandId, CommandResponse response, TimeSpan duration)
    {
        _logger.LogDebug("[{CommandId}] ← Command Response [{Duration}ms]",
            commandId, duration.TotalMilliseconds);
        _logger.LogDebug("[{CommandId}]   SW: {SW:X4} ({SW1:X2} {SW2:X2})",
            commandId, response.StatusWord, (byte)(response.StatusWord >> 8), (byte)(response.StatusWord & 0xFF));

        // Interpret status word
        var statusDescription = GetStatusDescription(response.StatusWord);
        if (!string.IsNullOrEmpty(statusDescription))
        {
            _logger.LogDebug("[{CommandId}]   Status: {Description}",
                commandId, statusDescription);
        }

        if (response.Data is { Length: > 0 })
        {
            _logger.LogDebug("[{CommandId}]   Response Length: {Length} bytes",
                commandId, response.Data.Length);

            if (_dumpHex)
            {
                _logger.LogDebug("[{CommandId}]   Data: {Data}",
                    commandId, response.Data.ToHexString());
                LogHexDump(commandId, response.Data, "   ");
            }
        }
    }

    private void LogError(string commandId, SmartCardError error, TimeSpan duration)
    {
        _logger.LogError("[{CommandId}] ✗ Error after {Duration}ms: {Error}",
            commandId, duration.TotalMilliseconds, error);
    }

    private void AnalyzeScp03Command(string commandId, IApduCommand command)
    {
        // Analyze based on INS byte
        switch (command.Ins)
        {
            case 0x50: // INITIALIZE UPDATE
                AnalyzeInitializeUpdate(commandId, command);
                break;
            case 0x82: // EXTERNAL AUTHENTICATE
                AnalyzeExternalAuthenticate(commandId, command);
                break;
            case 0xD8: // PUT KEY
                AnalyzePutKey(commandId, command);
                break;
            case 0x7A: // BEGIN R-MAC SESSION
                _logger.LogInformation("[{CommandId}] SCP03: BEGIN R-MAC SESSION command", commandId);
                break;
            case 0x78: // END R-MAC SESSION
                _logger.LogInformation("[{CommandId}] SCP03: END R-MAC SESSION command", commandId);
                break;
        }

        // Check for secure messaging
        if ((command.Cla & 0x04) == 0x04)
        {
            _logger.LogInformation("[{CommandId}] Secure messaging indicated (CLA bit 2 set)", commandId);
        }
    }

    private void AnalyzeInitializeUpdate(string commandId, IApduCommand command)
    {
        _logger.LogInformation("[{CommandId}] SCP03: INITIALIZE UPDATE command", commandId);
        _logger.LogInformation("[{CommandId}]   Key Version: {KeyVersion:X2}", commandId, command.P1);
        _logger.LogInformation("[{CommandId}]   Key Identifier: {KeyId:X2}", commandId, command.P2);

        if (command.Data is { Length: 8 })
        {
            _logger.LogInformation("[{CommandId}]   Host Challenge: {Challenge}",
                commandId, command.Data.ToHexString());
        }
    }

    private void AnalyzeExternalAuthenticate(string commandId, IApduCommand command)
    {
        _logger.LogInformation("[{CommandId}] SCP03: EXTERNAL AUTHENTICATE command", commandId);
        _logger.LogInformation("[{CommandId}]   Security Level: {Level:X2}", commandId, command.P1);

        // Decode security level
        var secLevel = new StringBuilder();
        if ((command.P1 & 0x01) != 0) secLevel.Append("C-MAC ");
        if ((command.P1 & 0x03) == 0x03) secLevel.Append("C-DECRYPTION ");
        if ((command.P1 & 0x10) != 0) secLevel.Append("R-MAC ");
        if ((command.P1 & 0x30) == 0x30) secLevel.Append("R-ENCRYPTION ");

        if (secLevel.Length > 0)
        {
            _logger.LogInformation("[{CommandId}]   Security: {Security}",
                commandId, secLevel.ToString().TrimEnd());
        }

        if (command.Data is { Length: >= 8 })
        {
            _logger.LogInformation("[{CommandId}]   Host Cryptogram: {Cryptogram}",
                commandId, command.Data.Take(8).ToArray().ToHexString());

            if (command.Data.Length > 8)
            {
                _logger.LogInformation("[{CommandId}]   MAC: {MAC}",
                    commandId, command.Data.Skip(8).Take(8).ToArray().ToHexString());
            }
        }
    }

    private void AnalyzePutKey(string commandId, IApduCommand command)
    {
        _logger.LogInformation("[{CommandId}] SCP03: PUT KEY command", commandId);
        _logger.LogInformation("[{CommandId}]   Key Version (P1): {KeyVersion:X2}", commandId, command.P1);
        _logger.LogInformation("[{CommandId}]   Key Identifier (P2): {KeyId:X2}", commandId, command.P2);
    }

    private void AnalyzeScp03Response(string commandId, IApduCommand command, CommandResponse response)
    {
        if (command.Ins == 0x50 && response.IsSuccess && response.Data != null)
        {
            // INITIALIZE UPDATE response
            AnalyzeInitializeUpdateResponse(commandId, response.Data);
        }
    }

    private void AnalyzeInitializeUpdateResponse(string commandId, byte[] data)
    {
        _logger.LogInformation("[{CommandId}] SCP03: INITIALIZE UPDATE Response Analysis", commandId);

        if (data.Length >= 29)
        {
            var offset = 0;

            // Key Diversification Data (10 bytes)
            var keyDivData = data.Skip(offset).Take(10).ToArray();
            _logger.LogInformation("[{CommandId}]   Key Diversification Data: {Data}",
                commandId, keyDivData.ToHexString());
            offset += 10;

            // Key Information (3 bytes)
            var keyInfo = data.Skip(offset).Take(3).ToArray();
            _logger.LogInformation("[{CommandId}]   Key Information: {Info}",
                commandId, keyInfo.ToHexString());
            _logger.LogInformation("[{CommandId}]     - Key Version: {Version:X2}",
                commandId, keyInfo[0]);
            _logger.LogInformation("[{CommandId}]     - SCP ID: {ScpId:X2} (SCP{Protocol:X2}, i={Implementation:X2})",
                commandId, keyInfo[1], keyInfo[1] & 0x0F, keyInfo[1] & 0xF0);
            offset += 3;

            // Card Challenge (8 bytes)
            var cardChallenge = data.Skip(offset).Take(8).ToArray();
            _logger.LogInformation("[{CommandId}]   Card Challenge: {Challenge}",
                commandId, cardChallenge.ToHexString());
            offset += 8;

            // Card Cryptogram (8 bytes)
            var cardCryptogram = data.Skip(offset).Take(8).ToArray();
            _logger.LogInformation("[{CommandId}]   Card Cryptogram: {Cryptogram}",
                commandId, cardCryptogram.ToHexString());
            offset += 8;

            // Sequence Counter (3 bytes) - only for pseudo-random challenge
            if (data.Length >= 32)
            {
                var seqCounter = data.Skip(offset).Take(3).ToArray();
                _logger.LogInformation("[{CommandId}]   Sequence Counter: {Counter} (pseudo-random mode)",
                    commandId, seqCounter.ToHexString());
            }
        }
        else
        {
            _logger.LogWarning("[{CommandId}] Response too short for full analysis ({Length} bytes)",
                commandId, data.Length);
        }
    }

    private void LogHexDump(string commandId, byte[] data, string indent)
    {
        if (!_traceCrypto || data == null || data.Length == 0)
            return;

        var sb = new StringBuilder();
        for (var i = 0; i < data.Length; i += 16)
        {
            sb.Clear();
            sb.Append($"{indent}{i:X4}: ");

            // Hex bytes
            for (var j = 0; j < 16; j++)
            {
                if (i + j < data.Length)
                    sb.Append($"{data[i + j]:X2} ");
                else
                    sb.Append("   ");

                if (j == 7)
                    sb.Append(" ");
            }

            sb.Append(" |");

            // ASCII representation
            for (var j = 0; j < 16 && i + j < data.Length; j++)
            {
                var b = data[i + j];
                sb.Append(b is >= 0x20 and < 0x7F ? (char)b : '.');
            }

            sb.Append('|');
            _logger.LogDebug("[{CommandId}] {Dump}", commandId, sb.ToString());
        }
    }

    private static string GetStatusDescription(ushort sw)
    {
        return sw switch
        {
            0x9000 => "Success",
            0x6283 => "Selected file invalidated",
            0x6300 => "Authentication failed",
            0x6581 => "Memory failure",
            0x6700 => "Wrong length",
            0x6881 => "Logical channel not supported",
            0x6882 => "Secure messaging not supported",
            0x6982 => "Security status not satisfied",
            0x6985 => "Conditions of use not satisfied",
            0x6A80 => "Incorrect parameters in data field",
            0x6A82 => "Application not found",
            0x6A84 => "Not enough memory space",
            0x6A86 => "Incorrect P1-P2",
            0x6A88 => "Referenced data not found",
            _ when (sw & 0xFF00) == 0x6200 => "Warning: State unchanged",
            _ when (sw & 0xFF00) == 0x6300 => "Warning: Authentication failed",
            _ => null
        };
    }
}