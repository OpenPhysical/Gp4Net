using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Gp4Net.Tool.Commands.Trace;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Card service that replays APDU exchanges from a JSON trace file.
/// Designed for deterministic testing and debugging.
/// </summary>
[PublicAPI]
public class TraceBasedCardService : ICardService
{
    private readonly TraceData _traceData;
    private readonly List<Exchange> _exchanges;
    private readonly string _tracePath;
    private int _currentExchangeIndex;
    private string _currentOperationFilter = string.Empty;
    private readonly HashSet<int> _allowedExchangeIndices = [];
    private bool _isConnected;
    private TraceBasedCardChannel _currentChannel;

    public TraceBasedCardService(string tracePath, string operationFilter = null)
    {
        _tracePath = tracePath;
            
        if (!File.Exists(tracePath))
        {
            throw new FileNotFoundException($"Trace file not found: {tracePath}");
        }

        var json = File.ReadAllText(tracePath);
        _traceData = JsonSerializer.Deserialize<TraceData>(json, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
        }) ?? throw new InvalidOperationException("Failed to deserialize trace data");

        _exchanges = _traceData.Exchanges;
        _currentOperationFilter = operationFilter ?? string.Empty;
            
        ApplyOperationFilter();
    }

    /// <summary>
    /// Sets the operation filter to limit which exchanges are replayed.
    /// </summary>
    public void SetOperationFilter(string operationFilter)
    {
        _currentOperationFilter = operationFilter;
        ApplyOperationFilter();
        _currentExchangeIndex = 0;
    }

    private void ApplyOperationFilter()
    {
        _allowedExchangeIndices.Clear();

        if (string.IsNullOrEmpty(_currentOperationFilter))
        {
            // No filter - allow all exchanges
            for (var i = 0; i < _exchanges.Count; i++)
            {
                _ = _allowedExchangeIndices.Add(i);
            }
        }
        else
        {
            // Parse comma-separated operation names
            var requestedOps = _currentOperationFilter.Split(',', StringSplitOptions.RemoveEmptyEntries)
                .Select(op => op.Trim())
                .ToHashSet();

            // Add exchanges from requested operations
            foreach (var exchange in _exchanges)
            {
                if (requestedOps.Contains(exchange.Operation))
                {
                    _ = _allowedExchangeIndices.Add(exchange.Index - 1); // Index is 1-based in trace
                }
            }
        }
    }

    public IReadOnlyList<string> GetReaders()
    {
        return [$"TraceBasedReader:{_tracePath}"];
    }

    public bool Connect(string readerName)
    {
        if (!readerName.StartsWith("TraceBasedReader:"))
        {
            throw new ArgumentException($"Invalid reader name format. Expected 'TraceBasedReader:<path>', got '{readerName}'");
        }

        _isConnected = true;
        _currentExchangeIndex = 0;
        _currentChannel = new TraceBasedCardChannel(this);

        return true;
    }

    public void Disconnect()
    {
        _isConnected = false;
        _currentExchangeIndex = 0;
        TraceBasedCardChannel.Dispose();
        _currentChannel = null;
    }

    public bool IsConnected
    {
        get
        {
            return _isConnected;
        }
    }

    public byte[] GetAtr()
    {
        return _isConnected ? Convert.FromHexString(_traceData.Metadata.Card.Atr) : null;
    }

    public CardResponse SendCommand(byte[] command)
    {
        if (!_isConnected || _currentChannel == null)
        {
            throw new InvalidOperationException("Not connected to card");
        }

        return _currentChannel.Transmit(command);
    }

    public CardResponse SendCommand(IApduCommand command)
    {
        var apdu = ApduBuilder.BuildApdu(command);
        return SendCommand(apdu);
    }

    /// <summary>
    /// Secure channel establishment for trace-based testing.
    /// Returns true if the trace contains secure channel establishment operations.
    /// The actual secure channel state is managed by the pipeline processors.
    /// </summary>
    public bool EstablishSecureChannel(byte[] keySet, byte securityLevel)
    {
        // Check if trace contains INITIALIZE UPDATE and EXTERNAL AUTHENTICATE operations
        var hasInitUpdate = _exchanges.Any(e => 
            e.Command.Length >= 10 && 
            e.Command.Substring(0, 4).Equals("8050", StringComparison.OrdinalIgnoreCase));
            
        var hasExtAuth = _exchanges.Any(e => 
            e.Command.Length >= 10 && 
            e.Command.Substring(0, 4).Equals("8482", StringComparison.OrdinalIgnoreCase));
            
        return hasInitUpdate && hasExtAuth;
    }

    /// <summary>
    /// Secure channel is established if the trace contains both INITIALIZE UPDATE and EXTERNAL AUTHENTICATE.
    /// </summary>
    public bool IsSecureChannelEstablished
    {
        get
        {
            return EstablishSecureChannel([], 0);
        }
    }

    public void Dispose()
    {
        // Nothing to dispose
    }

    /// <summary>
    /// Gets the next exchange in the trace that matches the provided command.
    /// </summary>
    internal Exchange GetNextExchange(byte[] commandApdu)
    {
        var commandHex = BitConverter.ToString(commandApdu).Replace("-", "");

        // Find next allowed exchange that matches the command
        while (_currentExchangeIndex < _exchanges.Count)
        {
            var exchangeIndex = _currentExchangeIndex;
                
            if (_allowedExchangeIndices.Contains(exchangeIndex))
            {
                var exchange = _exchanges[exchangeIndex];
                _currentExchangeIndex++;

                // Check if command matches
                if (exchange.Command.Equals(commandHex, StringComparison.OrdinalIgnoreCase))
                {
                    return exchange;
                }

                // For wrapped commands, also check the unwrapped version
                if (commandHex.StartsWith("84") && exchange.Command.StartsWith("80"))
                {
                    // This might be a wrapped version of the trace command
                    // For now, we'll accept it if INS bytes match
                    if (commandHex.Length >= 4 && exchange.Command.Length >= 4)
                    {
                        var cmdIns = commandHex.Substring(2, 2);
                        var exchIns = exchange.Command.Substring(2, 2);
                        if (cmdIns == exchIns)
                        {
                            return exchange;
                        }
                    }
                }
            }
            else
            {
                _currentExchangeIndex++;
            }
        }

        return null;
    }

    /// <summary>
    /// Card channel implementation for trace-based testing.
    /// </summary>
    private class TraceBasedCardChannel
    {
        private readonly TraceBasedCardService _service;

        public TraceBasedCardChannel(TraceBasedCardService service)
        {
            _service = service;
        }

        public CardResponse Transmit(byte[] commandApdu)
        {
            var exchange = _service.GetNextExchange(commandApdu);
            if (exchange == null)
            {
                throw new InvalidOperationException(
                    $"No matching exchange found for command: {BitConverter.ToString(commandApdu)}. " +
                    $"Current exchange index: {_service._currentExchangeIndex}, " +
                    $"Total exchanges: {_service._exchanges.Count}, " +
                    $"Allowed exchanges: {_service._allowedExchangeIndices.Count}");
            }

            // Parse response
            var fullResponse = exchange.Response;
            if (fullResponse.Length < 4)
            {
                throw new InvalidOperationException($"Invalid response in trace: {fullResponse}");
            }

            // Extract data and status word
            var sw = fullResponse.Substring(fullResponse.Length - 4, 4);
            var data = fullResponse.Length > 4 
                ? fullResponse.Substring(0, fullResponse.Length - 4) 
                : "";

            // Handle command-specific response parsing for "009000" responses
            if (data == "00" && fullResponse.Length == 6 && commandApdu.Length >= 2)
            {
                var instruction = commandApdu[1]; // INS byte
                    
                // LOAD commands (INS = 0xE8) typically return no data, so "009000" should be empty + 9000
                if (instruction == 0xE8)
                {
                    data = "";
                }
                // DELETE commands (INS = 0xE6) return length field, so "009000" should be "00" + 9000
                // Keep data = "00" for DELETE commands and other commands
            }

            var responseData = string.IsNullOrEmpty(data) 
                ? []
                : Convert.FromHexString(data);

            var sw1 = Convert.ToByte(sw.Substring(0, 2), 16);
            var sw2 = Convert.ToByte(sw.Substring(2, 2), 16);
            var statusWord = (ushort)((sw1 << 8) | sw2);

            return new CardResponse(responseData, statusWord);
        }

        public static void Dispose()
        {
            // Nothing to dispose
        }
    }
}

/// <summary>
/// Extension methods for using trace-based card service in tests.
/// </summary>
public static class TraceBasedCardServiceExtensions
{
    /// <summary>
    /// Creates a reader name for trace-based testing.
    /// </summary>
    public static string CreateTraceReaderName(string tracePath, string operations = null)
    {
        var readerName = $"TraceBasedReader:{tracePath}";
        if (!string.IsNullOrEmpty(operations))
        {
            readerName += $"?operations={operations}";
        }
        return readerName;
    }

    /// <summary>
    /// Parses a trace reader name to extract path and operations.
    /// </summary>
    public static (string TracePath, string Operations) ParseTraceReaderName(string readerName)
    {
        if (!readerName.StartsWith("TraceBasedReader:"))
        {
            throw new ArgumentException($"Invalid trace reader name: {readerName}");
        }

        var pathAndQuery = readerName.Substring("TraceBasedReader:".Length);
        var parts = pathAndQuery.Split('?', 2);
            
        var tracePath = parts[0];
        string operations = null;

        if (parts.Length > 1)
        {
            var query = parts[1];
            if (query.StartsWith("operations="))
            {
                operations = query.Substring("operations=".Length);
            }
        }

        return (tracePath, operations);
    }
}