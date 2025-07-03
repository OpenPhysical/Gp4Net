using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Web;
using Gp4Net.Tool.Commands.Trace;
using Gp4Net.Tool.Services.CardCommunication;
using Gp4Net.Transport;
using JetBrains.Annotations;
using log4net;
using MoonSharp.Interpreter;

namespace Gp4Net.Tool.Services
{
    /// <summary>
    /// Enhanced Lua card service that can load JSON trace data with rich metadata.
    /// Supports operation filtering and session-aware replay.
    /// </summary>
    [PublicAPI]
    public class JsonLuaCardService : ICardService
    {
        private static readonly ILog Logger = LogManager.GetLogger(typeof(JsonLuaCardService));
        
        private Script? _luaScript;
        private Dictionary<string, string> _parameters = new();
        private bool _isConnected;
        private string? _readerName;
        private TraceData? _traceData;
        private List<string> _requestedOperations = new();
        private HashSet<int> _allowedExchanges = new();
        private HashSet<int> _usedExchanges = new();
        private bool _secureChannelEstablished;

        /// <inheritdoc />
        public IReadOnlyList<string> GetReaders()
        {
            // JSON readers are not discoverable - they must be explicitly specified
            // Return empty list to prevent automatic detection or prompting
            return new List<string>().AsReadOnly();
        }

        /// <inheritdoc />
        public bool Connect(string readerName)
        {
            if (string.IsNullOrEmpty(readerName) || !readerName.StartsWith("json:"))
            {
                return false;
            }

            try
            {
                Disconnect(); // Ensure clean state

                _readerName = readerName;
                var (jsonPath, parameters) = ParseJsonReaderName(readerName);
                _parameters = parameters;

                // Load JSON trace data
                var fullJsonPath = ResolveJsonPath(jsonPath);
                if (!File.Exists(fullJsonPath))
                {
                    Logger.Error($"JSON trace file not found: {fullJsonPath}");
                    return false;
                }

                var jsonContent = File.ReadAllText(fullJsonPath);
                _traceData = JsonSerializer.Deserialize<TraceData>(jsonContent, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
                });

                if (_traceData == null)
                {
                    Logger.Error("Failed to deserialize JSON trace data");
                    return false;
                }

                // Parse requested operations
                if (_parameters.ContainsKey("operations"))
                {
                    _requestedOperations = _parameters["operations"].Split(',').ToList();
                    _allowedExchanges = BuildAllowedExchanges(_requestedOperations);
                    Logger.Info($"Operation filter: {string.Join(", ", _requestedOperations)}");
                }

                // Initialize Lua script
                _luaScript = new Script();
                _luaScript.Options.DebugPrint = s => Logger.Debug($"Lua: {s}");
                
                // Register Lua functions
                RegisterLuaFunctions(_luaScript);
                
                // Load the JSON data into Lua
                LoadTraceDataIntoLua(_traceData);

                _isConnected = true;
                Logger.Info($"Connected to JSON virtual reader: {readerName}");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Error($"Failed to connect to JSON reader {readerName}", ex);
                Disconnect();
                return false;
            }
        }

        /// <inheritdoc />
        public void Disconnect()
        {
            _luaScript = null;
            _isConnected = false;
            _parameters.Clear();
            _readerName = null;
            _traceData = null;
            _requestedOperations.Clear();
            _allowedExchanges.Clear();
            _usedExchanges.Clear();
            _secureChannelEstablished = false;
            
            Logger.Debug("Disconnected from JSON virtual reader");
        }

        /// <inheritdoc />
        public bool IsConnected => _isConnected && _luaScript != null && _traceData != null;

        /// <inheritdoc />
        public byte[]? GetAtr()
        {
            if (!IsConnected || _traceData == null)
            {
                return null;
            }

            try
            {
                var atrHex = _traceData.Metadata.Card.Atr.Replace(" ", "");
                return Convert.FromHexString(atrHex);
            }
            catch (Exception ex)
            {
                Logger.Error("Error getting ATR from JSON trace", ex);
                return Convert.FromHexString("3BD518FF8191FE1FC38073C821100A"); // Default
            }
        }

        /// <inheritdoc />
        public CardResponse SendCommand(byte[] command)
        {
            ArgumentNullException.ThrowIfNull(command);

            if (!IsConnected || _luaScript == null || _traceData == null)
            {
                throw new InvalidOperationException("Not connected to JSON virtual reader");
            }

            var commandHex = Convert.ToHexString(command);
            Logger.Debug($"Processing APDU {commandHex}");

            // Find matching exchange by command
            var cleanCommand = commandHex.Replace(" ", "").ToUpper();
            var matchingExchange = _traceData.Exchanges.FirstOrDefault(e => 
                e.Command == cleanCommand && 
                (_allowedExchanges.Count == 0 || _allowedExchanges.Contains(e.Index)) &&
                !_usedExchanges.Contains(e.Index));

            if (matchingExchange == null)
            {
                // Look for any matching command to provide better error message
                var anyMatch = _traceData.Exchanges.FirstOrDefault(e => e.Command == cleanCommand);
                if (anyMatch != null)
                {
                    if (_usedExchanges.Contains(anyMatch.Index))
                    {
                        throw new InvalidOperationException(
                            $"Command {cleanCommand} already used (exchange {anyMatch.Index})");
                    }
                    else if (_allowedExchanges.Any() && !_allowedExchanges.Contains(anyMatch.Index))
                    {
                        throw new InvalidOperationException(
                            $"Command {cleanCommand} not allowed in operation filter: {string.Join(",", _requestedOperations)}");
                    }
                }
                
                throw new InvalidOperationException(
                    $"No matching exchange found for command {cleanCommand}");
            }

            // Mark exchange as used
            _usedExchanges.Add(matchingExchange.Index);

            // Extract response
            var responseBytes = Convert.FromHexString(matchingExchange.Response.Replace(" ", ""));
            var statusWord = responseBytes.Length >= 2 
                ? (ushort)((responseBytes[^2] << 8) | responseBytes[^1])
                : (ushort)0x9000;
            var responseData = responseBytes.Length > 2 ? responseBytes[..^2] : Array.Empty<byte>();

            Logger.Debug($"Returning response for exchange {matchingExchange.Index} ({matchingExchange.Description}): Data={Convert.ToHexString(responseData)}, SW={statusWord:X4}");

            // Check if this is a successful EXTERNAL AUTHENTICATE command
            if (matchingExchange.Description == "EXTERNAL AUTHENTICATE" && statusWord == 0x9000)
            {
                _secureChannelEstablished = true;
                Logger.Info("Secure channel established after successful EXTERNAL AUTHENTICATE");
            }

            // Simulate response time
            if (matchingExchange.ResponseTimeMs > 0)
            {
                System.Threading.Thread.Sleep(matchingExchange.ResponseTimeMs);
            }

            return new CardResponse(responseData, statusWord);
        }

        /// <inheritdoc />
        public CardResponse SendCommand(IApduCommand command)
        {
            // Convert IApduCommand to byte array
            var apduBytes = new List<byte> { command.Cla, command.Ins, command.P1, command.P2 };

            var hasData = command.Data != null && command.Data.Length > 0;
            var hasExpectedLength = command.ExpectedResponseLength.HasValue;

            if (hasData)
            {
                if (command.IsExtendedLength && command.Data!.Length > 255)
                {
                    apduBytes.Add(0x00);
                    apduBytes.Add((byte)(command.Data.Length >> 8));
                    apduBytes.Add((byte)(command.Data.Length & 0xFF));
                }
                else
                {
                    apduBytes.Add((byte)command.Data!.Length);
                }
                apduBytes.AddRange(command.Data);
            }

            if (hasExpectedLength)
            {
                var expectedLength = command.ExpectedResponseLength!.Value;
                if (command.IsExtendedLength && expectedLength > 255)
                {
                    if (!hasData)
                    {
                        apduBytes.Add(0x00);
                    }
                    apduBytes.Add((byte)(expectedLength >> 8));
                    apduBytes.Add((byte)(expectedLength & 0xFF));
                }
                else
                {
                    apduBytes.Add(expectedLength == 0 || expectedLength == 256 ? (byte)0x00 : (byte)expectedLength);
                }
            }

            return SendCommand(apduBytes.ToArray());
        }

        /// <inheritdoc />
        public bool EstablishSecureChannel(byte[] keySet, byte securityLevel)
        {
            // For JSON virtual readers, secure channel is simulated
            Logger.Debug("Secure channel establishment simulated for JSON virtual reader");
            _secureChannelEstablished = true;
            return true;
        }

        /// <inheritdoc />
        public bool IsSecureChannelEstablished => _secureChannelEstablished;

        /// <inheritdoc />
        public void Dispose()
        {
            Disconnect();
        }

        private (string jsonPath, Dictionary<string, string> parameters) ParseJsonReaderName(string readerName)
        {
            // Parse json:trace.json?param1=value1&param2=value2
            var parts = readerName.Substring(5).Split('?', 2); // Remove "json:" prefix
            var jsonPath = parts[0];
            var parameters = new Dictionary<string, string>();

            if (parts.Length > 1)
            {
                var queryString = parts[1];
                var parsedQuery = HttpUtility.ParseQueryString(queryString);
                
                foreach (string? key in parsedQuery.AllKeys)
                {
                    if (key != null)
                    {
                        parameters[key] = parsedQuery[key] ?? "";
                    }
                }
            }

            return (jsonPath, parameters);
        }

        private string ResolveJsonPath(string jsonPath)
        {
            // Try multiple locations
            var locations = new[]
            {
                jsonPath, // Absolute path
                Path.Combine(Directory.GetCurrentDirectory(), jsonPath),
                Path.Combine(Directory.GetCurrentDirectory(), "traces", jsonPath)
            };

            foreach (var location in locations)
            {
                if (File.Exists(location))
                {
                    return location;
                }
            }

            return jsonPath; // Return original if not found
        }

        private HashSet<int> BuildAllowedExchanges(List<string> operations)
        {
            var allowed = new HashSet<int>();

            if (_traceData?.Operations == null)
                return allowed;

            foreach (var operationName in operations)
            {
                if (_traceData.Operations.TryGetValue(operationName, out var operation))
                {
                    for (int i = operation.StartExchange; i <= operation.EndExchange; i++)
                    {
                        allowed.Add(i);
                    }
                }
                else
                {
                    Logger.Warn($"Operation '{operationName}' not found in trace data");
                }
            }

            return allowed;
        }

        private void LoadTraceDataIntoLua(TraceData traceData)
        {
            if (_luaScript == null) return;

            // Create a simple Lua representation of the trace data
            var luaScript = @"
trace_metadata = {
    source_file = """ + traceData.Metadata.Source.File + @""",
    card_type = """ + traceData.Metadata.Card.CardType + @""",
    total_exchanges = " + traceData.Exchanges.Count + @"
}

function get_trace_info()
    return trace_metadata
end

function get_operations()
    local ops = {}";

            foreach (var op in traceData.Operations)
            {
                luaScript += $@"
    ops[""{op.Key}""] = {{
        description = ""{op.Value.Description}"",
        start_exchange = {op.Value.StartExchange},
        end_exchange = {op.Value.EndExchange}
    }}";
            }

            luaScript += @"
    return ops
end";

            _luaScript.DoString(luaScript);
        }

        private void RegisterLuaFunctions(Script script)
        {
            // Register utility functions
            script.Globals["hex_to_bytes"] = (Func<string, byte[]>)(hex => 
                Convert.FromHexString(hex.Replace(" ", "")));
            
            script.Globals["bytes_to_hex"] = (Func<byte[], string>)(bytes => 
                Convert.ToHexString(bytes));
                
            script.Globals["log_debug"] = (Action<string>)(msg => Logger.Debug($"Lua: {msg}"));
            script.Globals["log_info"] = (Action<string>)(msg => Logger.Info($"Lua: {msg}"));
            script.Globals["log_warn"] = (Action<string>)(msg => Logger.Warn($"Lua: {msg}"));
            script.Globals["log_error"] = (Action<string>)(msg => Logger.Error($"Lua: {msg}"));
        }
    }
}