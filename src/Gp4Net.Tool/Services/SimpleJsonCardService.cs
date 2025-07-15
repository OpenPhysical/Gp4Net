using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Web;
using Gp4Net.Tool.Services.CardCommunication;
using Gp4Net.Transport;
using JetBrains.Annotations;
using log4net;

namespace Gp4Net.Tool.Services
{
    /// <summary>
    /// Simplified JSON trace format for virtual card testing.
    /// </summary>
    public class SimpleTraceData
    {
        public TraceMetadata Metadata { get; set; } = new();
        public Dictionary<string, OperationRange> Operations { get; set; } = new();
        public List<SimpleExchange> Exchanges { get; set; } = new();
    }

    public class TraceMetadata
    {
        public string CardType { get; set; } = "NXP_P71";
        public string Atr { get; set; } = "3BD518FF8191FE1FC38073C821100A";
        public string IsdAid { get; set; } = "A000000151000000";
    }

    public class OperationRange
    {
        public int StartIndex { get; set; }
        public int EndIndex { get; set; }
    }

    /// <summary>
    /// Simplified APDU exchange.
    /// </summary>
    public class SimpleExchange
    {
        public string Command { get; set; } = "";
        public string Response { get; set; } = "";
        public string? Description { get; set; }
        public int? ResponseTimeMs { get; set; }
    }

    /// <summary>
    /// Simple JSON card service that uses minimal trace format.
    /// </summary>
    [PublicAPI]
    public class SimpleJsonCardService : ICardService
    {
        private static readonly ILog Logger = LogManager.GetLogger(typeof(SimpleJsonCardService));
        
        private SimpleTraceData? _traceData;
        private Dictionary<string, string> _parameters = new();
        private HashSet<int> _allowedExchanges = new();
        private HashSet<int> _usedExchanges = new();
        private bool _isConnected;
        private bool _secureChannelEstablished;
        private string? _readerName;

        /// <inheritdoc />
        public IReadOnlyList<string> GetReaders()
        {
            var readers = new List<string>();
            
            // Look for JSON trace files
            var tracesDir = Path.Combine(Directory.GetCurrentDirectory(), "traces");
            if (Directory.Exists(tracesDir))
            {
                foreach (var jsonFile in Directory.GetFiles(tracesDir, "*.json"))
                {
                    var fileName = Path.GetFileName(jsonFile);
                    if (!readers.Contains($"json:{fileName}"))
                    {
                        readers.Add($"json:{fileName}");
                    }
                }
            }
            
            // Add examples if not already found
            if (!readers.Any(r => r.Contains("card_info.json")))
                readers.Add("json:simple_card_info.json");
            if (!readers.Any(r => r.Contains("scp03.json")))
                readers.Add("json:simple_scp03.json?ops=info,auth");
            
            return readers.AsReadOnly();
        }

        /// <inheritdoc />
        public bool Connect(string readerName)
        {
            if (string.IsNullOrEmpty(readerName) || !readerName.StartsWith("json:"))
                return false;

            try
            {
                Disconnect(); // Ensure clean state

                _readerName = readerName;
                var (jsonPath, parameters) = ParseReaderName(readerName);
                _parameters = parameters;

                // Load JSON trace data
                var fullJsonPath = ResolveJsonPath(jsonPath);
                if (!File.Exists(fullJsonPath))
                {
                    Logger.Error($"JSON trace file not found: {fullJsonPath}");
                    return false;
                }

                var jsonContent = File.ReadAllText(fullJsonPath);
                _traceData = JsonSerializer.Deserialize<SimpleTraceData>(jsonContent, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

                if (_traceData == null)
                {
                    Logger.Error("Failed to deserialize JSON trace data");
                    return false;
                }

                // Parse requested operations
                if (_parameters.ContainsKey("ops"))
                {
                    var requestedOps = _parameters["ops"].Split(',');
                    _allowedExchanges = BuildAllowedExchanges(requestedOps);
                    Logger.Info($"Operation filter: {string.Join(", ", requestedOps)}");
                }

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
            _traceData = null;
            _isConnected = false;
            _parameters.Clear();
            _readerName = null;
            _allowedExchanges.Clear();
            _usedExchanges.Clear();
            _secureChannelEstablished = false;
            
            Logger.Debug("Disconnected from JSON virtual reader");
        }

        /// <inheritdoc />
        public bool IsConnected => _isConnected && _traceData != null;

        /// <inheritdoc />
        public byte[]? GetAtr()
        {
            if (!IsConnected || _traceData == null)
                return null;

            try
            {
                var atrHex = _traceData.Metadata.Atr.Replace(" ", "");
                return Convert.FromHexString(atrHex);
            }
            catch (Exception ex)
            {
                Logger.Error("Error getting ATR from JSON trace", ex);
                return Convert.FromHexString("3BD518FF8191FE1FC38073C821100A");
            }
        }

        /// <inheritdoc />
        public CardResponse SendCommand(byte[] command)
        {
            ArgumentNullException.ThrowIfNull(command);

            if (!IsConnected || _traceData == null)
                throw new InvalidOperationException("Not connected to JSON virtual reader");

            var commandHex = Convert.ToHexString(command);
            Logger.Debug($"Processing APDU {commandHex}");

            // Find matching exchange by command
            var matchingIndex = -1;
            for (int i = 0; i < _traceData.Exchanges.Count; i++)
            {
                var ex = _traceData.Exchanges[i];
                if (ex.Command.Equals(commandHex, StringComparison.OrdinalIgnoreCase) &&
                    (_allowedExchanges.Count == 0 || _allowedExchanges.Contains(i + 1)) &&
                    !_usedExchanges.Contains(i + 1))
                {
                    matchingIndex = i;
                    break;
                }
            }

            if (matchingIndex < 0)
            {
                throw new InvalidOperationException($"No matching exchange found for command {commandHex}");
            }

            var exchange = _traceData.Exchanges[matchingIndex];
            _usedExchanges.Add(matchingIndex + 1);

            // Extract response
            var responseHex = exchange.Response;
            byte[] responseBytes;
            ushort statusWord;

            if (responseHex.Length == 4)
            {
                // Just status word
                statusWord = Convert.ToUInt16(responseHex, 16);
                responseBytes = Array.Empty<byte>();
            }
            else
            {
                // Response data + status word
                var fullResponse = Convert.FromHexString(responseHex);
                statusWord = (ushort)((fullResponse[^2] << 8) | fullResponse[^1]);
                responseBytes = fullResponse.Length > 2 ? fullResponse[..^2] : Array.Empty<byte>();
            }

            Logger.Debug($"Returning response {matchingIndex + 1} ({exchange.Description ?? "UNKNOWN"}): SW={statusWord:X4}");

            // Check if this establishes secure channel
            if ((exchange.Description == "EXT AUTH" || exchange.Description == "EXTERNAL AUTHENTICATE") && statusWord == 0x9000)
            {
                _secureChannelEstablished = true;
                Logger.Info("Secure channel established");
            }

            // Simulate response time
            if (exchange.ResponseTimeMs > 0)
            {
                System.Threading.Thread.Sleep(exchange.ResponseTimeMs.Value);
            }

            return new CardResponse(responseBytes, statusWord);
        }

        /// <inheritdoc />
        public CardResponse SendCommand(IApduCommand command)
        {
            // Convert IApduCommand to byte array
            var apduBytes = new List<byte> { command.Cla, command.Ins, command.P1, command.P2 };

            if (command.Data != null && command.Data.Length > 0)
            {
                apduBytes.Add((byte)command.Data.Length);
                apduBytes.AddRange(command.Data);
            }

            if (command.ExpectedResponseLength.HasValue)
            {
                apduBytes.Add((byte)command.ExpectedResponseLength.Value);
            }

            return SendCommand(apduBytes.ToArray());
        }

        /// <inheritdoc />
        public bool EstablishSecureChannel(byte[] keySet, byte securityLevel)
        {
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

        private (string jsonPath, Dictionary<string, string> parameters) ParseReaderName(string readerName)
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

        private HashSet<int> BuildAllowedExchanges(string[] operations)
        {
            var allowed = new HashSet<int>();

            foreach (var operationName in operations)
            {
                if (_traceData?.Operations?.TryGetValue(operationName, out var opRange) == true)
                {
                    for (int i = opRange.StartIndex; i <= opRange.EndIndex; i++)
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
    }
}