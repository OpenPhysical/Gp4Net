using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using System.Web;
using Gp4Net.Tool.Services.CardCommunication;
using Gp4Net.Transport;
using JetBrains.Annotations;
using log4net;
using MoonSharp.Interpreter;

namespace Gp4Net.Tool.Services
{
    /// <summary>
    /// Virtual card service that uses Lua scripts to simulate card behavior.
    /// Supports URL-style reader names: lua:script.lua?trace=input.txt&param=value
    /// </summary>
    [PublicAPI]
    public class LuaVirtualCardService : ICardService
    {
        private static readonly ILog Logger = LogManager.GetLogger(typeof(LuaVirtualCardService));
        
        private Script? _luaScript;
        private string? _scriptPath;
        private Dictionary<string, string> _parameters = new();
        private bool _isConnected;
        private string? _readerName;

        /// <inheritdoc />
        public IReadOnlyList<string> GetReaders()
        {
            // Return available Lua scripts in the scripts directory
            var readers = new List<string>();
            
            var scriptsDir = Path.Combine(Directory.GetCurrentDirectory(), "scripts", "virtual_readers");
            if (Directory.Exists(scriptsDir))
            {
                foreach (var luaFile in Directory.GetFiles(scriptsDir, "*.lua"))
                {
                    var scriptName = Path.GetFileNameWithoutExtension(luaFile);
                    readers.Add($"lua:{scriptName}.lua");
                }
            }
            
            // Add example readers
            readers.Add("lua:gp_pro_trace.lua?trace=docs/traces/install_uninstall.log");
            readers.Add("lua:scp03_test.lua");
            readers.Add("lua:scp02_test.lua");
            
            return readers.AsReadOnly();
        }

        /// <inheritdoc />
        public bool Connect(string readerName)
        {
            if (string.IsNullOrEmpty(readerName) || !readerName.StartsWith("lua:"))
            {
                return false;
            }

            try
            {
                Disconnect(); // Ensure clean state

                _readerName = readerName;
                var (scriptPath, parameters) = ParseLuaReaderName(readerName);
                _scriptPath = scriptPath;
                _parameters = parameters;

                // Initialize Lua script
                _luaScript = new Script();
                
                // Register core Lua libraries
                _luaScript.Options.DebugPrint = s => Logger.Debug($"Lua: {s}");
                
                // Add custom functions for card simulation
                RegisterLuaFunctions(_luaScript);

                // Load the script
                var fullScriptPath = ResolveLuaScriptPath(scriptPath);
                if (!File.Exists(fullScriptPath))
                {
                    Logger.Error($"Lua script not found: {fullScriptPath}");
                    return false;
                }

                var scriptContent = File.ReadAllText(fullScriptPath);
                _luaScript.DoString(scriptContent);

                // Initialize the script with parameters
                if (_parameters.Count > 0)
                {
                    var initFunc = _luaScript.Globals.Get("initialize");
                    if (initFunc != null && initFunc.Type == DataType.Function)
                    {
                        var paramTable = new Table(_luaScript);
                        foreach (var kvp in _parameters)
                        {
                            paramTable[kvp.Key] = kvp.Value;
                        }
                        _luaScript.Call(initFunc, paramTable);
                    }
                }

                _isConnected = true;
                Logger.Info($"Connected to Lua virtual reader: {readerName}");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Error($"Failed to connect to Lua reader {readerName}", ex);
                Disconnect();
                return false;
            }
        }

        /// <inheritdoc />
        public void Disconnect()
        {
            if (_luaScript != null)
            {
                try
                {
                    var disconnectFunc = _luaScript.Globals.Get("disconnect");
                    if (disconnectFunc != null && disconnectFunc.Type == DataType.Function)
                    {
                        _luaScript.Call(disconnectFunc);
                    }
                }
                catch (Exception ex)
                {
                    Logger.Warn("Error during Lua script disconnect", ex);
                }
                
                _luaScript = null;
            }

            _isConnected = false;
            _scriptPath = null;
            _parameters.Clear();
            _readerName = null;
            
            Logger.Debug("Disconnected from Lua virtual reader");
        }

        /// <inheritdoc />
        public bool IsConnected => _isConnected && _luaScript != null;

        /// <inheritdoc />
        public byte[]? GetAtr()
        {
            if (!IsConnected || _luaScript == null)
            {
                return null;
            }

            try
            {
                var atrFunc = _luaScript.Globals.Get("get_atr");
                if (atrFunc != null && atrFunc.Type == DataType.Function)
                {
                    var result = _luaScript.Call(atrFunc);
                    if (result.Type == DataType.String)
                    {
                        var atrHex = result.String.Replace(" ", "");
                        return Convert.FromHexString(atrHex);
                    }
                }

                // Default ATR if not provided by script
                return Convert.FromHexString("3BD518FF8191FE1FC38073C821100A");
            }
            catch (Exception ex)
            {
                Logger.Error("Error getting ATR from Lua script", ex);
                return null;
            }
        }

        /// <inheritdoc />
        public CardResponse SendCommand(byte[] command)
        {
            ArgumentNullException.ThrowIfNull(command);

            if (!IsConnected || _luaScript == null)
            {
                throw new InvalidOperationException("Not connected to Lua virtual reader");
            }

            try
            {
                var commandHex = Convert.ToHexString(command);
                Logger.Debug($"Sending APDU to Lua script: {commandHex}");

                var processFunc = _luaScript.Globals.Get("process_apdu");
                if (processFunc == null || processFunc.Type != DataType.Function)
                {
                    throw new InvalidOperationException("Lua script must provide 'process_apdu' function");
                }

                var result = _luaScript.Call(processFunc, commandHex);
                
                if (result.Type == DataType.Tuple && result.Tuple.Length >= 1)
                {
                    var responseHex = result.Tuple[0].String;
                    var responseTime = result.Tuple.Length > 1 ? (int)result.Tuple[1].Number : 20;
                    
                    var responseBytes = Convert.FromHexString(responseHex.Replace(" ", ""));
                    
                    // Extract status word (last 2 bytes)
                    var statusWord = responseBytes.Length >= 2 
                        ? (ushort)((responseBytes[^2] << 8) | responseBytes[^1])
                        : (ushort)0x9000;
                    
                    // Extract data (all bytes except last 2)
                    var responseData = responseBytes.Length > 2 
                        ? responseBytes[..^2] 
                        : Array.Empty<byte>();

                    Logger.Debug($"Received response from Lua script: Data={Convert.ToHexString(responseData)}, SW={statusWord:X4} (took {responseTime}ms)");

                    // Simulate response time
                    if (responseTime > 0)
                    {
                        Task.Delay(responseTime).Wait();
                    }

                    return new CardResponse(responseData, statusWord);
                }
                else if (result.Type == DataType.String)
                {
                    // Simple string response
                    var responseBytes = Convert.FromHexString(result.String.Replace(" ", ""));
                    var statusWord = responseBytes.Length >= 2 
                        ? (ushort)((responseBytes[^2] << 8) | responseBytes[^1])
                        : (ushort)0x9000;
                    var responseData = responseBytes.Length > 2 ? responseBytes[..^2] : Array.Empty<byte>();

                    return new CardResponse(responseData, statusWord);
                }
                else
                {
                    throw new InvalidOperationException($"Invalid response type from Lua script: {result.Type}");
                }
            }
            catch (ScriptRuntimeException ex)
            {
                Logger.Error($"Lua script runtime error: {ex.DecoratedMessage}", ex);
                throw new InvalidOperationException($"Lua script error: {ex.DecoratedMessage}", ex);
            }
            catch (Exception ex)
            {
                Logger.Error($"Error processing APDU in Lua script", ex);
                throw;
            }
        }

        /// <inheritdoc />
        public CardResponse SendCommand(IApduCommand command)
        {
            // Convert IApduCommand to byte array using the existing logic from EnhancedWsctCardService
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
            // For virtual readers, we don't need to establish a real secure channel
            // The Lua script handles the secure messaging simulation
            Logger.Debug("Secure channel establishment delegated to Lua script");
            return true;
        }

        /// <inheritdoc />
        public bool IsSecureChannelEstablished => true; // Always true for virtual readers

        /// <inheritdoc />
        public void Dispose()
        {
            Disconnect();
        }

        private (string scriptPath, Dictionary<string, string> parameters) ParseLuaReaderName(string readerName)
        {
            // Parse lua:script.lua?param1=value1&param2=value2
            var parts = readerName.Substring(4).Split('?', 2); // Remove "lua:" prefix
            var scriptPath = parts[0];
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

            return (scriptPath, parameters);
        }

        private string ResolveLuaScriptPath(string scriptPath)
        {
            // Try multiple locations
            var locations = new[]
            {
                scriptPath, // Absolute path
                Path.Combine(Directory.GetCurrentDirectory(), scriptPath),
                Path.Combine(Directory.GetCurrentDirectory(), "scripts", "virtual_readers", scriptPath),
                Path.Combine(Directory.GetCurrentDirectory(), "scripts", scriptPath)
            };

            foreach (var location in locations)
            {
                if (File.Exists(location))
                {
                    return location;
                }
            }

            return scriptPath; // Return original if not found
        }

        private void RegisterLuaFunctions(Script script)
        {
            // Register utility functions that Lua scripts can use
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