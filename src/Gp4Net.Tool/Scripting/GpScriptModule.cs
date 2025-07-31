using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using MoonSharp.Interpreter;
using MoonSharp.Interpreter.Interop;

namespace Gp4Net.Tool.Scripting
{
    /// <summary>
    /// Provides GlobalPlatform operations to Lua scripts.
    /// </summary>
    [PublicAPI]
    [MoonSharpUserData]
    public class GpScriptModule
    {
        private readonly ICardService _cardService;
        private readonly Gp4Net.Services.IGlobalPlatformService _globalPlatformService;
        private readonly ILogger _logger;

        /// <summary>
        /// Initializes a new instance of the GpScriptModule class.
        /// </summary>
        public GpScriptModule(
            ICardService cardService,
            Gp4Net.Services.IGlobalPlatformService globalPlatformService,
            ILogger logger
        )
        {
            _cardService = cardService ?? throw new ArgumentNullException(nameof(cardService));
            _globalPlatformService =
                globalPlatformService
                ?? throw new ArgumentNullException(nameof(globalPlatformService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Connects to a card reader.
        /// </summary>
        [MoonSharpVisible(true)]
        public Table? Connect(string reader = "auto")
        {
            try
            {
                if (reader == "auto")
                {
                    var readers = _cardService.GetReaders();
                    if (readers.Count == 0)
                    {
                        _logger.LogError("No readers found");
                        return null;
                    }
                    reader = readers[0];
                }

                if (_cardService.Connect(reader))
                {
                    var script = new Script();
                    var cardTable = new Table(script) { ["reader"] = reader, ["connected"] = true };

                    return cardTable;
                }

                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to connect to reader");
                return null;
            }
        }

        /// <summary>
        /// Disconnects from the card.
        /// </summary>
        [MoonSharpVisible(true)]
        public void Disconnect(Table? card)
        {
            _cardService.Disconnect();
        }

        /// <summary>
        /// Checks if connected to a card.
        /// </summary>
        [MoonSharpVisible(true)]
        public bool IsConnected(Table? card)
        {
            return _cardService.IsConnected;
        }

        /// <summary>
        /// Establishes a secure channel.
        /// </summary>
        [MoonSharpVisible(true)]
        public Table? EstablishSecureChannel(Table card, string keyset, byte securityLevel)
        {
            if (!_cardService.IsConnected)
            {
                throw new InvalidOperationException("Not connected to card");
            }

            // For now, use default test keys
            // TODO: Integrate with keyset resolution
            var keyBytes = GpTestKeys.StandardTestKey;

            if (_cardService.EstablishSecureChannel(keyBytes, securityLevel))
            {
                var script = new Script();
                var scTable = new Table(script)
                {
                    ["protocol"] = 0x02, // TODO: Get actual protocol
                    ["security_level"] = securityLevel
                };

                return scTable;
            }

            return null;
        }

        /// <summary>
        /// Closes the secure channel.
        /// </summary>
        [MoonSharpVisible(true)]
        public void CloseSecureChannel(Table card)
        {
            // TODO: Implement when CardService supports it
            _logger.LogWarning("Close secure channel not yet implemented");
        }

        /// <summary>
        /// Selects an application.
        /// </summary>
        [MoonSharpVisible(true)]
        public Table Select(Table card, byte[] aid)
        {
            var selectResult = SelectCommand.Create(aid);
            if (selectResult.IsFailure)
            {
                throw new InvalidOperationException($"Failed to create SELECT command: {selectResult.Error.Message}");
            }
            
            var selectCommand = selectResult.Value;
            var response = _cardService.SendCommand(selectCommand);

            var script = new Script();
            var responseTable = new Table(script)
            {
                ["data"] = response.Data,
                ["sw"] = response.StatusWord
            };

            return responseTable;
        }

        /// <summary>
        /// Gets card status.
        /// </summary>
        [MoonSharpVisible(true)]
        public Table[] GetStatus(Table card, string filter = "all")
        {
            // TODO: Update to use functional GetStatusAsync
            throw new NotImplementedException("GetApplications not implemented in functional architecture");
        }

        /// <summary>
        /// Gets card information.
        /// </summary>
        [MoonSharpVisible(true)]
        public Table GetCardInfo(Table card)
        {
            var script = new Script();
            var infoTable = new Table(script);

            var atr = _cardService.GetAtr();
            if (atr != null)
            {
                infoTable["atr"] = atr;
            }

            infoTable["protocol"] = 0; // T=0

            // TODO: Get serial and CPLC when available

            return infoTable;
        }

        /// <summary>
        /// Installs a CAP file.
        /// </summary>
        [MoonSharpVisible(true)]
        public Table InstallCap(Table card, string capFile, Table? parameters)
        {
            var capData = System.IO.File.ReadAllBytes(capFile);

            bool installApplets = true;
            bool makeSelectable = true;

            if (parameters != null)
            {
                if (parameters["install_applets"] != null)
                {
                    installApplets = (bool)parameters["install_applets"];
                }

                if (parameters["make_selectable"] != null)
                {
                    makeSelectable = (bool)parameters["make_selectable"];
                }
            }

            // TODO: Update to use functional InstallCapFileAsync
            throw new NotImplementedException("InstallCapFile not implemented in functional architecture");
        }

        /// <summary>
        /// Loads a CAP file (package only).
        /// </summary>
        [MoonSharpVisible(true)]
        public Table LoadCap(Table card, string capFile, Table? parameters)
        {
            // TODO: Implement when GlobalPlatformService supports separate load
            var script = new Script();
            var resultTable = new Table(script)
            {
                ["success"] = false,
                ["error"] = "Load-only not yet implemented"
            };

            return resultTable;
        }

        /// <summary>
        /// Installs an applet from a loaded package.
        /// </summary>
        [MoonSharpVisible(true)]
        public Table InstallApplet(
            Table card,
            byte[] packageAid,
            byte[] appletAid,
            Table? parameters
        )
        {
            // TODO: Implement when GlobalPlatformService supports it
            var script = new Script();
            var resultTable = new Table(script)
            {
                ["success"] = false,
                ["error"] = "Install applet not yet implemented"
            };

            return resultTable;
        }

        /// <summary>
        /// Deletes an application or package.
        /// </summary>
        [MoonSharpVisible(true)]
        public Table Delete(Table card, byte[] aid, Table? parameters)
        {
            bool cascade = true;
            if (parameters != null && parameters["cascade"] != null)
            {
                cascade = (bool)parameters["cascade"];
            }

            // Note: Lua script execution requires synchronous operation
            // This is the only acceptable use of .GetAwaiter().GetResult() due to Lua interop constraints
            var result = _globalPlatformService.DeleteApplicationAsync(aid, cascade).GetAwaiter().GetResult();

            var script = new Script();
            var resultTable = new Table(script);

            if (result.IsSuccess)
            {
                resultTable["success"] = true;
                resultTable["error"] = null;
                resultTable["deleted_aids"] = new[] { aid }; // Simplified - just return the deleted AID
            }
            else
            {
                resultTable["success"] = false;
                resultTable["error"] = result.Error.Message;
                resultTable["deleted_aids"] = new byte[0][];
            }

            return resultTable;
        }

        /// <summary>
        /// Sets the lifecycle state of an application.
        /// </summary>
        [MoonSharpVisible(true)]
        public Table SetLifecycleState(Table card, byte[] aid, string state)
        {
            if (!Enum.TryParse<Gp4Net.Domain.LifecycleState>(state, true, out var lifecycleState))
            {
                throw new ArgumentException($"Invalid lifecycle state: {state}");
            }

            // Note: Lua script execution requires synchronous operation
            // This is the only acceptable use of .GetAwaiter().GetResult() due to Lua interop constraints
            var result = _globalPlatformService.SetLifecycleStateAsync(aid, lifecycleState).GetAwaiter().GetResult();

            var script = new Script();
            var resultTable = new Table(script);

            if (result.IsSuccess)
            {
                resultTable["success"] = true;
                resultTable["error"] = null;
            }
            else
            {
                resultTable["success"] = false;
                resultTable["error"] = result.Error.Message;
            }

            return resultTable;
        }

        /// <summary>
        /// Sends a raw APDU command.
        /// </summary>
        [MoonSharpVisible(true)]
        public Table SendApdu(Table card, byte[] apdu)
        {
            var response = _cardService.SendCommand(apdu);

            var script = new Script();
            var responseTable = new Table(script)
            {
                ["data"] = response.Data,
                ["sw"] = response.StatusWord
            };

            return responseTable;
        }

        /// <summary>
        /// Sleeps for specified milliseconds.
        /// </summary>
        [MoonSharpVisible(true)]
        public void Sleep(int milliseconds)
        {
            Thread.Sleep(milliseconds);
        }

        /// <summary>
        /// Reads a file.
        /// </summary>
        [MoonSharpVisible(true)]
        public byte[] ReadFile(string path)
        {
            return System.IO.File.ReadAllBytes(path);
        }

        /// <summary>
        /// Writes a file.
        /// </summary>
        [MoonSharpVisible(true)]
        public void WriteFile(string path, byte[] data)
        {
            System.IO.File.WriteAllBytes(path, data);
        }

        /// <summary>
        /// Lists available readers.
        /// </summary>
        [MoonSharpVisible(true)]
        public string[] ListReaders()
        {
            return [.. _cardService.GetReaders()];
        }
    }
}
