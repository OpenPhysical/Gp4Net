using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Gp4Net.Constants;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Tool.Services.CardCommunication;
using Gp4Net.Transport;
using JetBrains.Annotations;
using log4net;
using WSCT.Core;
using WSCT.ISO7816;
using WSCT.Wrapper;
using WSCT.Wrapper.Desktop.Core;

namespace Gp4Net.Tool.Services
{
    /// <summary>
    /// Enhanced WSCT-based implementation that leverages more built-in WSCT functionality.
    /// </summary>
    [PublicAPI]
    public class EnhancedWsctCardService : ICardService
    {
        private static readonly ILog Logger = LogManager.GetLogger(typeof(EnhancedWsctCardService));

        private readonly ISecureChannelManager _secureChannelManager;
        private readonly IApduTransportFactory _transportFactory;
        private CardContext? _context;
        private CardChannel? _channel;
        private SecureChannelSession? _secureChannelSession;
        private IApduTransport? _transport;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the EnhancedWsctCardService class.
        /// </summary>
        public EnhancedWsctCardService(
            ISecureChannelManager secureChannelManager,
            IApduTransportFactory transportFactory
        )
        {
            _secureChannelManager =
                secureChannelManager
                ?? throw new ArgumentNullException(nameof(secureChannelManager));
            _transportFactory =
                transportFactory ?? throw new ArgumentNullException(nameof(transportFactory));
        }

        /// <inheritdoc />
        public IReadOnlyList<string> GetReaders()
        {
            try
            {
                // Use WSCT built-in functionality directly
                var tempContext = new CardContext();
                var result = tempContext.Establish();
                if (result != ErrorCode.Success)
                {
                    Logger.Warn($"Failed to establish context for reader enumeration: {result}");
                    return Array.Empty<string>();
                }

                result = tempContext.ListReaders("");
                if (result != ErrorCode.Success)
                {
                    Logger.Warn($"Failed to list readers: {result}");
                    return Array.Empty<string>();
                }

                // Convert to IReadOnlyList and ensure we have actual data
                var readers = tempContext.Readers?.ToList() ?? [];
                Logger.Debug($"Found {readers.Count} card readers");
                return readers.AsReadOnly();
            }
            catch (Exception ex)
            {
                Logger.Error("Failed to list card readers", ex);
                return Array.Empty<string>();
            }
        }

        /// <inheritdoc />
        public bool Connect(string readerName)
        {
            if (string.IsNullOrEmpty(readerName))
            {
                throw new ArgumentException(
                    "Reader name cannot be null or empty",
                    nameof(readerName)
                );
            }

            try
            {
                Disconnect(); // Ensure clean state

                // Use WSCT built-in CardContext and CardChannel directly
                _context = new CardContext();
                var result = _context.Establish();
                if (result != ErrorCode.Success)
                {
                    Logger.Error($"Failed to establish card context: {result}");
                    return false;
                }

                _channel = new CardChannel(_context, readerName);
                result = _channel.Connect(WSCT.Wrapper.ShareMode.Exclusive, WSCT.Wrapper.Protocol.Any);
                if (result != ErrorCode.Success)
                {
                    // WSCT CardChannel doesn't implement IDisposable
                    _channel = null;
                    _ = _context.Release();
                    // WSCT CardContext doesn't implement IDisposable
                    _context = null;
                    Logger.Error($"Failed to connect to reader {readerName}: {result}");
                    return false;
                }

                Logger.Info($"Connected to card in reader: {readerName}");

                // Detect transport protocol based on actual protocol in use
                var activeProtocol = _channel.Protocol;
                var transportProtocol =
                    activeProtocol == WSCT.Wrapper.Protocol.T1 ? TransportProtocol.T1 : TransportProtocol.T0;
                _transport = _transportFactory.CreateTransport(transportProtocol);

                Logger.Debug($"Using transport protocol: {transportProtocol}");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Error($"Failed to connect to reader {readerName}", ex);
                Disconnect(); // Clean up on error
                return false;
            }
        }

        /// <inheritdoc />
        public void Disconnect()
        {
            if (_channel != null)
            {
                try
                {
                    // Use WSCT built-in disconnect functionality
                    _ = _channel.Disconnect(Disposition.UnpowerCard);
                    Logger.Debug("Disconnected from card");
                }
                catch (Exception ex)
                {
                    Logger.Warn("Error during card disconnect", ex);
                }
                finally
                {
                    // WSCT CardChannel doesn't implement IDisposable
                    _channel = null;
                    _secureChannelSession = null;
                    _transport = null;
                }
            }

            if (_context != null)
            {
                try
                {
                    _ = _context.Release();
                    // WSCT CardContext doesn't implement IDisposable
                }
                catch (Exception ex)
                {
                    Logger.Warn("Error during context release", ex);
                }
                finally
                {
                    _context = null;
                }
            }
        }

        /// <inheritdoc />
        public bool IsConnected => _channel != null && _context != null;

        /// <inheritdoc />
        public byte[]? GetAtr()
        {
            if (!IsConnected || _channel == null)
            {
                return null;
            }

            try
            {
                // Use WSCT built-in GetAttrib functionality
                byte[]? atrBuffer = null;
                var result = _channel.GetAttrib(Attrib.AtrString, ref atrBuffer);

                if (result != ErrorCode.Success)
                {
                    Logger.Warn($"GetAttrib failed with result: {result}");
                    return null;
                }

                if (atrBuffer == null || atrBuffer.Length == 0)
                {
                    Logger.Warn("ATR buffer is null or empty");
                    return null;
                }

                Logger.Debug($"Card ATR: {Convert.ToHexString(atrBuffer)}");
                return atrBuffer;
            }
            catch (Exception ex)
            {
                Logger.Error("Failed to get card ATR", ex);
                return null;
            }
        }

        /// <inheritdoc />
        public CardResponse SendCommand(byte[] command)
        {
            ArgumentNullException.ThrowIfNull(command);

            if (!IsConnected || _channel == null)
            {
                throw new InvalidOperationException("Card is not connected");
            }

            try
            {
                // Note: Secure channel wrapping should be done through SendCommand(IApduCommand)
                // This method is now only for raw byte array commands without secure channel
                var commandToSend = command;
                Logger.Debug($"Sending APDU: {Convert.ToHexString(commandToSend)}");

                // Use WSCT built-in CommandAPDU and ResponseAPDU classes
                var commandApdu = new CommandAPDU(commandToSend);
                var responseApdu = new ResponseAPDU();

                var result = _channel.Transmit(commandApdu, responseApdu);
                if (result != ErrorCode.Success)
                {
                    throw new InvalidOperationException($"Transmit failed: {result}");
                }

                var responseData = responseApdu.Udr ?? Array.Empty<byte>();
                var statusWord = responseApdu.StatusWord;

                // Note: Response unwrapping is handled by SendCommand(IApduCommand) when secure channel is active
                Logger.Debug(
                    $"Received response: Data={Convert.ToHexString(responseData)}, SW={statusWord:X4}"
                );

                return new CardResponse(responseData, statusWord);
            }
            catch (InvalidOperationException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Logger.Error($"Failed to send APDU command: {Convert.ToHexString(command)}", ex);
                throw new InvalidOperationException("Failed to communicate with card", ex);
            }
        }

        /// <inheritdoc />
        public CardResponse SendCommand(IApduCommand command)
        {
            ArgumentNullException.ThrowIfNull(command);

            // If secure channel is established, wrap the command
            if (_secureChannelSession != null)
            {
                try
                {
                    // Get wrapped command data and Le from secure channel
                    var (wrappedData, expectedResponseLength) = _secureChannelSession.WrapCommand(command);

                    if (Logger.IsDebugEnabled)
                    {
                        Logger.Debug($"Secure channel wrapping:");
                        Logger.Debug($"  Original command: CLA={command.Cla:X2} INS={command.Ins:X2} P1={command.P1:X2} P2={command.P2:X2}");
                        if (command.Data != null)
                        {
                            Logger.Debug($"  Original data: {Convert.ToHexString(command.Data)} (length={command.Data.Length})");
                        }
                        Logger.Debug($"  Expected response length: {expectedResponseLength?.ToString() ?? "none"}");
                        Logger.Debug($"  Wrapped data: {Convert.ToHexString(wrappedData)}");
                    }

                    // Build final APDU with wrapped data and Le
                    var finalApdu = new List<byte>(wrappedData);
                    
                    // Add Le if needed
                    if (expectedResponseLength.HasValue)
                    {
                        var le = expectedResponseLength.Value;
                        if (command.IsExtendedLength && le > 255)
                        {
                            // Extended length Le
                            if (wrappedData.Length == 4) // No data, need 00 before Le
                            {
                                finalApdu.Add(0x00);
                            }
                            finalApdu.Add((byte)(le >> 8));
                            finalApdu.Add((byte)(le & 0xFF));
                        }
                        else
                        {
                            // Short length Le
                            finalApdu.Add(le == 0 || le == 256 ? (byte)0x00 : (byte)le);
                        }
                        
                        if (Logger.IsDebugEnabled)
                        {
                            Logger.Debug($"  Added Le={le} (0x{le:X2})");
                        }
                    }
                    
                    if (Logger.IsDebugEnabled)
                    {
                        Logger.Debug($"  Final APDU: {Convert.ToHexString([.. finalApdu])}");
                    }

                    // Send wrapped command and get response
                    var response = SendCommand([.. finalApdu]);
                    
                    // Unwrap response if secure channel has R-MAC or R-ENC
                    if (_secureChannelSession.SecurityLevel.HasRMac() || _secureChannelSession.SecurityLevel.HasREncryption())
                    {
                        // Combine data and SW for unwrapping
                        var fullResponse = new byte[response.Data.Length + 2];
                        Array.Copy(response.Data, 0, fullResponse, 0, response.Data.Length);
                        fullResponse[fullResponse.Length - 2] = (byte)(response.StatusWord >> 8);
                        fullResponse[fullResponse.Length - 1] = (byte)(response.StatusWord & 0xFF);

                        if (Logger.IsDebugEnabled)
                        {
                            Logger.Debug($"Secure channel unwrapping:");
                            Logger.Debug($"  Wrapped response: {Convert.ToHexString(fullResponse)}");
                        }

                        var unwrapped = _secureChannelSession.UnwrapResponse(fullResponse);

                        // Extract unwrapped data and SW
                        byte[] unwrappedData = Array.Empty<byte>();
                        ushort unwrappedSw = 0x6F00;
                        
                        if (unwrapped.Length >= 2)
                        {
                            unwrappedData = new byte[unwrapped.Length - 2];
                            Array.Copy(unwrapped, 0, unwrappedData, 0, unwrappedData.Length);
                            unwrappedSw = (ushort)(
                                (unwrapped[unwrapped.Length - 2] << 8) | unwrapped[unwrapped.Length - 1]
                            );
                        }

                        if (Logger.IsDebugEnabled)
                        {
                            Logger.Debug($"  Unwrapped: Data={Convert.ToHexString(unwrappedData)}, SW={unwrappedSw:X4}");
                        }

                        return new CardResponse(unwrappedData, unwrappedSw);
                    }
                    
                    return response;
                }
                catch (Exception ex)
                {
                    Logger.Error("Failed to wrap command with secure channel", ex);
                    throw;
                }
            }
            else
            {
                // No secure channel - build APDU normally
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
                    if (command.Data != null)
                    {
                        apduBytes.AddRange(command.Data);
                    }
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
                        apduBytes.Add(
                            expectedLength == 0 || expectedLength == 256
                                ? (byte)0x00
                                : (byte)expectedLength
                        );
                    }
                }

                return SendCommand([.. apduBytes]);
            }
        }

        /// <inheritdoc />
        public bool EstablishSecureChannel(byte[] keySet, byte securityLevel)
        {
            ArgumentNullException.ThrowIfNull(keySet);

            if (!IsConnected)
            {
                throw new InvalidOperationException("Card is not connected");
            }

            if (_transport == null)
            {
                throw new InvalidOperationException("Transport not initialized");
            }

            try
            {
                var scp03KeySet = new Scp03KeySet(keySet, keySet, keySet, 0x00);
                var secLevel = (SecurityLevel)securityLevel;
                var cardChannel = new CardServiceChannelAdapter(this, TransportProtocol.T0);

                Logger.Info($"Establishing secure channel:");
                Logger.Info($"  Key Version: 0x{scp03KeySet.KeyVersion:X2}");
                Logger.Info($"  Security Level: {secLevel}");
                
                if (Logger.IsDebugEnabled)
                {
                    Logger.Debug($"  Key Set (first 8 bytes): {Convert.ToHexString(keySet.Take(8).ToArray())}...");
                }

                _secureChannelSession = Task.Run(
                        async () =>
                            await _secureChannelManager
                                .EstablishAsync(
                                    cardChannel,
                                    _transport,
                                    scp03KeySet,
                                    secLevel,
                                    CancellationToken.None
                                )
                                .ConfigureAwait(false)
                    )
                    .GetAwaiter()
                    .GetResult();

                Logger.Info(
                    $"Successfully established secure channel with security level: {secLevel}"
                );
                
                if (_secureChannelSession != null && Logger.IsDebugEnabled)
                {
                    Logger.Debug($"  Session ID: {Convert.ToHexString(_secureChannelSession.SessionId)}");
                    Logger.Debug($"  Protocol: SCP{_secureChannelSession.ProtocolVersion:X2}");
                }
                
                return true;
            }
            catch (Exception ex)
            {
                Logger.Error("Failed to establish secure channel", ex);
                _secureChannelSession = null;
                return false;
            }
        }

        /// <inheritdoc />
        public bool IsSecureChannelEstablished => _secureChannelSession != null;

        /// <inheritdoc />
        public void Dispose()
        {
            if (!_disposed)
            {
                Disconnect();
                _disposed = true;
            }
        }
    }
}
