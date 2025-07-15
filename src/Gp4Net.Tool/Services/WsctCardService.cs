using System;
using System.Collections.Generic;
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
using WSCT.ISO7816;
using WSCT.Wrapper;

namespace Gp4Net.Tool.Services
{
    /// <summary>
    /// WSCT-based implementation of the card service.
    /// </summary>
    [PublicAPI]
    public class WsctCardService : ICardService
    {
        private static readonly ILog Logger = LogManager.GetLogger(typeof(WsctCardService));

        private readonly IWsctFactory _wsctFactory;
        private readonly ICardContextWrapper _context;
        private readonly ISecureChannelManager _secureChannelManager;
        private readonly IApduTransportFactory _transportFactory;
        private ICardChannelWrapper? _channel;
        private SecureChannelSession? _secureChannelSession;
        private IApduTransport? _transport;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the WsctCardService class.
        /// </summary>
        /// <param name="wsctFactory">Factory for creating WSCT objects.</param>
        /// <param name="secureChannelManager">The secure channel manager.</param>
        /// <param name="transportFactory">The APDU transport factory.</param>
        public WsctCardService(
            IWsctFactory wsctFactory,
            ISecureChannelManager secureChannelManager,
            IApduTransportFactory transportFactory
        )
        {
            _wsctFactory = wsctFactory ?? throw new ArgumentNullException(nameof(wsctFactory));
            _secureChannelManager =
                secureChannelManager
                ?? throw new ArgumentNullException(nameof(secureChannelManager));
            _transportFactory =
                transportFactory ?? throw new ArgumentNullException(nameof(transportFactory));
            _context = _wsctFactory.CreateCardContext();

            var result = _context.Establish();
            if (result != ErrorCode.Success)
            {
                throw new InvalidOperationException($"Failed to establish card context: {result}");
            }
        }

        /// <summary>
        /// Initializes a new instance of the WsctCardService class with default factories.
        /// </summary>
        public WsctCardService(
            ISecureChannelManager secureChannelManager,
            IApduTransportFactory transportFactory
        )
            : this(new WsctFactory(), secureChannelManager, transportFactory) { }

        /// <inheritdoc />
        public IReadOnlyList<string> GetReaders()
        {
            try
            {
                var result = _context.ListReaders("");
                if (result != ErrorCode.Success)
                {
                    Logger.Warn($"Failed to list readers: {result}");
                    return Array.Empty<string>();
                }

                var readers = _context.Readers;
                Logger.Debug($"Found {readers.Count} card readers");
                return readers;
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

                _channel = _context.CreateCardChannel(readerName);
                var result = _channel.Connect(WSCT.Wrapper.ShareMode.Exclusive, WSCT.Wrapper.Protocol.T0 | WSCT.Wrapper.Protocol.T1);
                if (result != ErrorCode.Success)
                {
                    _channel.Dispose();
                    _channel = null;
                    Logger.Error($"Failed to connect to reader {readerName}: {result}");
                    return false;
                }
                Logger.Info($"Connected to card in reader: {readerName}");

                // Detect transport protocol based on ATR or default to T=0
                _transport = _transportFactory.CreateTransport(TransportProtocol.T0);

                return true;
            }
            catch (Exception ex)
            {
                Logger.Error($"Failed to connect to reader {readerName}", ex);
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
                    _ = _channel.Disconnect(Disposition.UnpowerCard);
                    Logger.Debug("Disconnected from card");
                }
                catch (Exception ex)
                {
                    Logger.Warn("Error during card disconnect", ex);
                }
                finally
                {
                    _channel.Dispose();
                    _channel = null;
                    _secureChannelSession = null;
                    _transport = null;
                }
            }
        }

        /// <inheritdoc />
        public bool IsConnected
        {
            get
            {
                // Simply check if channel exists - GetStatus() can hang
                return _channel != null;
            }
        }

        /// <inheritdoc />
        public byte[]? GetAtr()
        {
            if (!IsConnected || _channel == null)
            {
                return null;
            }

            try
            {
                Logger.Debug("Attempting to get ATR from card channel");

                // Use GetAttrib with timeout as the primary method
                // GetStatus method is not available in the wrapper interface
                return GetAtrUsingGetAttrib();
            }
            catch (Exception ex)
            {
                Logger.Error("Failed to get card ATR", ex);
                return null;
            }
        }

        private byte[]? GetAtrUsingGetAttrib()
        {
            try
            {
                Logger.Debug("Using GetAttrib for ATR retrieval");

                // Direct call like in working implementation - no timeout needed
                byte[]? atrBuffer = null;
                var result = _channel?.GetAttrib(Attrib.AtrString, ref atrBuffer!) ?? ErrorCode.InternalError;

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
                Logger.Debug($"GetAttrib failed: {ex.Message}");
                return null;
            }
        }

        /// <inheritdoc />
        public CardResponse SendCommand(byte[] command)
        {
            ArgumentNullException.ThrowIfNull(command);

            if (!IsConnected)
            {
                throw new InvalidOperationException("Card is not connected");
            }

            try
            {
                var commandToSend = command;

                // Note: Secure channel wrapping should be done through SendCommand(IApduCommand)
                Logger.Debug($"Sending APDU: {Convert.ToHexString(commandToSend)}");

                var apdu = _wsctFactory.CreateCommandApdu(commandToSend);
                var response = _wsctFactory.CreateResponseApdu();
                var result = _channel!.Transmit(apdu, response);

                if (result != ErrorCode.Success)
                {
                    throw new InvalidOperationException($"Transmit failed: {result}");
                }

                var responseApdu = response as WSCT.ISO7816.ResponseAPDU;
                if (responseApdu == null)
                {
                    throw new InvalidOperationException("Invalid response type received");
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
                // Re-throw InvalidOperationException with original message for specific error cases
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
                    var wrapResult = _secureChannelSession.WrapCommand(command);
                    if (wrapResult.IsFailure)
                    {
                        throw new InvalidOperationException($"Failed to wrap command: {wrapResult.Error.Message}");
                    }
                    var (wrappedData, expectedResponseLength) = wrapResult.Value;

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

                        var unwrapResult = _secureChannelSession.UnwrapResponse(fullResponse);
                        if (unwrapResult.IsFailure)
                        {
                            throw new InvalidOperationException($"Failed to unwrap response: {unwrapResult.Error.Message}");
                        }
                        var unwrapped = unwrapResult.Value;

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
                            apduBytes.Add(0x00); // Extended length prefix if no data
                        }

                        apduBytes.Add((byte)(expectedLength >> 8));
                        apduBytes.Add((byte)(expectedLength & 0xFF));
                    }
                    else
                    {
                        // For standard length, add LE byte
                        // If expectedLength is 0 or 256, send 0x00 (meaning max response)
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
                // For now, assume SCP02 with test keys
                // In a real implementation, this would be configurable
                var scp02KeySet = Scp02KeySet.Create(
                    keySet, // ENC key
                    keySet, // MAC key
                    keySet, // DEK key
                    0xFF
                ).GetOrThrow(e => new InvalidOperationException($"Failed to create Scp02KeySet: {e.Message}")); // Key version

                var secLevel = (SecurityLevel)securityLevel;
                var cardChannel = new CardServiceChannelAdapter(this, TransportProtocol.T0);

                // Establish secure channel
                // Use Task.Run to prevent deadlocks when calling async method from sync context
                var establishResult = Task.Run(
                        async () =>
                            await _secureChannelManager
                                .EstablishAsync(
                                    cardChannel,
                                    _transport,
                                    scp02KeySet,
                                    secLevel,
                                    CancellationToken.None
                                )
                                .ConfigureAwait(false)
                    )
                    .GetAwaiter()
                    .GetResult();

                if (establishResult.IsFailure)
                {
                    Logger.Error($"Failed to establish secure channel: {establishResult.Error.Message}");
                    _secureChannelSession = null;
                    return false;
                }

                _secureChannelSession = establishResult.Value;

                Logger.Info(
                    $"Successfully established secure channel with security level: {secLevel}"
                );
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
                _context?.Dispose();
                _disposed = true;
            }
        }
    }
}
