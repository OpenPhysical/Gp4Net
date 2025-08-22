using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Tool.Services.CardCommunication;
using Gp4Net.Transport;
using JetBrains.Annotations;
using log4net;
using WSCT.Wrapper;

namespace Gp4Net.Tool.Services;

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
    
    // Thread safety: Protect all mutable state with reader-writer lock
    private readonly ReaderWriterLockSlim _stateLock = new();
    private ICardChannelWrapper _channel;
    // Legacy session removed - using functional SecureChannelState instead
    private Domain.Security.SecureChannelState _secureChannelState;
    private IApduTransport _transport;
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
                return [];
            }

            var readers = _context.Readers;
            Logger.Debug($"Found {readers.Count} card readers");
            return readers;
        }
        catch (Exception ex)
        {
            Logger.Error("Failed to list card readers", ex);
            return [];
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

        // Thread safety: Use write lock to protect state modification
        _stateLock.EnterWriteLock();
        try
        {
            DisconnectInternal(); // Ensure clean state

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
        finally
        {
            _stateLock.ExitWriteLock();
        }
    }

    /// <inheritdoc />
    public void Disconnect()
    {
        // Thread safety: Use write lock for public disconnect method
        _stateLock.EnterWriteLock();
        try
        {
            DisconnectInternal();
        }
        finally
        {
            _stateLock.ExitWriteLock();
        }
    }

    /// <summary>
    /// Internal disconnect method that assumes lock is already held.
    /// Used by Connect method which already holds write lock.
    /// </summary>
    private void DisconnectInternal()
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
                _secureChannelState = null;
                _transport = null;
            }
        }
    }

    /// <inheritdoc />
    public bool IsConnected
    {
        get
        {
            // Thread safety: Use read lock to safely check connection state
            _stateLock.EnterReadLock();
            try
            {
                // Simply check if channel exists - GetStatus() can hang
                return _channel != null;
            }
            finally
            {
                _stateLock.ExitReadLock();
            }
        }
    }

    /// <inheritdoc />
    public byte[] GetAtr()
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

    private byte[] GetAtrUsingGetAttrib()
    {
        try
        {
            Logger.Debug("Using GetAttrib for ATR retrieval");

            // Direct call like in working implementation - no timeout needed
            byte[] atrBuffer = null;
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

            // Note: Secure channel wrapping should be done through SendCommand(IApduCommand)
            Logger.Debug($"Sending APDU: {Convert.ToHexString(command)}");

            var apdu = _wsctFactory.CreateCommandApdu(command);
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

            var responseData = responseApdu.Udr ?? [];
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
        // TODO: Update to use functional security processors
        if (_secureChannelState != null)
        {
            try
            {
                // Secure channel wrapping disabled - use GlobalPlatformService for secure channel operations
                Logger.Error("Direct secure channel operations not supported in WsctCardService. Use GlobalPlatformService instead.");
                return new CardResponse([], 0x6F00); // SW_UNKNOWN_ERROR
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

            var hasData = command.Data is { Length: > 0 };
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
                        expectedLength is 0 or 256
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
            var keySetResult = Scp02KeySet.Create(
                keySet, // ENC key
                keySet, // MAC key
                keySet, // DEK key
                0xFF // Key version
            );

            if (keySetResult.IsFailure)
            {
                Logger.Error($"Failed to create Scp02KeySet: {keySetResult.Error.Message}");
                return false;
            }

            var scp02KeySet = keySetResult.Value;

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
                _secureChannelState = null;
                _secureChannelState = null;
                return false;
            }

            _secureChannelState = establishResult.Value;
            
            // TODO: Create functional SecureChannelState instead of legacy SecureChannelSession
            // _secureChannelState = CreateSecureChannelState(sessionKeys, securityLevel, protocolVersion);

            Logger.Info(
                $"Successfully established secure channel with security level: {secLevel}"
            );
            return true;
        }
        catch (Exception ex)
        {
            Logger.Error("Failed to establish secure channel", ex);
            _secureChannelState = null;
            return false;
        }
    }

    /// <inheritdoc />
    public bool IsSecureChannelEstablished
    {
        get
        {
            return _secureChannelState != null;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        // Thread safety: Protect disposal from concurrent access
        _stateLock.EnterWriteLock();
        try
        {
            if (!_disposed)
            {
                DisconnectInternal();
                _context?.Dispose();
                _disposed = true;
            }
        }
        finally
        {
            _stateLock.ExitWriteLock();
            _stateLock.Dispose(); // Dispose the lock after all operations
        }
    }
}