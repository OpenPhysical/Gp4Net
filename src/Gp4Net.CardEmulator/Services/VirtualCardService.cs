using System;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Services;

/// <summary>
/// Service for managing virtual card operations in test environments.
/// Provides a unified interface for card reader management and communication.
/// </summary>
[PublicAPI]
public class VirtualCardService : IDisposable
{
    private readonly VirtualReaderManager _readerManager;
    private readonly Maybe<VirtualCardReader> _connectedReader;
    private readonly bool _disposed;

    /// <summary>
    /// Initializes a new instance of the VirtualCardService class.
    /// </summary>
    public VirtualCardService()
    {
        _readerManager = new VirtualReaderManager();
        _connectedReader = Maybe<VirtualCardReader>.None;
        _disposed = false;
    }

    /// <summary>
    /// Private constructor for creating new instances with state.
    /// </summary>
    private VirtualCardService(VirtualReaderManager readerManager, Maybe<VirtualCardReader> connectedReader, bool disposed)
    {
        _readerManager = readerManager;
        _connectedReader = connectedReader;
        _disposed = disposed;
    }

    /// <summary>
    /// Gets the virtual reader manager for managing card readers.
    /// </summary>
    /// <returns>The virtual reader manager instance.</returns>
    public VirtualReaderManager GetReaderManager()
    {
        return _disposed 
            ? new VirtualReaderManager() // Return empty manager if disposed
            : _readerManager;
    }

    /// <summary>
    /// Connects to a virtual card reader by name.
    /// </summary>
    /// <param name="readerName">The name of the reader to connect to.</param>
    /// <returns>A result indicating whether the connection was successful.</returns>
    public Result<bool, SmartCardError> Connect(string readerName)
    {
        if (_disposed)
        {
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.CommunicationError("Service has been disposed"));
        }

        return Maybe<string>.From(readerName)
            .Where(name => !string.IsNullOrEmpty(name))
            .ToResult(SmartCardError.InvalidArgument("Reader name cannot be null or empty"))
            .Bind(name => FindAndConnectToReader(name));
    }

    /// <summary>
    /// Finds and connects to the specified reader.
    /// </summary>
    private Result<bool, SmartCardError> FindAndConnectToReader(string readerName)
    {
        Maybe<VirtualCardReader> reader = Maybe<VirtualCardReader>.From(_readerManager.GetReader(readerName));
        
        return reader.ToResult(SmartCardError.CommunicationError($"Reader '{readerName}' not found"))
            .Map(r => r.Connect());
    }

    /// <summary>
    /// Creates a new service instance with a connected reader.
    /// </summary>
    /// <param name="reader">The reader to connect to.</param>
    /// <returns>A new service instance with the reader connected.</returns>
    public VirtualCardService WithConnectedReader(VirtualCardReader reader)
    {
        return new VirtualCardService(_readerManager, Maybe<VirtualCardReader>.From(reader), _disposed);
    }

    /// <summary>
    /// Sends an APDU command to the connected card.
    /// </summary>
    /// <param name="command">The APDU command bytes to send.</param>
    /// <returns>A virtual command response compatible with test expectations.</returns>
    public VirtualCommandResponse SendCommand(byte[] command)
    {
        if (_disposed)
        {
            return VirtualCommandResponse.Failed(SmartCardError.CommunicationError("Service has been disposed"));
        }

        return Maybe<byte[]>.From(command)
            .Where(cmd => cmd.Length > 0)
            .ToResult(SmartCardError.InvalidArgument("Command cannot be null or empty"))
            .Bind(cmd => _connectedReader
                .ToResult(SmartCardError.CommunicationError("No reader is connected"))
                .Map(reader => reader.TransmitCommand(cmd))
                .Map(VirtualCommandResponse.FromApduResponse))
            .Match(
                success => success,
                error => VirtualCommandResponse.Failed(error));
    }

    /// <summary>
    /// Disconnects from the current reader and returns a disposed service.
    /// </summary>
    public VirtualCardService Disconnect()
    {
        _connectedReader.Match(
            reader => { reader.Disconnect(); return true; },
            () => true);

        return new VirtualCardService(_readerManager, Maybe<VirtualCardReader>.None, false);
    }

    /// <summary>
    /// Creates a disposed version of this service.
    /// </summary>
    public VirtualCardService MarkDisposed()
    {
        VirtualCardService disconnectedService = Disconnect();
        disconnectedService._readerManager.Clear();
        return new VirtualCardService(_readerManager, Maybe<VirtualCardReader>.None, true);
    }

    /// <summary>
    /// Disposes the service resources.
    /// </summary>
    public void Dispose()
    {
        // Functional approach - create disposed instance
        VirtualCardService disposedService = MarkDisposed();
        // Note: In pure functional approach, we'd return the disposed service
        // but IDisposable interface requires void return
    }
}

/// <summary>
/// Represents a virtual command response that matches test expectations.
/// Adapts between different response formats for compatibility.
/// </summary>
[PublicAPI]
public class VirtualCommandResponse
{
    /// <summary>
    /// Gets a value indicating whether the command was successful.
    /// </summary>
    public bool IsSuccessful { get; }

    /// <summary>
    /// Gets the response data bytes (excluding status word).
    /// </summary>
    public byte[] Data { get; }

    /// <summary>
    /// Gets the status word from the response.
    /// </summary>
    public StatusWord StatusWord { get; }

    /// <summary>
    /// Gets any error information if the command failed.
    /// </summary>
    public Maybe<SmartCardError> Error { get; }

    /// <summary>
    /// Initializes a new instance of the VirtualCommandResponse class.
    /// </summary>
    /// <param name="isSuccessful">Whether the command was successful.</param>
    /// <param name="data">The response data.</param>
    /// <param name="statusWord">The status word.</param>
    /// <param name="error">Any error information.</param>
    private VirtualCommandResponse(bool isSuccessful, byte[] data, StatusWord statusWord, Maybe<SmartCardError> error)
    {
        IsSuccessful = isSuccessful;
        Data = data ?? [];
        StatusWord = statusWord;
        Error = error;
    }

    /// <summary>
    /// Creates a successful response from an APDU response.
    /// </summary>
    /// <param name="apduResponse">The APDU response to convert.</param>
    /// <returns>A virtual command response.</returns>
    public static VirtualCommandResponse FromApduResponse(ApduResponse apduResponse)
    {
        bool isSuccessful = apduResponse.IsSuccessful;
        Maybe<SmartCardError> error = isSuccessful 
            ? Maybe<SmartCardError>.None 
            : Maybe<SmartCardError>.From(SmartCardError.FromStatusWord(apduResponse.StatusWord));

        return new VirtualCommandResponse(
            isSuccessful, 
            apduResponse.Data, 
            apduResponse.StatusWord, 
            error);
    }

    /// <summary>
    /// Creates a failed response with error information.
    /// </summary>
    /// <param name="error">The error that caused the failure.</param>
    /// <returns>A virtual command response indicating failure.</returns>
    public static VirtualCommandResponse Failed(SmartCardError error)
    {
        return new VirtualCommandResponse(
            false, 
            [], 
            0x6F00, // Generic error status word
            Maybe<SmartCardError>.From(error));
    }

    /// <summary>
    /// Creates a successful response with data.
    /// </summary>
    /// <param name="data">The response data.</param>
    /// <returns>A virtual command response indicating success.</returns>
    public static VirtualCommandResponse Success(byte[]? data = null)
    {
        return new VirtualCommandResponse(
            true, 
            data ?? [], 
            0x9000, // Success status word
            Maybe<SmartCardError>.None);
    }
}