using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Pipeline;
using Gp4Net.Services;
using Gp4Net.Tool.Services.CardCommunication;
using Gp4Net.Tool.Services.CardCommunication.Wsct;
using Gp4Net.Transport;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using WSCT.ISO7816;
using WSCT.Wrapper;
using static Gp4Net.Pipeline.CommandProcessing;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Service for creating CardSessionCommands instances connected to physical smart cards via WSCT.
/// </summary>
[PublicAPI]
public static class PhysicalCardConnections
{
    /// <summary>
    /// Creates a CardSessionCommands connected to a physical smart card.
    /// </summary>
    /// <param name="readerName">The name of the physical card reader</param>
    /// <param name="logger">Logger for the CardSessionCommands</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>A CardSessionCommands connected to the physical card, or an error</returns>
    public static Task<Result<ICardSessionCommands, SmartCardError>> CreateServiceAsync(
        string readerName,
        ILogger<CardSessionCommands> logger,
        CancellationToken cancellationToken = default
    )
    {
        if (ReaderEnumeration.IsVirtualReader(readerName))
        {
            // Delegate to virtual card connection service when a virtual reader is requested.
            return VirtualCardConnections.CreateServiceAsync(readerName, logger, cancellationToken);
        }

        // Use unified ReaderEnumeration instead of duplicating logic
        return ReaderEnumeration
            .EnumeratePhysicalReadersAsync(cancellationToken)
            .Bind(readers => Task.FromResult(SelectReader(readerName, readers)))
            .Bind(selectedReader => ConnectToCard(selectedReader, logger));
    }

    /// <summary>
    /// Selects a specific reader from the available readers.
    /// </summary>
    private static Result<string, SmartCardError> SelectReader(
        string requestedReader,
        string[] availableReaders
    )
    {
        // Delegate to unified ReaderEnumeration for consistent matching logic
        return ReaderEnumeration.SelectReaderByPartialMatch(requestedReader, availableReaders);
    }

    /// <summary>
    /// Connects to a physical smart card and creates a CardSessionCommands.
    /// </summary>
    private static Task<Result<ICardSessionCommands, SmartCardError>> ConnectToCard(
        string readerName,
        ILogger<CardSessionCommands> logger
    )
    {
        // Create WSCT context and channel using existing wrappers
        var context = new WsctCardContextWrapper();
        var establishError = context.Establish();

        if (establishError != ErrorCode.Success)
        {
            context.Dispose();
            return Task.FromResult(
                Result.Failure<ICardSessionCommands, SmartCardError>(
                    SmartCardError.CommunicationError(
                        $"Failed to establish context: {establishError}"
                    )
                )
            );
        }

        var channel = context.CreateCardChannel(readerName);
        var connectError = channel.Connect(
            WSCT.Wrapper.ShareMode.Shared,
            WSCT.Wrapper.Protocol.Any
        );

        if (connectError != ErrorCode.Success)
        {
            channel.Dispose();
            context.Dispose();
            return Task.FromResult(
                Result.Failure<ICardSessionCommands, SmartCardError>(
                    SmartCardError.CommunicationError($"Failed to connect to card: {connectError}")
                )
            );
        }

        // Create adapters for Gp4Net transport layer
        var cardChannel = new WsctCardChannel(channel);
        var transport = new WsctApduTransport(channel);

        // Create command environment
        var environment = new CommandEnvironment(
            Channel: cardChannel,
            Transport: transport,
            SecureChannel: Maybe<SecureChannelState>.None,
            Options: new CommandOptions(
                UseSecureChannel: false,
                CaptureMetrics: true,
                EnableLogging: true, // Enable logging infrastructure
                VerboseLogging: false, // CLI will override if --verbose
                DebugLogging: false // CLI will override if --debug
            ),
            Logger: logger
        );

        // Create command processor pipeline
        var processor = CommandProcessors.CreatePipeline(
            enableLogging: true,
            enableSecureChannel: true
        );

        // Return the CardSessionCommands
        return Task.FromResult(
            Result.Success<ICardSessionCommands, SmartCardError>(
                new CardSessionCommands(environment, processor, logger)
            )
        );
    }
}

/// <summary>
/// Adapter that implements ICardChannel for WSCT CardChannel.
/// </summary>
internal class WsctCardChannel : ICardChannel
{
    private readonly WsctCardChannelWrapper _channel;

    public TransportProtocol Protocol => TransportProtocol.T1; // Most modern cards use T=1
    public bool IsOpen => true; // Assume open if channel exists

    public WsctCardChannel(WsctCardChannelWrapper channel)
    {
        _channel = channel;
    }

    public Task<Result<ChannelExchange, SmartCardError>> TransmitAsync(
        byte[] command,
        CancellationToken cancellationToken = default
    )
    {
        var cmd = new CommandAPDU(command);
        var rsp = new ResponseAPDU();

        var errorCode = _channel.Transmit(cmd, rsp);

        if (errorCode != ErrorCode.Success)
        {
            return Task.FromResult(
                Result.Failure<ChannelExchange, SmartCardError>(
                    SmartCardError.CommunicationError($"Transmission failed: {errorCode}")
                )
            );
        }

        // Build complete response with UDR (data) and status words
        var udr = Maybe<byte[]>.From(rsp.Udr);
        var dataLength = udr.Map(d => d.Length).GetValueOrDefault(0);
        var responseBytes = new byte[dataLength + 2];

        udr.Execute(data => Array.Copy(data, 0, responseBytes, 0, data.Length));
        responseBytes[dataLength] = rsp.Sw1;
        responseBytes[dataLength + 1] = rsp.Sw2;

        return Task.FromResult(
            Result.Success<ChannelExchange, SmartCardError>(
                new ChannelExchange(responseBytes, this)
            )
        );
    }
}

/// <summary>
/// Adapter that implements IApduTransport for WSCT.
/// </summary>
internal class WsctApduTransport : IApduTransport
{
    private readonly WsctCardChannelWrapper _channel;

    public TransportProtocol Protocol => TransportProtocol.T1;
    public int MaxCommandDataLength => 255; // Standard short APDU
    public int MaxResponseDataLength => 256;
    public bool SupportsExtendedLength => false;

    public WsctApduTransport(WsctCardChannelWrapper channel)
    {
        _channel = channel;
    }

    public async Task<Result<TransportExchange, SmartCardError>> TransmitAsync(
        IApduCommand command,
        ICardChannel channel,
        CancellationToken cancellationToken = default
    )
    {
        var commandResult = ApduBuilder.BuildApdu(Maybe<IApduCommand>.From(command));
        if (commandResult.IsFailure)
        {
            return Result.Failure<TransportExchange, SmartCardError>(commandResult.Error);
        }

        var result = await channel.TransmitAsync(commandResult.Value, cancellationToken);
        return result.Map(exchange =>
        {
            byte[] bytes = exchange.Response;
            if (bytes.Length < 2)
            {
                return new TransportExchange(new ApduResponse([], 0x6F00), exchange.Channel);
            }

            ushort statusWord = (ushort)(bytes[^2] << 8 | bytes[^1]);
            byte[] data = bytes.Length > 2 ? bytes[..^2] : [];
            return new TransportExchange(new ApduResponse(data, statusWord), exchange.Channel);
        });
    }
}
