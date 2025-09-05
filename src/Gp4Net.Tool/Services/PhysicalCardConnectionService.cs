using System;
using System.Collections.Immutable;
using System.Linq;
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
/// Service for creating SmartCardService instances connected to physical smart cards via WSCT.
/// </summary>
[PublicAPI]
public static class PhysicalCardConnectionService
{
    /// <summary>
    /// Creates a SmartCardService connected to a physical smart card.
    /// </summary>
    /// <param name="readerName">The name of the physical card reader</param>
    /// <param name="logger">Logger for the SmartCardService</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>A SmartCardService connected to the physical card, or an error</returns>
    public static Task<Result<ISmartCardService, SmartCardError>> CreateServiceAsync(
        string readerName,
        ILogger<SmartCardService> logger,
        CancellationToken cancellationToken = default
    )
    {
        return EnumerateReadersAsync()
            .Bind(readers => SelectReader(readerName, readers))
            .Bind(selectedReader => ConnectToCard(selectedReader, logger));
    }

    /// <summary>
    /// Enumerates available physical card readers using WSCT.
    /// </summary>
    private static Task<Result<string[], SmartCardError>> EnumerateReadersAsync()
    {
        using var context = new WsctCardContextWrapper();
        var errorCode = context.Establish();
        
        if (errorCode != ErrorCode.Success)
        {
            return Task.FromResult(
                Result.Failure<string[], SmartCardError>(
                    SmartCardError.CommunicationError($"Failed to establish context: {errorCode}")
                )
            );
        }
        
        errorCode = context.ListReaders(null);
        if (errorCode != ErrorCode.Success)
        {
            return Task.FromResult(
                Result.Success<string[], SmartCardError>(Array.Empty<string>())
            );
        }
        
        return Task.FromResult(
            Result.Success<string[], SmartCardError>(context.Readers.ToArray())
        );
    }

    /// <summary>
    /// Selects a specific reader from the available readers.
    /// </summary>
    private static Result<string, SmartCardError> SelectReader(string requestedReader, string[] availableReaders)
    {
        if (availableReaders.Length == 0)
        {
            return Result.Failure<string, SmartCardError>(
                SmartCardError.CommunicationError("No card readers found on the system")
            );
        }

        var readerList = ImmutableList.Create(availableReaders);

        // Try exact match first
        var exactMatches = readerList
            .Where(r => string.Equals(r, requestedReader, StringComparison.OrdinalIgnoreCase))
            .ToImmutableList();
        
        if (exactMatches.Any())
        {
            return Result.Success<string, SmartCardError>(exactMatches.First());
        }

        // Try partial match
        var partialMatches = readerList
            .Where(r => r.Contains(requestedReader, StringComparison.OrdinalIgnoreCase))
            .ToImmutableList();
        
        if (partialMatches.Any())
        {
            return Result.Success<string, SmartCardError>(partialMatches.First());
        }

        // No match found
        var availableList = string.Join(", ", readerList.Select(r => $"'{r}'"));
        return Result.Failure<string, SmartCardError>(
            SmartCardError.InvalidArgument(
                $"Reader '{requestedReader}' not found. Available readers: {availableList}"
            )
        );
    }

    /// <summary>
    /// Connects to a physical smart card and creates a SmartCardService.
    /// </summary>
    private static Task<Result<ISmartCardService, SmartCardError>> ConnectToCard(
        string readerName,
        ILogger<SmartCardService> logger
    )
    {
        // Create WSCT context and channel using existing wrappers
        var context = new WsctCardContextWrapper();
        var establishError = context.Establish();
        
        if (establishError != ErrorCode.Success)
        {
            context.Dispose();
            return Task.FromResult(
                Result.Failure<ISmartCardService, SmartCardError>(
                    SmartCardError.CommunicationError($"Failed to establish context: {establishError}")
                )
            );
        }
        
        var channel = context.CreateCardChannel(readerName);
        var connectError = channel.Connect(WSCT.Wrapper.ShareMode.Shared, WSCT.Wrapper.Protocol.Any);
        
        if (connectError != ErrorCode.Success)
        {
            channel.Dispose();
            context.Dispose();
            return Task.FromResult(
                Result.Failure<ISmartCardService, SmartCardError>(
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
            Options: CommandOptions.Default,
            Logger: logger
        );

        // Create command processor pipeline
        var processor = Gp4Net.Pipeline.CommandProcessors.CreatePipeline(
            enableLogging: true,
            enableSecureChannel: true
        );

        // Return the SmartCardService
        return Task.FromResult(
            Result.Success<ISmartCardService, SmartCardError>(
                new SmartCardService(environment, processor, logger)
            )
        );
    }
}

/// <summary>
/// Adapter that implements ICardChannel for WSCT CardChannel.
/// </summary>
internal class WsctCardChannel : Gp4Net.Transport.ICardChannel
{
    private readonly ICardChannelWrapper _channel;

    public TransportProtocol Protocol => TransportProtocol.T1; // Most modern cards use T=1
    public bool IsOpen => true; // Assume open if channel exists

    public WsctCardChannel(ICardChannelWrapper channel)
    {
        _channel = channel;
    }

    public Task<byte[]> TransmitAsync(byte[] command, CancellationToken cancellationToken = default)
    {
        var cmd = new WSCT.ISO7816.CommandAPDU(command);
        var rsp = new WSCT.ISO7816.ResponseAPDU();
        
        var errorCode = _channel.Transmit(cmd, rsp);
        
        if (errorCode != ErrorCode.Success)
        {
            return Task.FromResult(Array.Empty<byte>());
        }

        // Build complete response with UDR (data) and status words
        var udr = Maybe<byte[]>.From(rsp.Udr);
        var dataLength = udr.Map(d => d.Length).GetValueOrDefault(0);
        var responseBytes = new byte[dataLength + 2];
        
        udr.Execute(data => Array.Copy(data, 0, responseBytes, 0, data.Length));
        responseBytes[dataLength] = rsp.Sw1;
        responseBytes[dataLength + 1] = rsp.Sw2;
        
        return Task.FromResult(responseBytes);
    }
}

/// <summary>
/// Adapter that implements IApduTransport for WSCT.
/// </summary>
internal class WsctApduTransport : Gp4Net.Transport.IApduTransport
{
    private readonly ICardChannelWrapper _channel;

    public TransportProtocol Protocol => TransportProtocol.T1;
    public int MaxCommandDataLength => 255; // Standard short APDU
    public int MaxResponseDataLength => 256;
    public bool SupportsExtendedLength => false;

    public WsctApduTransport(ICardChannelWrapper channel)
    {
        _channel = channel;
    }

    public Task<Result<Gp4Net.Transport.ApduResponse, SmartCardError>> TransmitAsync(
        IApduCommand command,
        Gp4Net.Transport.ICardChannel channel,
        CancellationToken cancellationToken = default
    )
    {
        var result = ApduBuilder.BuildApdu(Maybe<IApduCommand>.From(command))
            .Bind(commandBytes =>
            {
                var cmd = new WSCT.ISO7816.CommandAPDU(commandBytes);
                var rsp = new WSCT.ISO7816.ResponseAPDU();
                
                var errorCode = _channel.Transmit(cmd, rsp);
                
                if (errorCode != ErrorCode.Success)
                {
                    return Result.Failure<Gp4Net.Transport.ApduResponse, SmartCardError>(
                        SmartCardError.CommunicationError($"Transmission failed: {errorCode}")
                    );
                }

                // Create ApduResponse from WSCT ResponseAPDU
                var udr = Maybe<byte[]>.From(rsp.Udr);
                var data = udr.GetValueOrDefault(Array.Empty<byte>());
                var statusWord = (ushort)((rsp.Sw1 << 8) | rsp.Sw2);
                
                var response = new Gp4Net.Transport.ApduResponse(
                    data: data,
                    statusWord: statusWord
                );
                return Result.Success<Gp4Net.Transport.ApduResponse, SmartCardError>(response);
            });
        
        return Task.FromResult(result);
    }
}