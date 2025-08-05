using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Pipeline;
using Gp4Net.Transport;

namespace Gp4Net.Tests.Infrastructure;

/// <summary>
/// Test implementation of command pipeline for functional testing.
/// </summary>
public class TestCommandPipeline : ICommandPipeline
{
    public async Task<Result<CommandResponse, SmartCardError>> ExecuteAsync(
        IApduCommand command,
        IPipelineContext context,
        CancellationToken cancellationToken = default)
    {
        // Basic test implementation - just execute the command
        var transportMaybe = context.Get<IApduTransport>("ApduTransport");
        var channelMaybe = context.Get<ICardChannel>("CardChannel");
            
        if (transportMaybe.HasNoValue || channelMaybe.HasNoValue)
        {
            return Result.Failure<CommandResponse, SmartCardError>(
                SmartCardError.CommunicationError("Transport or channel not available in context"));
        }
            
        var transport = transportMaybe.Value;
        var channel = channelMaybe.Value;
            
        var response = await transport.TransmitAsync(command, channel, cancellationToken);
            
        return Result.Success<CommandResponse, SmartCardError>(
            new CommandResponse(response.Data, response.StatusWord, context));
    }

    public async Task<Result<CommandResponse, SmartCardError>> ExecuteAsync(
        CommandRequest request,
        CancellationToken cancellationToken = default)
    {
        // Basic test implementation - execute the command from the request
        var transportMaybe = request.Context.Get<IApduTransport>("ApduTransport");
        var channelMaybe = request.Context.Get<ICardChannel>("CardChannel");
            
        if (transportMaybe.HasNoValue || channelMaybe.HasNoValue)
        {
            return Result.Failure<CommandResponse, SmartCardError>(
                SmartCardError.CommunicationError("Transport or channel not available in context"));
        }
            
        var transport = transportMaybe.Value;
        var channel = channelMaybe.Value;
            
        var response = await transport.TransmitAsync(request.Command, channel, cancellationToken);
            
        return Result.Success<CommandResponse, SmartCardError>(
            new CommandResponse(response.Data, response.StatusWord, request.Context));
    }
}

/// <summary>
/// Test implementation of APDU transport factory.
/// </summary>
public class TestApduTransportFactory : IApduTransportFactory
{
    public IApduTransport CreateTransport(TransportProtocol protocol, bool supportsExtendedLength = true)
    {
        return new TestApduTransport(protocol, supportsExtendedLength);
    }
}

/// <summary>
/// Test implementation of APDU transport.
/// </summary>
public class TestApduTransport : IApduTransport
{
    public TransportProtocol Protocol { get; }
    public int MaxCommandDataLength { get; }
    public int MaxResponseDataLength { get; }
    public bool SupportsExtendedLength { get; }

    public TestApduTransport(TransportProtocol protocol = TransportProtocol.T0, bool supportsExtendedLength = true)
    {
        Protocol = protocol;
        SupportsExtendedLength = supportsExtendedLength;
        MaxCommandDataLength = supportsExtendedLength ? 65535 : 255;
        MaxResponseDataLength = supportsExtendedLength ? 65536 : 256;
    }

    public async Task<ApduResponse> TransmitAsync(
        IApduCommand command,
        ICardChannel channel,
        CancellationToken cancellationToken = default)
    {
        // Build APDU bytes manually from IApduCommand properties
        var commandBytes = new List<byte> { command.Cla, command.Ins, command.P1, command.P2 };
            
        if (command.Data is { Length: > 0 })
        {
            commandBytes.Add((byte)command.Data.Length);
            commandBytes.AddRange(command.Data);
        }
            
        if (command.ExpectedResponseLength.HasValue)
        {
            commandBytes.Add((byte)(command.ExpectedResponseLength.Value == 0 ? 256 : command.ExpectedResponseLength.Value));
        }
            
        // Delegate to the channel's transmit method
        var response = await channel.TransmitAsync(commandBytes.ToArray(), cancellationToken);
        var statusWord = (ushort)((response[response.Length - 2] << 8) | response[response.Length - 1]);
        var data = response.Length > 2 ? response[..^2] : [];
        return new ApduResponse(data, statusWord);
    }
}

/// <summary>
/// Test implementation of secure channel manager.
/// </summary>
public class TestSecureChannelManager : ISecureChannelManager
{
    public async Task<Result<Gp4Net.Domain.Security.SecureChannelState, SmartCardError>> EstablishAsync(
        ICardChannel channel,
        IApduTransport transport,
        IKeySet keySet,
        SecurityLevel securityLevel,
        CancellationToken cancellationToken = default)
    {
        // For testing, return failure
        // Real tests should use actual secure channel implementations or trace-based cards
        await Task.CompletedTask;
        return Result.Failure<Gp4Net.Domain.Security.SecureChannelState, SmartCardError>(
            SmartCardError.UnexpectedError("TestSecureChannelManager is a stub for interface compatibility only"));
    }

    public async Task<Result<Gp4Net.Domain.Security.SecureChannelState, SmartCardError>> EstablishAutoDetectAsync(
        ICardChannel channel,
        IApduTransport transport,
        IKeySet keySet,
        SecurityLevel securityLevel,
        CancellationToken cancellationToken = default)
    {
        // For testing, return failure
        // Real tests should use actual secure channel implementations or trace-based cards
        await Task.CompletedTask;
        return Result.Failure<Gp4Net.Domain.Security.SecureChannelState, SmartCardError>(
            SmartCardError.UnexpectedError("TestSecureChannelManager is a stub for interface compatibility only"));
    }
}

/// <summary>
/// Test implementation of card channel adapter for trace-based services.
/// </summary>
public class TestCardServiceChannelAdapter : ICardChannel
{
    private readonly Gp4Net.Tool.Services.ICardService _cardService;

    public TestCardServiceChannelAdapter(Gp4Net.Tool.Services.ICardService cardService)
    {
        _cardService = cardService ?? throw new ArgumentNullException(nameof(cardService));
    }

    public TransportProtocol Protocol => TransportProtocol.T0;
    public bool IsOpen => _cardService.IsSecureChannelEstablished;

    public Task<byte[]> TransmitAsync(byte[] command, CancellationToken cancellationToken = default)
    {
        var response = _cardService.SendCommand(command);
        var responseBytes = new byte[response.Data.Length + 2];
        response.Data.CopyTo(responseBytes, 0);
        responseBytes[responseBytes.Length - 2] = (byte)(response.StatusWord >> 8); // SW1
        responseBytes[responseBytes.Length - 1] = (byte)(response.StatusWord & 0xFF); // SW2
        return Task.FromResult(responseBytes);
    }
}