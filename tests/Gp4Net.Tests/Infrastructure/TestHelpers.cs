using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Pipeline;
using Gp4Net.Services;
using Gp4Net.Transport;
using Microsoft.Extensions.Logging.Abstractions;
using static Gp4Net.Pipeline.CommandProcessing;
using SecureChannelService = Gp4Net.Domain.Security.SecureChannelService;

namespace Gp4Net.Tests.Infrastructure;

/// <summary>
/// Test helpers for functional command processing.
/// </summary>
public static class TestCommandProcessing
{
    /// <summary>
    /// Creates a test command processor that directly executes commands.
    /// </summary>
    public static CommandProcessor CreateTestProcessor()
    {
        return async (command, environment, cancellationToken) =>
        {
            try
            {
                // Basic test implementation - just execute the command
                ApduResponse? response = await environment.Transport.TransmitAsync(
                    command,
                    environment.Channel,
                    cancellationToken
                );

                // Build APDU bytes for metadata
                byte[]? commandBytes = ApduBuilder.BuildApdu(command);
                byte[] responseBytes = new byte[response.Data.Length + 2];
                Array.Copy(response.Data, 0, responseBytes, 0, response.Data.Length);
                responseBytes[^2] = (byte)(response.StatusWord >> 8);
                responseBytes[^1] = (byte)(response.StatusWord & 0xFF);

                return Result.Success<CommandResult, SmartCardError>(
                    new CommandResult(
                        response.Data,
                        response.StatusWord,
                        environment,
                        new CommandMetadata(
                            ExecutionTime: TimeSpan.Zero,
                            TransmittedBytes: commandBytes,
                            ReceivedBytes: responseBytes
                        )
                    )
                );
            }
            catch (Exception ex)
            {
                return Result.Failure<CommandResult, SmartCardError>(
                    SmartCardError.CommunicationError(
                        "Test execution failed",
                        Maybe<Exception>.From(ex)
                    )
                );
            }
        };
    }

    /// <summary>
    /// Creates a test command environment.
    /// </summary>
    public static CommandEnvironment CreateTestEnvironment(
        ICardChannel channel,
        IApduTransport transport
    )
    {
        // Create secure channel service for testing
        SecureChannelService secureChannelService = new SecureChannelService();

        return new CommandEnvironment(
            channel,
            transport,
            Maybe<Gp4Net.Domain.Security.SecureChannelState>.None,
            secureChannelService,
            NullLogger.Instance
        );
    }
}

/// <summary>
/// Test implementation of APDU transport factory.
/// </summary>
public class TestApduTransportFactory : IApduTransportFactory
{
    public IApduTransport CreateTransport(
        TransportProtocol protocol,
        bool supportsExtendedLength = true
    )
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

    public TestApduTransport(
        TransportProtocol protocol = TransportProtocol.T0,
        bool supportsExtendedLength = true
    )
    {
        Protocol = protocol;
        SupportsExtendedLength = supportsExtendedLength;
        MaxCommandDataLength = supportsExtendedLength ? 65535 : 255;
        MaxResponseDataLength = supportsExtendedLength ? 65536 : 256;
    }

    public async Task<ApduResponse> TransmitAsync(
        IApduCommand command,
        ICardChannel channel,
        CancellationToken cancellationToken = default
    )
    {
        // Build APDU bytes manually from IApduCommand properties
        List<byte> commandBytes = [command.Cla, command.Ins, command.P1, command.P2];

        if (command.Data is { Length: > 0 })
        {
            commandBytes.Add((byte)command.Data.Length);
            commandBytes.AddRange(command.Data);
        }

        if (command.ExpectedResponseLength.HasValue)
        {
            commandBytes.Add(
                (byte)(
                    command.ExpectedResponseLength.Value == 0
                        ? 256
                        : command.ExpectedResponseLength.Value
                )
            );
        }

        // Delegate to the channel's transmit method
        byte[]? response = await channel.TransmitAsync([.. commandBytes], cancellationToken);
        ushort statusWord = (ushort)(response[^2] << 8 | response[^1]);
        byte[] data = response.Length > 2 ? response[..^2] : [];
        return new ApduResponse(data, statusWord);
    }
}

/// <summary>
/// Test implementation of secure channel manager.
/// </summary>
public class TestSecureChannelManager : ISecureChannelManager
{
    public async Task<Result<SecureChannelState, SmartCardError>> EstablishSecureChannelAsync(
        IKeySet keySet,
        SecurityLevel securityLevel,
        CancellationToken cancellationToken = default
    )
    {
        // For testing, return failure
        // Real tests should use actual secure channel implementations or trace-based cards
        await Task.CompletedTask;
        return Result.Failure<SecureChannelState, SmartCardError>(
            SmartCardError.UnexpectedError(
                "TestSecureChannelManager is a stub for interface compatibility only"
            )
        );
    }

    public async Task<Result<SecureChannelState, SmartCardError>> EstablishSecureChannelAsync(
        string keysetName,
        SecurityLevel securityLevel,
        byte keyVersion = 0x01,
        CancellationToken cancellationToken = default
    )
    {
        // For testing, return failure
        // Real tests should use actual secure channel implementations or trace-based cards
        await Task.CompletedTask;
        return Result.Failure<SecureChannelState, SmartCardError>(
            SmartCardError.UnexpectedError(
                "TestSecureChannelManager is a stub for interface compatibility only"
            )
        );
    }

    public Maybe<SecureChannelState> GetCurrentChannel()
    {
        return Maybe<SecureChannelState>.None;
    }

    public UnitResult<SmartCardError> CloseChannel()
    {
        return UnitResult.Success<SmartCardError>();
    }
}

/// <summary>
/// Test implementation of card channel adapter for trace-based services.
/// Preserves all original functionality while adapting to ISmartCardService.
/// </summary>
public class TestCardServiceChannelAdapter : ICardChannel
{
    private readonly Maybe<ISmartCardService> _smartCardService;

    public TestCardServiceChannelAdapter(ISmartCardService smartCardService)
    {
        _smartCardService = Maybe<ISmartCardService>.From(smartCardService);
    }

    public TransportProtocol Protocol => TransportProtocol.T0;

    public bool IsOpen =>
        _smartCardService
            .Bind(service => service.IsSecureChannelEstablishedAsync().Result.ToMaybe())
            .GetValueOrDefault(false);

    public async Task<byte[]> TransmitAsync(
        byte[] command,
        CancellationToken cancellationToken = default
    )
    {
        return await _smartCardService
            .ToResult("Smart card service not available")
            .Bind(async service =>
            {
                Result<CommandResponse, SmartCardError> commandResult =
                    await service.SendCommandAsync(command, cancellationToken);
                return commandResult.Match(
                    response => Result.Success(ConstructResponseBytes(response)),
                    error => Result.Failure<byte[]>($"Command failed: {error.Message}")
                );
            })
            .Match(
                success => Task.FromResult(success),
                error => Task.FromResult(new byte[] { 0x6F, 0x00 })
            ); // Generic error response
    }

    private static byte[] ConstructResponseBytes(CommandResponse response)
    {
        byte[] responseBytes = new byte[response.Data.Length + 2];
        response.Data.CopyTo(responseBytes, 0);
        responseBytes[^2] = (byte)(response.StatusWord >> 8); // SW1
        responseBytes[^1] = (byte)(response.StatusWord & 0xFF); // SW2
        return responseBytes;
    }
}
