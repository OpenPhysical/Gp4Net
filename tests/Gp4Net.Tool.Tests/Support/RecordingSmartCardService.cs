using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Pipeline;
using Gp4Net.Services;
using Gp4Net.Transport;
using WSCT.ISO7816;

namespace Gp4Net.Tool.Tests.Support;

internal sealed class RecordingSmartCardService : ISmartCardService
{
    private readonly ISmartCardService inner;

    public List<(byte[] Command, Result<CommandResponse, SmartCardError> Result)> Records { get; } =
        new();

    public RecordingSmartCardService(ISmartCardService inner)
    {
        this.inner = inner;
    }

    public IPipelineContext Context => inner.Context;

    public void Dispose() => inner.Dispose();

    public Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        CommandAPDU command,
        CancellationToken cancellationToken = default
    ) => inner.ExecuteCommandAsync(command, cancellationToken);

    public Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        CommandAPDU command,
        bool useSecureChannel,
        CancellationToken cancellationToken = default
    ) => inner.ExecuteCommandAsync(command, useSecureChannel, cancellationToken);

    public Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        CommandAPDU command,
        CommandOptions options,
        CancellationToken cancellationToken = default
    ) => inner.ExecuteCommandAsync(command, options, cancellationToken);

    public Result<ISmartCardService, SmartCardError> WithContext(IPipelineContext context) =>
        inner.WithContext(context);

    public Result<ISmartCardService, SmartCardError> WithContextValue<T>(string key, T value) =>
        inner.WithContextValue(key, value);

    public Task<Result<bool, SmartCardError>> IsConnectedAsync(
        CancellationToken cancellationToken = default
    ) => inner.IsConnectedAsync(cancellationToken);

    public Task<Result<byte[], SmartCardError>> GetAtrAsync(
        CancellationToken cancellationToken = default
    ) => inner.GetAtrAsync(cancellationToken);

    public Task<Result<string[], SmartCardError>> GetReadersAsync(
        CancellationToken cancellationToken = default
    ) => inner.GetReadersAsync(cancellationToken);

    public Task<Result<bool, SmartCardError>> IsSecureChannelEstablishedAsync(
        CancellationToken cancellationToken = default
    ) => inner.IsSecureChannelEstablishedAsync(cancellationToken);

    public async Task<Result<CommandResponse, SmartCardError>> SendCommandAsync(
        byte[] command,
        CancellationToken cancellationToken = default
    )
    {
        var result = await inner.SendCommandAsync(command, cancellationToken);
        Records.Add((command, result));
        return result;
    }

    public Task<
        Result<CardTransportCapabilities, SmartCardError>
    > GetCardTransportCapabilitiesAsync(CancellationToken cancellationToken = default) =>
        inner.GetCardTransportCapabilitiesAsync(cancellationToken);
}
