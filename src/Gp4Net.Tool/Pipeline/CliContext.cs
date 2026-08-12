using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Services;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Tool.Pipeline;

/// <summary>
/// Pure functional implementation of CLI execution context.
/// Eliminates imperative keyset resolution and provides pure pipeline functions.
/// </summary>
[PublicAPI]
public class CliContext : ICliExecutionContext
{
    private readonly ILogger<CliContext> _logger;
    private readonly KeysetResolution _keysetResolver;
    private readonly CardSessionConnections? _serviceFactory;
    private readonly ReaderSelectionOperations? _readerResolutionService;

    public IDisplay Display { get; }
    public ICardSessionCommands CardService { get; }
    public KeysetResolution KeysetResolution => _keysetResolver;

    /// <summary>
    /// Pure function for establishing secure channels from user requests.
    /// Eliminates imperative command-level keyset resolution.
    /// </summary>
    public Func<
        SecureChannelRequest,
        CancellationToken,
        Task<Result<SecureChannelExecutionContext, SmartCardError>>
    > EstablishSecureChannelAsync { get; }

    public CliContext(
        IDisplay display,
        ICardSessionCommands cardService,
        KeysetResolution keysetResolver,
        ILogger<CliContext> logger,
        CardSessionConnections? serviceFactory = null,
        ReaderSelectionOperations? readerResolutionService = null
    )
    {
        // Pure assignment - dependency injection framework ensures non-null services
        Display = display;
        CardService = cardService;
        _keysetResolver = keysetResolver;
        _logger = logger;
        _serviceFactory = serviceFactory;
        _readerResolutionService = readerResolutionService;

        // Create pure function for secure channel establishment
        EstablishSecureChannelAsync = (request, cancellationToken) =>
            SecureChannelOperations.EstablishFromRequestAsync(
                request,
                CardService,
                _keysetResolver,
                cancellationToken
            );
    }

    /// <summary>
    /// Ensures a card connection is established using pure functional patterns.
    /// </summary>
    public async Task<Result<ICliExecutionContext, SmartCardError>> RequireCardConnection(
        Maybe<string> readerName = default
    )
    {
        if (_serviceFactory is null || _readerResolutionService is null)
        {
            var connectedResult = await CardService.IsConnectedAsync();
            return connectedResult.Bind(connected =>
                connected
                    ? Result.Success<ICliExecutionContext, SmartCardError>(this)
                    : Result.Failure<ICliExecutionContext, SmartCardError>(
                        SmartCardError.CommunicationError(
                            "No card connection established and no connection factory is available."
                        )
                    )
            );
        }

        var connectedServiceResult = await ReaderResolutionHelper.ResolveAndConnectAsync(
            readerName,
            _serviceFactory,
            _readerResolutionService,
            Display
        );

        return connectedServiceResult.Map(connectedService =>
            (ICliExecutionContext)
                new CliContext(
                    Display,
                    connectedService,
                    _keysetResolver,
                    _logger,
                    _serviceFactory,
                    _readerResolutionService
                )
        );
    }

    /// <summary>
    /// Pure secure channel requirement - handled by EstablishSecureChannelAsync function.
    /// </summary>
    public Task<Result<ICliExecutionContext, SmartCardError>> RequireSecureChannel(
        byte securityLevel = 1,
        Maybe<string> keyset = default
    )
    {
        var request = new SecureChannelRequest(
            KeysetName: keyset,
            ExplicitKeys: Maybe<ExplicitKeys>.None,
            KeysetParameters: Maybe<System.Collections.Generic.Dictionary<string, string>>.None,
            SecurityLevel: (SecurityLevel)securityLevel,
            ExplicitKeyVersion: Maybe<byte>.None
        );

        return RequireSecureChannel(request);
    }

    public async Task<Result<ICliExecutionContext, SmartCardError>> RequireSecureChannel(
        SecureChannelRequest request,
        CancellationToken cancellationToken = default
    )
    {
        var secureChannelResult = await EstablishSecureChannelAsync(request, cancellationToken);
        return secureChannelResult
            .Bind(secureContext =>
                CardService.WithContextValue(
                    "SecureChannelSession",
                    secureContext.SecureChannelState
                )
            )
            .Map(securedService =>
                (ICliExecutionContext)
                    new CliContext(
                        Display,
                        securedService,
                        _keysetResolver,
                        _logger,
                        _serviceFactory,
                        _readerResolutionService
                    )
            );
    }

    /// <summary>
    /// Executes command logic using pure functional error handling.
    /// </summary>
    public async Task<int> ExecuteAsync(Func<ICliExecutionContext, Task<int>> commandLogic)
    {
        return await ExecuteCommandWithErrorHandling(() => commandLogic(this));
    }

    /// <summary>
    /// Executes synchronous command logic using pure functional error handling.
    /// </summary>
    public async Task<int> ExecuteAsync(Func<ICliExecutionContext, int> commandLogic)
    {
        return await ExecuteCommandWithErrorHandling(() => Task.FromResult(commandLogic(this)));
    }

    /// <summary>
    /// Pure functional error handling for command execution.
    /// </summary>
    private async Task<int> ExecuteCommandWithErrorHandling(Func<Task<int>> commandExecution)
    {
        try
        {
            return await commandExecution();
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Command execution failed: {ErrorMessage}", ex.Message);
            Display.Exception(ex);
            return 1;
        }
    }
}
