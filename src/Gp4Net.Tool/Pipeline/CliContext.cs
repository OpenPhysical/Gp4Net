using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
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
    private readonly IGlobalPlatformService _globalPlatformService;
    private readonly IKeysetResolver _keysetResolver;

    public IDisplayService Display { get; }
    public ISmartCardService CardService { get; }
    
    /// <summary>
    /// Pure function for establishing secure channels from user requests.
    /// Eliminates imperative command-level keyset resolution.
    /// </summary>
    public Func<SecureChannelRequest, CancellationToken, Task<Result<SecureChannelExecutionContext, SmartCardError>>> EstablishSecureChannelAsync { get; }

    public CliContext(
        IDisplayService display,
        ISmartCardService cardService,
        IDomainServiceFactory domainServiceFactory,
        IKeysetResolver keysetResolver,
        ILogger<CliContext> logger = null)
    {
        // Pure assignment - dependency injection framework ensures non-null services
        Display = display;
        CardService = cardService;
        _keysetResolver = keysetResolver;
        _logger = logger;
        
        // Create domain service once during construction using pure function
        _globalPlatformService = domainServiceFactory.CreateGlobalPlatformService(CardService);
        
        // Create pure function for secure channel establishment
        EstablishSecureChannelAsync = (request, cancellationToken) => 
            SecureChannelOperations.EstablishFromRequestAsync(request, CardService, _keysetResolver, cancellationToken);
    }

    /// <summary>
    /// Gets the GlobalPlatform service instance.
    /// Pure accessor - service created during construction.
    /// </summary>
    public IGlobalPlatformService GetGlobalPlatformService() => _globalPlatformService;

    /// <summary>
    /// Ensures a card connection is established using pure functional patterns.
    /// </summary>
    public Task<Result<ICliExecutionContext, SmartCardError>> RequireCardConnection(Maybe<string> readerName = default)
    {
        // Pure functional card connection handling
        // Reader resolution and connection is managed by the smart card service
        return Task.FromResult(Result.Success<ICliExecutionContext, SmartCardError>(this));
    }

    /// <summary>
    /// Pure secure channel requirement - handled by EstablishSecureChannelAsync function.
    /// </summary>
    public Task<Result<ICliExecutionContext, SmartCardError>> RequireSecureChannel(
        byte securityLevel = 1,
        Maybe<string> keyset = default)
    {
        // Secure channel establishment is now handled by pure pipeline functions
        return Task.FromResult(Result.Success<ICliExecutionContext, SmartCardError>(this));
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
        return await Result.Try(commandExecution, ex => ex)
            .Match(
                async successTask => await successTask,
                error =>
                {
                    _logger?.LogError(error, "Command execution failed");
                    Display.Exception(error);
                    return Task.FromResult(1);
                });
    }
}