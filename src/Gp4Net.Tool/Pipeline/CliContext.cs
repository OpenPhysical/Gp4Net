using System;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Domain.Keys;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Tool.Pipeline;

/// <summary>
/// Implementation of CLI execution context using functional patterns.
/// </summary>
[PublicAPI]
public class CliContext : ICliExecutionContext
{
    private readonly ILogger<CliContext> _logger;
    private Gp4Net.Services.IGlobalPlatformService _cachedGlobalPlatformService;
    
    public IDisplayService Display { get; }
    public ICardService CardService { get; }
    private readonly IDomainServiceFactory _domainServiceFactory;
    public IKeysetResolver KeysetResolver { get; }

    public CliContext(
        IDisplayService display,
        ICardService cardService,
        IDomainServiceFactory domainServiceFactory,
        IKeysetResolver keysetResolver,
        ILogger<CliContext> logger = null)
    {
        Display = display ?? throw new ArgumentNullException(nameof(display));
        CardService = cardService ?? throw new ArgumentNullException(nameof(cardService));
        _domainServiceFactory = domainServiceFactory ?? throw new ArgumentNullException(nameof(domainServiceFactory));
        KeysetResolver = keysetResolver ?? throw new ArgumentNullException(nameof(keysetResolver));
        _logger = logger;
    }

    /// <summary>
    /// Gets or creates the GlobalPlatform service instance.
    /// </summary>
    public Gp4Net.Services.IGlobalPlatformService GetGlobalPlatformService()
    {
        return _cachedGlobalPlatformService ??= _domainServiceFactory
            .CreateGlobalPlatformService(CardService);
    }

    /// <summary>
    /// Ensures a card connection is established.
    /// </summary>
    public async Task<ICliExecutionContext> RequireCardConnection(Maybe<string> readerName = default)
    {
        if (CardService.IsConnected)
        {
            return this;
        }

        var result = await ConnectToCardAsync(readerName);
        return result.Match(
            onSuccess: _ => this,
            onFailure: error =>
            {
                _logger?.LogError("Card connection failed: {Error}", error);
                Display.Error($"Failed to connect: {error}");
                throw new InvalidOperationException(error);
            });
    }

    /// <summary>
    /// Ensures a secure channel is established.
    /// </summary>
    public async Task<ICliExecutionContext> RequireSecureChannel(
        byte securityLevel = 1,
        Maybe<string> keyset = default)
    {
        if (CardService.IsSecureChannelEstablished)
        {
            return this;
        }

        var result = await EstablishSecureChannelAsync(securityLevel, keyset);
        return result.Match(
            onSuccess: _ => this,
            onFailure: error =>
            {
                _logger?.LogError("Secure channel establishment failed: {Error}", error);
                Display.Error($"Failed to establish secure channel: {error}");
                throw new InvalidOperationException(error);
            });
    }

    /// <summary>
    /// Executes command logic with error handling.
    /// </summary>
    public async Task<int> ExecuteAsync(Func<ICliExecutionContext, Task<int>> commandLogic)
    {
        try
        {
            return await commandLogic(this);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Command execution failed");
            Display.Exception(ex);
            return 1;
        }
    }

    /// <summary>
    /// Executes synchronous command logic with error handling.
    /// </summary>
    public async Task<int> ExecuteAsync(Func<ICliExecutionContext, int> commandLogic)
    {
        try
        {
            return await Task.FromResult(commandLogic(this));
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Command execution failed");
            Display.Exception(ex);
            return 1;
        }
    }

    private async Task<Result<bool, string>> ConnectToCardAsync(Maybe<string> readerName)
    {
        return await Task.Run(() =>
        {
            try
            {
                // Auto-detect reader if not specified
                var actualReaderName = readerName
                    .Where(static name => !string.IsNullOrEmpty(name) && name != "auto")
                    .GetValueOrDefault(() =>
                    {
                        var readers = CardService.GetReaders();
                        if (readers.Count == 0)
                        {
                            Display.Error("No card readers found");
                            return string.Empty;
                        }
                        var autoDetected = readers[0];
                        Display.Info($"Auto-detected reader: {autoDetected}");
                        return autoDetected;
                    });

                if (string.IsNullOrEmpty(actualReaderName))
                {
                    return Result.Failure<bool, string>("No card readers available");
                }

                if (!CardService.Connect(actualReaderName))
                {
                    return Result.Failure<bool, string>($"Failed to connect to reader: {actualReaderName}");
                }

                Display.Success($"Connected to reader: {actualReaderName}");
                return Result.Success<bool, string>(true);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Connection error");
                return Result.Failure<bool, string>($"Reader connection error: {ex.Message}");
            }
        });
    }

    private async Task<Result<bool, string>> EstablishSecureChannelAsync(
        byte securityLevel,
        Maybe<string> keyset)
    {
        return await Task.Run(() =>
        {
            try
            {
                Display.Info("Establishing secure channel...");

                // Use default keyset if not specified
                var keyBytes = GpTestKeys.StandardTestKey;

                if (CardService.EstablishSecureChannel(keyBytes, securityLevel))
                {
                    Display.Success("✓ Secure channel established");
                    return Result.Success<bool, string>(true);
                }
                
                return Result.Failure<bool, string>("Failed to establish secure channel");
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Secure channel error");
                return Result.Failure<bool, string>($"Secure channel error: {ex.Message}");
            }
        });
    }
}