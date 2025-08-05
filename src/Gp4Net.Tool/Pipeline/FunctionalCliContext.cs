using System;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Domain.Keys;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Pipeline;

/// <summary>
/// Functional implementation of CLI execution context using Result patterns.
/// </summary>
[PublicAPI]
public class FunctionalCliContext : ICliExecutionContext
{
    public IDisplayService Display { get; }
    public ICardService CardService { get; }
    private readonly IDomainServiceFactory _domainServiceFactory;
    private Gp4Net.Services.IGlobalPlatformService? _cachedGlobalPlatformService;
    public IKeysetResolver KeysetResolver { get; }

    public FunctionalCliContext(
        IDisplayService display,
        ICardService cardService,
        IDomainServiceFactory domainServiceFactory,
        IKeysetResolver keysetResolver)
    {
        Display = display ?? throw new ArgumentNullException(nameof(display));
        CardService = cardService ?? throw new ArgumentNullException(nameof(cardService));
        _domainServiceFactory = domainServiceFactory ?? throw new ArgumentNullException(nameof(domainServiceFactory));
        KeysetResolver = keysetResolver ?? throw new ArgumentNullException(nameof(keysetResolver));
    }

    /// <summary>
    /// Retrieves the instance of the <c>IGlobalPlatformService</c> associated with the context.
    /// If the service is already initialized, the cached instance is returned. Otherwise, it
    /// initializes the service using the provided <c>IDomainServiceFactory</c> and <c>ICardService</c>.
    /// </summary>
    /// <returns>The initialized <c>IGlobalPlatformService</c> instance.</returns>
    public Gp4Net.Services.IGlobalPlatformService GetGlobalPlatformService()
    {
        return _cachedGlobalPlatformService ??= _domainServiceFactory
            .CreateGlobalPlatformService(CardService);
    }

    /// <summary>
    /// Ensures that a card connection is established using the <c>ICardService</c>.
    /// If already connected, the current instance of <c>ICliExecutionContext</c> is returned.
    /// If not, attempts to connect to the card using the specified reader name.
    /// </summary>
    /// <param name="readerName">The optional name of the card reader to use for the connection.</param>
    /// <returns>The current <c>ICliExecutionContext</c> if the connection is successful, or throws an exception on failure.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the connection attempt fails with an error message.</exception>
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
                Display.Error($"Failed to connect: {error}");
                throw new InvalidOperationException(error);
            });
    }

    public async Task<ICliExecutionContext> RequireSecureChannel(
        byte securityLevel = 1,
        Maybe<string> keyset = default)
    {
        var result = await EstablishSecureChannelAsync(securityLevel, keyset);
        return result.Match(
            onSuccess: _ => this,
            onFailure: error =>
            {
                Display.Error($"Failed to establish secure channel: {error}");
                throw new InvalidOperationException(error);
            });
    }

    public async Task<int> ExecuteAsync(Func<ICliExecutionContext, Task<int>> commandLogic)
    {
        try
        {
            return await commandLogic(this);
        }
        catch (Exception ex)
        {
            Display.Exception(ex);
            return 1;
        }
    }

    public Task<int> ExecuteAsync(Func<ICliExecutionContext, int> commandLogic)
    {
        try
        {
            return Task.FromResult(commandLogic(this));
        }
        catch (Exception ex)
        {
            Display.Exception(ex);
            return Task.FromResult(1);
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
                            return string.Empty;
                        }
                        return readers[0];
                    });

                if (string.IsNullOrEmpty(actualReaderName))
                {
                    return Result.Failure<bool, string>("No card readers found");
                }

                Display.Info($"Connecting to card in reader: {actualReaderName}");

                if (CardService.Connect(actualReaderName))
                {
                    Display.Success("✓ Connected to card");
                    return Result.Success<bool, string>(true);
                }
                else
                {
                    return Result.Failure<bool, string>("Failed to connect to card");
                }
            }
            catch (Exception ex)
            {
                return Result.Failure<bool, string>($"Connection error: {ex.Message}");
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
                else
                {
                    return Result.Failure<bool, string>("Failed to establish secure channel");
                }
            }
            catch (Exception ex)
            {
                return Result.Failure<bool, string>($"Secure channel error: {ex.Message}");
            }
        });
    }
}
