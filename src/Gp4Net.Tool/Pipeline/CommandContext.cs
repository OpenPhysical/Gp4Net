using System;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Domain.Keys;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using log4net;

namespace Gp4Net.Tool.Pipeline;

/// <summary>
/// Default implementation of ICliExecutionContext.
/// </summary>
[PublicAPI]
public class CommandContext : ICliExecutionContext
{
    private static readonly ILog Logger = LogManager.GetLogger(typeof(CommandContext));

    public IDisplayService Display { get; }
    public ICardService CardService { get; }
    private readonly IDomainServiceFactory _domainServiceFactory;
    private Gp4Net.Services.IGlobalPlatformService? _cachedGlobalPlatformService;
    public IKeysetResolver KeysetResolver { get; }

    public CommandContext(
        IDisplayService display,
        ICardService cardService,
        IDomainServiceFactory domainServiceFactory,
        IKeysetResolver keysetResolver
    )
    {
        Display = display ?? throw new ArgumentNullException(nameof(display));
        CardService = cardService ?? throw new ArgumentNullException(nameof(cardService));
        _domainServiceFactory =
            domainServiceFactory
            ?? throw new ArgumentNullException(nameof(domainServiceFactory));
        KeysetResolver =
            keysetResolver ?? throw new ArgumentNullException(nameof(keysetResolver));
    }

    public Gp4Net.Services.IGlobalPlatformService GetGlobalPlatformService()
    {
        // Create on demand with proper context, cache for reuse within same command
        return _cachedGlobalPlatformService ??= _domainServiceFactory
            .CreateGlobalPlatformService(CardService);
    }

    public Task<ICliExecutionContext> RequireCardConnection(Maybe<string> readerName = default)
    {
        if (CardService.IsConnected)
        {
            return Task.FromResult<ICliExecutionContext>(this);
        }

        try
        {
            // Auto-detect reader if not specified
            string actualReaderName;
            if (!readerName.HasValue || string.IsNullOrEmpty(readerName.Value) || readerName.Value == "auto")
            {
                var readers = CardService.GetReaders();
                if (readers.Count == 0)
                {
                    Display.Error("No card readers found");
                    throw new InvalidOperationException("No card readers available");
                }

                actualReaderName = readers[0];
                Display.Info($"Auto-detected reader: {actualReaderName}");
            }
            else
            {
                actualReaderName = readerName.Value;
            }

            if (!CardService.Connect(actualReaderName))
            {
                Display.Error($"Failed to connect to reader: {actualReaderName}");
                throw new InvalidOperationException(
                    $"Failed to connect to reader: {actualReaderName}"
                );
            }

            Display.Success($"Connected to reader: {actualReaderName}");
            return Task.FromResult<ICliExecutionContext>(this);
        }
        catch (Exception ex)
        {
            Logger.Error($"Card connection failed: {ex.Message}", ex);
            Display.Error($"Reader connection error: {ex.Message}");
            throw;
        }
    }

    public Task<ICliExecutionContext> RequireSecureChannel(
        byte securityLevel = 1,
        Maybe<string> keyset = default
    )
    {
        if (CardService.IsSecureChannelEstablished)
        {
            return Task.FromResult<ICliExecutionContext>(this);
        }

        try
        {
            Display.Info("Establishing secure channel...");

            // Use default keyset if not specified
            var keyBytes = GpTestKeys.StandardTestKey;

            if (CardService.EstablishSecureChannel(keyBytes, securityLevel))
            {
                Display.Success("✓ Secure channel established");
                return Task.FromResult<ICliExecutionContext>(this);
            }
            else
            {
                Display.Error("✗ Failed to establish secure channel");
                throw new InvalidOperationException("Failed to establish secure channel");
            }
        }
        catch (Exception ex)
        {
            Logger.Error($"Secure channel establishment failed: {ex.Message}", ex);
            Display.Error($"Secure channel error: {ex.Message}");
            throw;
        }
    }

    public async Task<int> ExecuteAsync(Func<ICliExecutionContext, Task<int>> commandLogic)
    {
        try
        {
            return await commandLogic(this);
        }
        catch (Exception ex)
        {
            Logger.Error($"Command execution failed: {ex.Message}", ex);
            Display.Exception(ex);
            return 1;
        }
    }

    public async Task<int> ExecuteAsync(Func<ICliExecutionContext, int> commandLogic)
    {
        try
        {
            return await Task.FromResult(commandLogic(this));
        }
        catch (Exception ex)
        {
            Logger.Error($"Command execution failed: {ex.Message}", ex);
            Display.Exception(ex);
            return 1;
        }
    }
}