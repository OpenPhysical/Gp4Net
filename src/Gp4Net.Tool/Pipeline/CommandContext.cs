using System;
using System.Threading.Tasks;
using Gp4Net.Domain.Keys;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using log4net;

namespace Gp4Net.Tool.Pipeline
{
    /// <summary>
    /// Default implementation of ICommandContext.
    /// </summary>
    [PublicAPI]
    public class CommandContext : ICommandContext
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

        public Task<ICommandContext> RequireCardConnection(string? readerName = null)
        {
            if (CardService.IsConnected)
            {
                return Task.FromResult<ICommandContext>(this);
            }

            try
            {
                // Auto-detect reader if not specified
                if (string.IsNullOrEmpty(readerName) || readerName == "auto")
                {
                    var readers = CardService.GetReaders();
                    if (readers.Count == 0)
                    {
                        Display.Error("No card readers found");
                        throw new InvalidOperationException("No card readers available");
                    }

                    readerName = readers[0];
                    Display.Info($"Auto-detected reader: {readerName}");
                }

                if (!CardService.Connect(readerName))
                {
                    Display.Error($"Failed to connect to reader: {readerName}");
                    throw new InvalidOperationException(
                        $"Failed to connect to reader: {readerName}"
                    );
                }

                Display.Success($"Connected to reader: {readerName}");
                return Task.FromResult<ICommandContext>(this);
            }
            catch (Exception ex)
            {
                Logger.Error($"Card connection failed: {ex.Message}", ex);
                Display.Error($"Reader connection error: {ex.Message}");
                throw;
            }
        }

        public Task<ICommandContext> RequireSecureChannel(
            byte securityLevel = 1,
            string? keyset = null
        )
        {
            if (CardService.IsSecureChannelEstablished)
            {
                return Task.FromResult<ICommandContext>(this);
            }

            try
            {
                Display.Info("Establishing secure channel...");

                // Use default keyset if not specified
                var keyBytes = GpTestKeys.StandardTestKey;

                if (CardService.EstablishSecureChannel(keyBytes, securityLevel))
                {
                    Display.Success("✓ Secure channel established");
                    return Task.FromResult<ICommandContext>(this);
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

        public async Task<int> ExecuteAsync(Func<ICommandContext, Task<int>> commandLogic)
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

        public async Task<int> ExecuteAsync(Func<ICommandContext, int> commandLogic)
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
}
