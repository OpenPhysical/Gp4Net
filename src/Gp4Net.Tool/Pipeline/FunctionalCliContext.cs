using System;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Pipeline
{
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

        public Gp4Net.Services.IGlobalPlatformService GetGlobalPlatformService()
        {
            return _cachedGlobalPlatformService ??= _domainServiceFactory
                .CreateGlobalPlatformService(CardService);
        }

        public async Task<ICliExecutionContext> RequireCardConnection(string? readerName = null)
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
            string? keyset = null)
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

        public async Task<int> ExecuteAsync(Func<ICliExecutionContext, int> commandLogic)
        {
            try
            {
                return commandLogic(this);
            }
            catch (Exception ex)
            {
                Display.Exception(ex);
                return 1;
            }
        }

        private async Task<Result<bool, string>> ConnectToCardAsync(string? readerName)
        {
            return await Task.Run(() =>
            {
                try
                {
                    // Auto-detect reader if not specified
                    if (string.IsNullOrEmpty(readerName) || readerName == "auto")
                    {
                        var readers = CardService.GetReaders();
                        if (readers.Count == 0)
                        {
                            return Result.Failure<bool, string>("No card readers found");
                        }
                        readerName = readers[0];
                    }

                    Display.Info($"Connecting to card in reader: {readerName}");

                    if (CardService.Connect(readerName))
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
            string? keyset)
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
}