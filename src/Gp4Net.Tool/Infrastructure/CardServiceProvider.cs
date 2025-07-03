using System;
using Gp4Net.Tool.Services;

namespace Gp4Net.Tool.Infrastructure
{
    /// <summary>
    /// Static service provider for CardService access in TypeConverters.
    /// This is a workaround for TypeConverters not supporting dependency injection.
    /// </summary>
    public static class CardServiceProvider
    {
        private static ICardService? _cardService;

        /// <summary>
        /// Sets the card service instance.
        /// </summary>
        /// <param name="cardService">The card service instance.</param>
        public static void SetCardService(ICardService cardService)
        {
            _cardService = cardService ?? throw new ArgumentNullException(nameof(cardService));
        }

        /// <summary>
        /// Gets the current card service instance.
        /// </summary>
        /// <returns>The card service instance.</returns>
        /// <exception cref="InvalidOperationException">Thrown when no card service has been set.</exception>
        public static ICardService GetCardService()
        {
            return _cardService
                ?? throw new InvalidOperationException(
                    "CardService has not been initialized. Call SetCardService first."
                );
        }
    }
}
