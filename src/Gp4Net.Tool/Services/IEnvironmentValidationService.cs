using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Services
{
    /// <summary>
    /// Service for validating environment safety before executing operations with real cards.
    /// Prevents accidental use of test keys against production cards and vice versa.
    /// </summary>
    [PublicAPI]
    public interface IEnvironmentValidationService
    {
        /// <summary>
        /// Validates that the keyset is appropriate for the detected card environment.
        /// Prevents using test keys on production cards or production keys on test cards.
        /// </summary>
        /// <param name="keySet">The keyset to validate.</param>
        /// <param name="channel">The card channel to analyze.</param>
        /// <param name="transport">The transport layer.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A result indicating whether the environment is safe or contains validation errors.</returns>
        Task<Result<EnvironmentValidationResult, SmartCardError>> ValidateEnvironmentAsync(
            IKeySet keySet,
            ICardChannel channel,
            IApduTransport transport,
            CancellationToken cancellationToken = default
        );

        /// <summary>
        /// Checks if a keyset contains only well-known test keys.
        /// </summary>
        /// <param name="keySet">The keyset to check.</param>
        /// <returns>True if the keyset contains only test keys, false otherwise.</returns>
        bool IsTestKeySet(IKeySet keySet);

        /// <summary>
        /// Checks if a card appears to be a production card based on various indicators.
        /// </summary>
        /// <param name="channel">The card channel.</param>
        /// <param name="transport">The transport layer.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A result containing the card environment assessment.</returns>
        Task<Result<CardEnvironment, SmartCardError>> DetectCardEnvironmentAsync(
            ICardChannel channel,
            IApduTransport transport,
            CancellationToken cancellationToken = default
        );
    }

    /// <summary>
    /// Represents the result of environment validation.
    /// </summary>
    [PublicAPI]
    public class EnvironmentValidationResult
    {
        /// <summary>
        /// Gets whether the environment combination is safe.
        /// </summary>
        public bool IsSafe { get; }

        /// <summary>
        /// Gets the detected card environment.
        /// </summary>
        public CardEnvironment CardEnvironment { get; }

        /// <summary>
        /// Gets whether the keyset appears to be for testing.
        /// </summary>
        public bool IsTestKeySet { get; }

        /// <summary>
        /// Gets warnings about the environment combination.
        /// </summary>
        public string[] Warnings { get; }

        /// <summary>
        /// Gets the validation message.
        /// </summary>
        public string Message { get; }

        /// <summary>
        /// Initializes a new instance of EnvironmentValidationResult.
        /// </summary>
        public EnvironmentValidationResult(
            bool isSafe,
            CardEnvironment cardEnvironment,
            bool isTestKeySet,
            string message,
            params string[] warnings
        )
        {
            IsSafe = isSafe;
            CardEnvironment = cardEnvironment;
            IsTestKeySet = isTestKeySet;
            Message = message;
            Warnings = warnings ?? [];
        }
    }

    /// <summary>
    /// Represents the detected card environment type.
    /// </summary>
    [PublicAPI]
    public enum CardEnvironment
    {
        /// <summary>
        /// Environment could not be determined.
        /// </summary>
        Unknown,

        /// <summary>
        /// Appears to be a test/development card.
        /// </summary>
        Test,

        /// <summary>
        /// Appears to be a production card.
        /// </summary>
        Production,

        /// <summary>
        /// Virtual/emulated card for testing.
        /// </summary>
        Virtual
    }
}