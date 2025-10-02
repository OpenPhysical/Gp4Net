using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Transport;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Pipeline;

/// <summary>
/// Functional command processing infrastructure using pure function composition.
/// </summary>
public static class CommandProcessing
{
    /// <summary>
    /// Represents a pure function that processes a command given an environment.
    /// </summary>
    public delegate Task<Result<CommandResult, SmartCardError>> CommandProcessor(
        IApduCommand command,
        CommandEnvironment environment,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Immutable environment containing all dependencies for command processing.
    /// </summary>
    public record CommandEnvironment(
        ICardChannel Channel,
        IApduTransport Transport,
        Maybe<SecureChannelState> SecureChannel,
        ILogger Logger,
        CommandOptions Options
    )
    {
        /// <summary>
        /// Creates a new environment with updated secure channel state.
        /// </summary>
        public CommandEnvironment WithSecureChannel(SecureChannelState secureChannel)
        {
            return this with { SecureChannel = Maybe<SecureChannelState>.From(secureChannel) };
        }

        /// <summary>
        /// Creates a new environment without secure channel.
        /// </summary>
        public CommandEnvironment WithoutSecureChannel()
        {
            return this with { SecureChannel = Maybe<SecureChannelState>.None };
        }
    }

    /// <summary>
    /// Represents the result of command processing.
    /// </summary>
    public record CommandResult(
        byte[] Data,
        StatusWord StatusWord,
        CommandEnvironment UpdatedEnvironment,
        CommandMetadata Metadata = null
    )
    {
        /// <summary>
        /// Creates a successful result.
        /// </summary>
        public static CommandResult Success(
            byte[] data,
            StatusWord statusWord,
            CommandEnvironment environment,
            CommandMetadata metadata = null
        )
        {
            return new(data, statusWord, environment, metadata ?? new CommandMetadata());
        }

        /// <summary>
        /// Checks if the command was successful.
        /// </summary>
        public bool IsSuccess =>
            StatusWord == Constants.Constants.StatusWords.Legacy.Success
            || (StatusWord & 0xFF00) == 0x6100;
    }

    /// <summary>
    /// Metadata collected during command processing.
    /// </summary>
    public record CommandMetadata(
        Maybe<TimeSpan> ExecutionTime = default,
        Maybe<byte[]> TransmittedBytes = default,
        Maybe<byte[]> ReceivedBytes = default,
        bool SecureChannelWrapped = false,
        bool SecureChannelUnwrapped = false,
        bool ResponseLogged = false,
        Maybe<InitializeUpdateResponse> InitializeUpdateResponse = default
    );
}
