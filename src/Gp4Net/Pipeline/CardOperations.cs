using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Transport;
using WSCT.ISO7816;
using static Gp4Net.Pipeline.CommandProcessing;

namespace Gp4Net.Pipeline;

/// <summary>
/// The immutable state required to exchange commands with a card.
/// </summary>
public sealed record CardSession(
    CommandEnvironment Environment,
    CommandProcessor Process,
    Func<CancellationToken, Task<UnitResult<SmartCardError>>> Close
)
{
    /// <summary>
    /// Creates a session whose underlying connection does not require explicit cleanup.
    /// </summary>
    public static CardSession Create(CommandEnvironment environment, CommandProcessor process) =>
        new(environment, process, _ => Task.FromResult(UnitResult.Success<SmartCardError>()));

    /// <summary>
    /// Returns a session with an established secure channel.
    /// </summary>
    public CardSession WithSecureChannel(SecureChannelState secureChannel) =>
        this with
        {
            Environment = Environment.WithSecureChannel(secureChannel)
        };

    /// <summary>
    /// Returns a session without secure messaging state.
    /// </summary>
    public CardSession WithoutSecureChannel() =>
        this with
        {
            Environment = Environment.WithoutSecureChannel()
        };
}

/// <summary>
/// A value paired with the card session produced while computing it.
/// </summary>
public readonly record struct CardStep<T>(T Value, CardSession Session);

/// <summary>
/// An asynchronous card computation that explicitly consumes and returns session state.
/// </summary>
public delegate Task<Result<CardStep<T>, SmartCardError>> CardOperation<T>(
    CardSession session,
    CancellationToken cancellationToken
);

/// <summary>
/// Functional composition for card operations.
/// </summary>
public static class CardOperations
{
    /// <summary>
    /// Runs an operation from the supplied immutable session.
    /// </summary>
    public static Task<Result<CardStep<T>, SmartCardError>> Run<T>(
        CardOperation<T> operation,
        CardSession session,
        CancellationToken cancellationToken = default
    ) => operation(session, cancellationToken);

    /// <summary>
    /// Creates an operation that produces a value without changing session state.
    /// </summary>
    public static CardOperation<T> Pure<T>(T value) =>
        (session, _) =>
            Task.FromResult(
                Result.Success<CardStep<T>, SmartCardError>(new CardStep<T>(value, session))
            );

    /// <summary>
    /// Maps the value of an operation while preserving its resulting session.
    /// </summary>
    public static CardOperation<TResult> Map<T, TResult>(
        this CardOperation<T> operation,
        Func<T, TResult> map
    ) =>
        async (session, cancellationToken) =>
            (await operation(session, cancellationToken)).Map(step => new CardStep<TResult>(
                map(step.Value),
                step.Session
            ));

    /// <summary>
    /// Composes operations and passes the updated session to the next operation.
    /// </summary>
    public static CardOperation<TResult> Bind<T, TResult>(
        this CardOperation<T> operation,
        Func<T, CardOperation<TResult>> bind
    ) =>
        async (session, cancellationToken) =>
        {
            var first = await operation(session, cancellationToken);
            return first.IsFailure
                ? Result.Failure<CardStep<TResult>, SmartCardError>(first.Error)
                : await bind(first.Value.Value)(first.Value.Session, cancellationToken);
        };

    /// <summary>
    /// Runs the next operation after the first, discarding the first value.
    /// </summary>
    public static CardOperation<TResult> Then<T, TResult>(
        this CardOperation<T> operation,
        CardOperation<TResult> next
    ) => operation.Bind(_ => next);

    /// <summary>
    /// Observes a successful value without changing it or the session.
    /// </summary>
    public static CardOperation<T> Tap<T>(this CardOperation<T> operation, Action<T> observe) =>
        operation.Map(value =>
        {
            observe(value);
            return value;
        });

    /// <summary>
    /// Executes a parsed command through the configured command pipeline.
    /// </summary>
    public static CardOperation<CommandResponse> Execute(
        CommandAPDU command,
        CommandOptions options
    ) =>
        async (session, cancellationToken) =>
        {
            var environment = session.Environment with { Options = options };
            var result = await session.Process(
                command.AsApduCommand(),
                environment,
                cancellationToken
            );

            return result.Map(commandResult =>
            {
                var updatedSession = session with
                {
                    Environment = commandResult.UpdatedEnvironment,
                };
                var response = new CommandResponse(
                    commandResult.Data,
                    commandResult.StatusWord,
                    BuildContext(commandResult.UpdatedEnvironment),
                    BuildMetadata(commandResult.Metadata)
                );
                return new CardStep<CommandResponse>(response, updatedSession);
            });
        };

    /// <summary>
    /// Executes a command without secure messaging.
    /// </summary>
    public static CardOperation<CommandResponse> Execute(CommandAPDU command) =>
        Execute(command, new CommandOptions(UseSecureChannel: false));

    /// <summary>
    /// Parses and executes raw APDU bytes without secure messaging.
    /// </summary>
    public static CardOperation<CommandResponse> Send(byte[] command) =>
        FromResult(ParseApduCommand(command)).Bind(Execute);

    /// <summary>
    /// Lifts a synchronous result into a card operation.
    /// </summary>
    public static CardOperation<T> FromResult<T>(Result<T, SmartCardError> result) =>
        (session, _) => Task.FromResult(result.Map(value => new CardStep<T>(value, session)));

    /// <summary>
    /// Closes the side-effecting connection owned by the session.
    /// </summary>
    public static async Task<UnitResult<SmartCardError>> Close(
        CardSession session,
        CancellationToken cancellationToken = default
    ) => await session.Close(cancellationToken);

    private static Result<CommandAPDU, SmartCardError> ParseApduCommand(byte[] command) =>
        ValidateApduFormat(command).Map(() => new CommandAPDU(command));

    private static UnitResult<SmartCardError> ValidateApduFormat(byte[] command)
    {
        if (command.Length < 4)
        {
            return SmartCardError.InvalidArgument("Invalid APDU command length");
        }

        if (command.Length <= 5)
        {
            return UnitResult.Success<SmartCardError>();
        }

        byte lc = command[4];
        return lc == 0x00 ? ValidateExtendedApduFormat(command) : ValidateShortApduFormat(command);
    }

    private static UnitResult<SmartCardError> ValidateShortApduFormat(byte[] command)
    {
        int lc = command[4];
        return command.Length == 5 + lc || command.Length == 5 + lc + 1
            ? UnitResult.Success<SmartCardError>()
            : SmartCardError.InvalidArgument("Invalid short APDU command format");
    }

    private static UnitResult<SmartCardError> ValidateExtendedApduFormat(byte[] command)
    {
        if (command.Length == 7)
        {
            return UnitResult.Success<SmartCardError>();
        }

        if (command.Length < 7)
        {
            return SmartCardError.InvalidArgument("Invalid extended APDU command format");
        }

        int lc = command[5] << 8 | command[6];
        if (lc == 0)
        {
            return SmartCardError.InvalidArgument("Invalid extended APDU command data length");
        }

        return command.Length == 7 + lc || command.Length == 7 + lc + 2
            ? UnitResult.Success<SmartCardError>()
            : SmartCardError.InvalidArgument("Invalid extended APDU command format");
    }

    private static ImmutablePipelineContext BuildContext(CommandEnvironment environment)
    {
        var context = ImmutablePipelineContext
            .Empty.With("CardChannel", environment.Channel)
            .With("ApduTransport", environment.Transport);

        return environment.SecureChannel.Match(
            secureChannel => context.With("SecureChannelSession", secureChannel),
            () => context
        );
    }

    private static IReadOnlyDictionary<string, object> BuildMetadata(CommandMetadata metadata) =>
        new Dictionary<string, object>
        {
            [ResponseMetadata.EXECUTION_TIME] = metadata.ExecutionTime.GetValueOrDefault(
                TimeSpan.Zero
            ),
            [ResponseMetadata.TRANSMITTED_BYTES] = metadata.TransmittedBytes.GetValueOrDefault([]),
            [ResponseMetadata.RECEIVED_BYTES] = metadata.ReceivedBytes.GetValueOrDefault([]),
            [ResponseMetadata.SECURE_CHANNEL_WRAPPED] = metadata.SecureChannelWrapped,
        };
}
