using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Trace;
using Gp4Net.Core;
using static Gp4Net.Constants.Constants;

namespace Gp4Net.CardEmulator.Cards;

/// <summary>
/// Functional virtual card that replays APDU responses from a trace.
/// Simple, clean implementation focusing on core functionality.
/// </summary>
public sealed record TraceReplayCard : IVirtualCard
{
    private readonly ApduTrace _trace;
    private readonly ImmutableList<ApduExchange> _executedExchanges;
    private readonly int _nextExchangeIndex;

    /// <summary>
    /// Gets whether the card is selected.
    /// </summary>
    public bool IsSelected { get; }

    /// <summary>
    /// Gets whether a secure channel is established.
    /// </summary>
    public bool IsSecureChannelEstablished { get; }

    /// <summary>
    /// Initializes a new TraceReplayCard with trace and state.
    /// </summary>
    private TraceReplayCard(
        ApduTrace trace,
        bool isSelected,
        bool isSecureChannelEstablished,
        ImmutableList<ApduExchange> executedExchanges,
        int nextExchangeIndex
    )
    {
        _trace = trace;
        IsSelected = isSelected;
        IsSecureChannelEstablished = isSecureChannelEstablished;
        _executedExchanges = executedExchanges;
        _nextExchangeIndex = nextExchangeIndex;
    }

    /// <summary>
    /// Creates a new TraceReplayCard from an APDU trace.
    /// </summary>
    /// <param name="trace">The APDU trace to replay.</param>
    /// <returns>A new TraceReplayCard instance or an error.</returns>
    public static Result<TraceReplayCard, SmartCardError> Create(ApduTrace trace)
    {
        return Maybe
            .From(trace)
            .ToResult(SmartCardError.InvalidArgument("Trace cannot be null"))
            .Map(t => new TraceReplayCard(
                t,
                isSelected: false,
                isSecureChannelEstablished: false,
                executedExchanges: ImmutableList<ApduExchange>.Empty,
                nextExchangeIndex: 0
            ));
    }

    /// <summary>
    /// Gets the Answer to Reset (ATR) of the virtual card.
    /// </summary>
    /// <returns>ATR bytes from trace or default JavaCard ATR.</returns>
    public byte[] GetAtr()
    {
        return _trace.Atr.GetValueOrDefault(
            Convert.FromHexString("3B7D94000080318065B08311AC83009000")
        );
    }

    /// <summary>
    /// Processes an APDU command functionally, returning response and updated card state.
    /// </summary>
    /// <param name="command">The APDU command bytes.</param>
    /// <returns>The APDU response and updated card instance, or an error.</returns>
    public Result<(ApduResponse Response, IVirtualCard UpdatedCard), SmartCardError> ProcessCommand(
        byte[] command
    )
    {
        return ValidateCommand(command)
            .Bind(cmd =>
                FindResponseForCommand(cmd)
                    .Map(response =>
                        CreateUpdatedCard(cmd, response)
                            .Map(updatedCard => (response, (IVirtualCard)updatedCard))
                    )
            )
            .Bind(result => result);
    }

    /// <summary>
    /// Resets the virtual card to its initial state.
    /// </summary>
    /// <returns>A new card instance in reset state.</returns>
    public Result<IVirtualCard, SmartCardError> Reset()
    {
        TraceReplayCard resetCard =
            new(
                _trace,
                isSelected: false,
                isSecureChannelEstablished: false,
                executedExchanges: ImmutableList<ApduExchange>.Empty,
                nextExchangeIndex: 0
            );

        return Result.Success<IVirtualCard, SmartCardError>(resetCard);
    }

    /// <summary>
    /// Validates the incoming APDU command.
    /// </summary>
    /// <param name="command">The command to validate.</param>
    /// <returns>The validated command or an error.</returns>
    private static Result<byte[], SmartCardError> ValidateCommand(byte[] command)
    {
        return Maybe
            .From(command)
            .ToResult(SmartCardError.InvalidArgument("Command cannot be null"))
            .Ensure(
                cmd => cmd.Length >= 4,
                SmartCardError.WrongLength("Command must be at least 4 bytes")
            );
    }

    /// <summary>
    /// Finds the appropriate response for a command using simple sequential replay.
    /// </summary>
    /// <param name="command">The command to find a response for.</param>
    /// <returns>The matching response or default error response.</returns>
    private Result<ApduResponse, SmartCardError> FindResponseForCommand(byte[] command)
    {
        // Try sequential replay first - most common case
        var sequentialResponse = TrySequentialReplay(command);
        if (sequentialResponse.IsSuccessful)
            return Result.Success<ApduResponse, SmartCardError>(sequentialResponse);

        // Try exact command match
        var exactMatchResponse = TryExactMatch(command);
        if (exactMatchResponse.IsSuccessful)
            return Result.Success<ApduResponse, SmartCardError>(exactMatchResponse);

        // Try pattern match by instruction
        var patternResponse = TryPatternMatch(command);
        return Result.Success<ApduResponse, SmartCardError>(patternResponse);
    }

    /// <summary>
    /// Attempts sequential replay if the next expected command matches.
    /// </summary>
    /// <param name="command">The command to match.</param>
    /// <returns>The response if sequential match found, otherwise error response.</returns>
    private ApduResponse TrySequentialReplay(byte[] command)
    {
        if (_nextExchangeIndex >= _trace.Exchanges.Count)
            return ApduResponse.Error(StatusWords.InstructionErrors.InstructionNotSupported);

        var nextExchange = _trace.Exchanges[_nextExchangeIndex];

        return CommandHeaderMatches(command, nextExchange.Command)
            ? nextExchange.Response.Match(response => response, () => ApduResponse.Error(0x6D00))
            : ApduResponse.Error(0x6D00);
    }

    /// <summary>
    /// Attempts to find exact command match in trace.
    /// </summary>
    /// <param name="command">The command to match.</param>
    /// <returns>The response if exact match found, otherwise error response.</returns>
    private ApduResponse TryExactMatch(byte[] command)
    {
        string commandKey = BitConverter.ToString(command);

        var matchingExchanges = _trace
            .Exchanges.Where(ex => BitConverter.ToString(ex.Command) == commandKey)
            .ToArray();

        if (matchingExchanges.Length == 0)
            return ApduResponse.Error(StatusWords.InstructionErrors.InstructionNotSupported);

        return matchingExchanges[0]
            .Response.Match(response => response, () => ApduResponse.Error(0x6D00));
    }

    /// <summary>
    /// Attempts to find response by instruction pattern matching.
    /// </summary>
    /// <param name="command">The command to match.</param>
    /// <returns>The response if pattern match found, otherwise error response.</returns>
    private ApduResponse TryPatternMatch(byte[] command)
    {
        byte ins = command[1];

        var matchingExchanges = _trace
            .Exchanges.Where(ex => ex.Command.Length >= 2 && ex.Command[1] == ins)
            .ToArray();

        if (matchingExchanges.Length == 0)
            return ApduResponse.Error(StatusWords.InstructionErrors.InstructionNotSupported);

        return matchingExchanges[0]
            .Response.Match(response => response, () => ApduResponse.Error(0x6D00));
    }

    /// <summary>
    /// Checks if command headers match (CLA, INS, P1, P2).
    /// </summary>
    /// <param name="actual">The actual command.</param>
    /// <param name="expected">The expected command.</param>
    /// <returns>True if headers match, allowing for secure messaging bits in CLA.</returns>
    private static bool CommandHeaderMatches(byte[] actual, byte[] expected)
    {
        if (actual.Length < 4 || expected.Length < 4)
            return false;

        // Allow CLA secure messaging bits to differ (mask with 0xFC)
        bool claMatches = (actual[0] & 0xFC) == (expected[0] & 0xFC);
        bool insMatches = actual[1] == expected[1];
        bool p1Matches = actual[2] == expected[2];
        bool p2Matches = actual[3] == expected[3];

        return claMatches && insMatches && p1Matches && p2Matches;
    }

    /// <summary>
    /// Creates an updated card instance with new state based on the processed command.
    /// </summary>
    /// <param name="command">The processed command.</param>
    /// <param name="response">The response that was returned.</param>
    /// <returns>A new card instance with updated state.</returns>
    private Result<TraceReplayCard, SmartCardError> CreateUpdatedCard(
        byte[] command,
        ApduResponse response
    )
    {
        return ApduExchange
            .Create(command, Maybe.From(response))
            .Map(exchange =>
            {
                var exchangeBuilder = _executedExchanges.ToBuilder();
                exchangeBuilder.Add(exchange);
                var newExecutedExchanges = exchangeBuilder.ToImmutable();

                (bool newSelected, bool newSecureChannel, int newIndex) = CalculateNewState(
                    command,
                    response
                );

                return new TraceReplayCard(
                    _trace,
                    newSelected,
                    newSecureChannel,
                    newExecutedExchanges,
                    newIndex
                );
            });
    }

    /// <summary>
    /// Calculates the new card state based on the command and response.
    /// </summary>
    /// <param name="command">The processed command.</param>
    /// <param name="response">The response returned.</param>
    /// <returns>New state values for selected status, secure channel, and exchange index.</returns>
    private (bool IsSelected, bool IsSecureChannelEstablished, int ExchangeIndex) CalculateNewState(
        byte[] command,
        ApduResponse response
    )
    {
        if (!response.IsSuccessful)
            return (IsSelected, IsSecureChannelEstablished, _nextExchangeIndex);

        byte ins = command[1];
        int newIndex = ShouldAdvanceSequentialIndex(command)
            ? _nextExchangeIndex + 1
            : _nextExchangeIndex;

        return ins switch
        {
            0xA4 => (true, IsSecureChannelEstablished, newIndex), // SELECT
            0x82 => (IsSelected, true, newIndex), // EXTERNAL AUTHENTICATE
            _ => (IsSelected, IsSecureChannelEstablished, newIndex),
        };
    }

    /// <summary>
    /// Determines if the sequential exchange index should advance based on command match.
    /// </summary>
    /// <param name="command">The processed command.</param>
    /// <returns>True if the index should advance.</returns>
    private bool ShouldAdvanceSequentialIndex(byte[] command)
    {
        return _nextExchangeIndex < _trace.Exchanges.Count
            && CommandHeaderMatches(command, _trace.Exchanges[_nextExchangeIndex].Command);
    }
}
