using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;

namespace Gp4Net.CardEmulator.Trace;

/// <summary>
/// Represents a complete APDU trace from a card session using immutable functional patterns.
/// </summary>
public class ApduTrace
{
    private readonly ImmutableList<ApduExchange> _exchanges;

    /// <summary>
    /// Gets the list of APDU exchanges in the trace.
    /// </summary>
    public IReadOnlyList<ApduExchange> Exchanges => _exchanges;

    /// <summary>
    /// Gets the ATR if captured in the trace.
    /// </summary>
    public Maybe<byte[]> Atr { get; }

    /// <summary>
    /// Gets metadata about the trace.
    /// </summary>
    public TraceMetadata Metadata { get; }

    /// <summary>
    /// Private constructor for immutable instances.
    /// </summary>
    private ApduTrace(
        ImmutableList<ApduExchange> exchanges,
        Maybe<byte[]> atr,
        TraceMetadata metadata
    )
    {
        _exchanges = exchanges;
        Atr = atr;
        Metadata = metadata;
    }

    /// <summary>
    /// Creates an empty APDU trace.
    /// </summary>
    /// <returns>A new empty trace instance.</returns>
    public static ApduTrace CreateEmpty() =>
        new ApduTrace(ImmutableList<ApduExchange>.Empty, Maybe<byte[]>.None, new TraceMetadata());

    /// <summary>
    /// Creates a new trace with an additional APDU exchange.
    /// </summary>
    /// <param name="exchange">The exchange to add.</param>
    /// <returns>A new trace instance with the added exchange, or an error.</returns>
    public Result<ApduTrace, SmartCardError> WithExchange(ApduExchange exchange)
    {
        return Result.Success<ApduTrace, SmartCardError>(
            new ApduTrace(ImmutableList.CreateRange(_exchanges.Append(exchange)), Atr, Metadata)
        );
    }

    /// <summary>
    /// Creates a new trace with the specified ATR.
    /// </summary>
    /// <param name="atr">The ATR bytes.</param>
    /// <returns>A new trace instance with the ATR set, or an error.</returns>
    public Result<ApduTrace, SmartCardError> WithAtr(byte[] atr)
    {
        return Result.Success<ApduTrace, SmartCardError>(
            new ApduTrace(_exchanges, Maybe<byte[]>.From(atr), Metadata)
        );
    }

    /// <summary>
    /// Finds exchanges matching a specific command pattern.
    /// </summary>
    public IEnumerable<ApduExchange> FindExchanges(
        Maybe<byte> cla = default,
        Maybe<byte> ins = default,
        Maybe<byte> p1 = default,
        Maybe<byte> p2 = default
    )
    {
        return _exchanges.Where(ex =>
        {
            if (ex.Command.Length < 4)
                return false;

            return cla.Match(claValue => ex.Command[0] == claValue, () => true)
                && ins.Match(insValue => ex.Command[1] == insValue, () => true)
                && p1.Match(p1Value => ex.Command[2] == p1Value, () => true)
                && p2.Match(p2Value => ex.Command[3] == p2Value, () => true);
        });
    }
}

// ApduResponse class has been moved to Core namespace
// Use Gp4Net.CardEmulator.Core.ApduResponse instead

/// <summary>
/// Metadata about an APDU trace.
/// </summary>
public class TraceMetadata
{
    /// <summary>
    /// Gets or sets the source of the trace (e.g., "gpshell", "pcsc").
    /// </summary>
    public string Source { get; set; } = "unknown";

    /// <summary>
    /// Gets or sets when the trace was captured.
    /// </summary>
    public DateTime CaptureTime { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Gets or sets the reader name if known.
    /// </summary>
    public string ReaderName { get; set; } = "unknown";

    /// <summary>
    /// Gets additional properties.
    /// </summary>
    public Dictionary<string, string> Properties { get; } = new Dictionary<string, string>();
}
