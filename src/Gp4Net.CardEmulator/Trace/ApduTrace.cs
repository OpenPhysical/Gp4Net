using System;
using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.CardEmulator.Core;

namespace Gp4Net.CardEmulator.Trace;

/// <summary>
/// Represents a complete APDU trace from a card session.
/// </summary>
public class ApduTrace
{
    private readonly List<ApduExchange> _exchanges = new List<ApduExchange>();

    /// <summary>
    /// Gets the list of APDU exchanges in the trace.
    /// </summary>
    public IReadOnlyList<ApduExchange> Exchanges
    {
        get
        {
            return _exchanges.AsReadOnly();
        }
    }

    /// <summary>
    /// Gets the ATR if captured in the trace.
    /// </summary>
    public byte[]? Atr { get; set; }

    /// <summary>
    /// Gets metadata about the trace.
    /// </summary>
    public TraceMetadata Metadata { get; } = new TraceMetadata();

    /// <summary>
    /// Adds an APDU exchange to the trace.
    /// </summary>
    public void AddExchange(ApduExchange exchange)
    {
        ArgumentNullException.ThrowIfNull(exchange);

        _exchanges.Add(exchange);
    }

    /// <summary>
    /// Finds exchanges matching a specific command pattern.
    /// </summary>
    public IEnumerable<ApduExchange> FindExchanges(
        byte? cla = null,
        byte? ins = null,
        byte? p1 = null,
        byte? p2 = null
    )
    {
        return _exchanges.Where(ex =>
        {
            if (ex.Command.Length < 4)
                return false;

            return (!cla.HasValue || ex.Command[0] == cla.Value)
                   && (!ins.HasValue || ex.Command[1] == ins.Value)
                   && (!p1.HasValue || ex.Command[2] == p1.Value)
                   && (!p2.HasValue || ex.Command[3] == p2.Value);
        });
    }
}

/// <summary>
/// Represents a single APDU command/response exchange.
/// </summary>
public class ApduExchange
{
    /// <summary>
    /// Gets the APDU command bytes.
    /// </summary>
    public byte[] Command { get; }

    /// <summary>
    /// Gets or sets the APDU response.
    /// </summary>
    public ApduResponse? Response { get; set; }

    /// <summary>
    /// Gets the timestamp of the exchange.
    /// </summary>
    public DateTime Timestamp { get; }

    /// <summary>
    /// Gets or sets optional metadata for this exchange.
    /// </summary>
    public Dictionary<string, object> Metadata { get; } = new Dictionary<string, object>();

    /// <summary>
    /// Gets whether this exchange has a response.
    /// </summary>
    public bool HasResponse
    {
        get
        {
            return Response != null;
        }
    }

    /// <summary>
    /// Private constructor for ApduExchange class.
    /// Use Create factory method instead.
    /// </summary>
    private ApduExchange(byte[] command, Maybe<ApduResponse> response)
    {
        Command = command;
        Response = response.Match(r => r, () => null);
        Timestamp = DateTime.UtcNow;
    }
    
    /// <summary>
    /// Creates a new ApduExchange instance with validation.
    /// </summary>
    public static Result<ApduExchange, SmartCardError> Create(byte[] command, Maybe<ApduResponse> response = default)
    {
        return Maybe<byte[]>.From(command)
            .ToResult(SmartCardError.InvalidArgument("Command cannot be null"))
            .Map(cmd => new ApduExchange(cmd, response));
    }

    /// <summary>
    /// Gets a string representation of the command for debugging.
    /// </summary>
    public string GetCommandString()
    {
        return BitConverter.ToString(Command).Replace("-", " ");
    }

    /// <summary>
    /// Gets a string representation of the response for debugging.
    /// </summary>
    public string GetResponseString()
    {
        if (Response == null)
            return "No response";

        string data =
            Response.Data is { Length: > 0 }
                ? BitConverter.ToString(Response.Data).Replace("-", " ") + " "
                : "";

        return $"{data}SW: {Response.StatusWord:X4}";
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
    public string? ReaderName { get; set; }

    /// <summary>
    /// Gets additional properties.
    /// </summary>
    public Dictionary<string, string> Properties { get; } = new Dictionary<string, string>();
}