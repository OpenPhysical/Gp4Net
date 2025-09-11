using System;
using System.Collections.Generic;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.Core;

namespace Gp4Net.CardEmulator.Trace;

/// <summary>
/// Represents a single APDU command/response exchange using functional programming principles.
/// Immutable record with Maybe&lt;T&gt; for optional response.
/// </summary>
public class ApduExchange
{
    /// <summary>
    /// Gets the APDU command bytes.
    /// </summary>
    public byte[] Command { get; }

    /// <summary>
    /// Gets the APDU response if present.
    /// </summary>
    public Maybe<ApduResponse> Response { get; private set; }

    /// <summary>
    /// Gets the timestamp of the exchange.
    /// </summary>
    public DateTime Timestamp { get; }

    /// <summary>
    /// Gets optional metadata for this exchange.
    /// </summary>
    public IReadOnlyDictionary<string, object> Metadata { get; }

    /// <summary>
    /// Gets whether this exchange has a response.
    /// </summary>
    public bool HasResponse => Response.HasValue;

    /// <summary>
    /// Private constructor for ApduExchange class.
    /// Use Create factory method instead.
    /// </summary>
    private ApduExchange(
        byte[] command,
        Maybe<ApduResponse> response,
        Maybe<IReadOnlyDictionary<string, object>> metadata
    )
    {
        Command = command;
        Response = response;
        Timestamp = DateTime.UtcNow;
        Metadata = metadata.Match(m => m, () => new Dictionary<string, object>());
    }

    /// <summary>
    /// Creates a new ApduExchange instance with validation.
    /// </summary>
    public static Result<ApduExchange, SmartCardError> Create(
        byte[] command,
        Maybe<ApduResponse> response = default,
        Maybe<IReadOnlyDictionary<string, object>> metadata = default
    )
    {
        return Maybe<byte[]>
            .From(command)
            .ToResult(SmartCardError.InvalidArgument("Command cannot be null"))
            .Map(cmd => new ApduExchange(cmd, response, metadata));
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
        return Response.Match(
            response =>
            {
                string data = response.Data is { Length: > 0 }
                    ? BitConverter.ToString(response.Data).Replace("-", " ") + " "
                    : "";
                return $"{data}SW: {response.StatusWord:X4}";
            },
            () => "No response"
        );
    }

    /// <summary>
    /// Creates a new ApduExchange with the specified response.
    /// </summary>
    public ApduExchange WithResponse(ApduResponse response)
    {
        return new ApduExchange(
            Command,
            Maybe<ApduResponse>.From(response),
            Maybe<IReadOnlyDictionary<string, object>>.From(Metadata)
        );
    }
}
