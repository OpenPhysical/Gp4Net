using System;
using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Pipeline;

namespace Gp4Net.Tests.TestBuilders;

/// <summary>
/// Builder pattern for creating CommandResponse instances for testing.
/// Preserves all original functionality while adapting to new CommandResponse type.
/// </summary>
public class CommandResponseBuilder
{
    private readonly byte[] _data;
    private readonly StatusWord _statusWord;
    private readonly IPipelineContext _context;
    private readonly IReadOnlyDictionary<string, object> _metadata;

    /// <summary>
    /// Initializes a new CommandResponseBuilder with default values.
    /// </summary>
    public CommandResponseBuilder()
    {
        _data = [];
        _statusWord = 0x9000;
        _context = ImmutablePipelineContext.Empty;
        _metadata = new Dictionary<string, object>();
    }

    private CommandResponseBuilder(
        byte[] data,
        StatusWord statusWord,
        IPipelineContext context,
        IReadOnlyDictionary<string, object> metadata)
    {
        _data = data;
        _statusWord = statusWord;
        _context = context;
        _metadata = metadata;
    }

    /// <summary>
    /// Sets the response data.
    /// </summary>
    public CommandResponseBuilder WithData(params byte[] data)
    {
        return new CommandResponseBuilder(data, _statusWord, _context, _metadata);
    }

    /// <summary>
    /// Sets the response data from a hex string.
    /// </summary>
    public CommandResponseBuilder WithDataFromHex(string hexData)
    {
        return Maybe<string>.From(hexData)
            .Where(hex => !string.IsNullOrWhiteSpace(hex))
            .Bind(hex => ConvertFromHexString(hex).ToMaybe())
            .Match(
                data => new CommandResponseBuilder(data, _statusWord, _context, _metadata),
                () => new CommandResponseBuilder([], _statusWord, _context, _metadata));
    }

    /// <summary>
    /// Sets the status word.
    /// </summary>
    public CommandResponseBuilder WithStatusWord(ushort statusWord)
    {
        return new CommandResponseBuilder(_data, statusWord, _context, _metadata);
    }

    /// <summary>
    /// Sets the status word from SW1 and SW2 bytes.
    /// </summary>
    public CommandResponseBuilder WithStatusBytes(byte sw1, byte sw2)
    {
        ushort statusWord = (ushort)((sw1 << 8) | sw2);
        return new CommandResponseBuilder(_data, statusWord, _context, _metadata);
    }

    /// <summary>
    /// Sets a success status (90 00).
    /// </summary>
    public CommandResponseBuilder WithSuccessStatus()
    {
        return new CommandResponseBuilder(_data, 0x9000, _context, _metadata);
    }

    /// <summary>
    /// Sets a warning status (62 XX or 63 XX).
    /// </summary>
    public CommandResponseBuilder WithWarningStatus(byte sw2 = 0x00)
    {
        ushort statusWord = (ushort)(0x6200 | sw2);
        return new CommandResponseBuilder(_data, statusWord, _context, _metadata);
    }

    /// <summary>
    /// Sets an error status (6X XX where X > 3).
    /// </summary>
    public CommandResponseBuilder WithErrorStatus(byte sw1 = 0x6A, byte sw2 = 0x82)
    {
        ushort statusWord = (ushort)((sw1 << 8) | sw2);
        return new CommandResponseBuilder(_data, statusWord, _context, _metadata);
    }

    /// <summary>
    /// Sets a "more data available" status (61 XX).
    /// </summary>
    public CommandResponseBuilder WithMoreDataAvailable(byte remainingBytes)
    {
        ushort statusWord = (ushort)(0x6100 | remainingBytes);
        return new CommandResponseBuilder(_data, statusWord, _context, _metadata);
    }

    /// <summary>
    /// Sets a security status not satisfied error (69 82).
    /// </summary>
    public CommandResponseBuilder WithSecurityNotSatisfied()
    {
        return new CommandResponseBuilder(_data, 0x6982, _context, _metadata);
    }

    /// <summary>
    /// Sets an authentication failed error (63 00).
    /// </summary>
    public CommandResponseBuilder WithAuthenticationFailed()
    {
        return new CommandResponseBuilder(_data, 0x6300, _context, _metadata);
    }

    /// <summary>
    /// Sets the pipeline context.
    /// </summary>
    public CommandResponseBuilder WithContext(IPipelineContext context)
    {
        return new CommandResponseBuilder(_data, _statusWord, context, _metadata);
    }

    /// <summary>
    /// Adds metadata to the response.
    /// </summary>
    public CommandResponseBuilder WithMetadata(string key, object value)
    {
        Dictionary<string, object> newMetadata = new Dictionary<string, object>(_metadata)
        {
            [key] = value
        };
        return new CommandResponseBuilder(_data, _statusWord, _context, newMetadata);
    }

    /// <summary>
    /// Builds the CommandResponse instance.
    /// </summary>
    public CommandResponse Build()
    {
        return new CommandResponse(_data, _statusWord, _context, _metadata);
    }

    /// <summary>
    /// Implicit conversion to CommandResponse.
    /// </summary>
    public static implicit operator CommandResponse(CommandResponseBuilder builder)
    {
        return builder.Build();
    }

    private static Result<byte[], string> ConvertFromHexString(string hex)
    {
        // Remove spaces and convert to uppercase using functional approach
        string cleanedHex = hex.Replace(" ", "").Replace("-", "").ToUpperInvariant();

        // Validate even length
        if (cleanedHex.Length % 2 != 0)
        {
            return Result.Failure<byte[], string>("Hex string must have even length");
        }

        // Convert using functional approach with Result wrapping
        return Result.Try(() =>
            Enumerable.Range(0, cleanedHex.Length / 2)
                .Select(i => Convert.ToByte(cleanedHex.Substring(i * 2, 2), 16))
                .ToArray(),
            ex => $"Invalid hex format: {ex.Message}");
    }
}