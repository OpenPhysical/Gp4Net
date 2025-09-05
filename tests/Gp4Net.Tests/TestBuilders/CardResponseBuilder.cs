using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Transport;

namespace Gp4Net.Tests.TestBuilders;

/// <summary>
/// Type alias for ApduResponse in test contexts for backward compatibility.
/// </summary>
using CardResponse = ApduResponse;

/// <summary>
/// Builder for creating test CardResponse/ApduResponse instances with fluent interface.
/// Provides convenient methods for building APDU responses in tests.
/// </summary>
public sealed class CardResponseBuilder
{
    private readonly byte[] _data;
    private readonly StatusWord _statusWord;

    /// <summary>
    /// Creates a new builder with default values.
    /// </summary>
    public CardResponseBuilder() : this([], new StatusWord(0x9000))
    {
    }

    private CardResponseBuilder(byte[] data, StatusWord statusWord)
    {
        _data = data;
        _statusWord = statusWord;
    }

    /// <summary>
    /// Sets the response data.
    /// </summary>
    /// <param name="data">The response data bytes.</param>
    /// <returns>A new builder with the data set.</returns>
    public CardResponseBuilder WithData(params byte[] data)
    {
        return new CardResponseBuilder(data ?? [], _statusWord);
    }

    /// <summary>
    /// Sets the response data from a hex string.
    /// </summary>
    /// <param name="hexString">The hex string (spaces and case ignored).</param>
    /// <returns>A new builder with the data set, or the same builder if hex parsing fails.</returns>
    public CardResponseBuilder WithDataFromHex(string hexString)
    {
        return ParseHexString(hexString).Match(
            data => new CardResponseBuilder(data, _statusWord),
            () => this
        );
    }

    /// <summary>
    /// Sets the status word.
    /// </summary>
    /// <param name="statusWord">The status word.</param>
    /// <returns>A new builder with the status word set.</returns>
    public CardResponseBuilder WithStatusWord(ushort statusWord)
    {
        return new CardResponseBuilder(_data, new StatusWord(statusWord));
    }

    /// <summary>
    /// Sets the status word from SW1 and SW2 bytes.
    /// </summary>
    /// <param name="sw1">The SW1 byte.</param>
    /// <param name="sw2">The SW2 byte.</param>
    /// <returns>A new builder with the status word set.</returns>
    public CardResponseBuilder WithStatusBytes(byte sw1, byte sw2)
    {
        return new CardResponseBuilder(_data, new StatusWord(sw1, sw2));
    }

    /// <summary>
    /// Sets the status word to success (0x9000).
    /// </summary>
    /// <returns>A new builder with success status set.</returns>
    public CardResponseBuilder WithSuccessStatus()
    {
        return new CardResponseBuilder(_data, new StatusWord(0x9000));
    }

    /// <summary>
    /// Sets the status word to "Security Status Not Satisfied" (0x6982).
    /// </summary>
    /// <returns>A new builder with security error status set.</returns>
    public CardResponseBuilder WithSecurityNotSatisfied()
    {
        return new CardResponseBuilder(_data, new StatusWord(0x6982));
    }

    /// <summary>
    /// Sets the status word to "More Data Available" with the specified number of bytes.
    /// </summary>
    /// <param name="bytesAvailable">The number of bytes available.</param>
    /// <returns>A new builder with more data available status set.</returns>
    public CardResponseBuilder WithMoreDataAvailable(byte bytesAvailable)
    {
        return new CardResponseBuilder(_data, new StatusWord(0x61, bytesAvailable));
    }

    /// <summary>
    /// Builds the CardResponse/ApduResponse.
    /// </summary>
    /// <returns>The built CardResponse.</returns>
    public CardResponse Build()
    {
        return new ApduResponse(_data, _statusWord);
    }

    /// <summary>
    /// Implicit conversion to CardResponse for convenience.
    /// </summary>
    /// <param name="builder">The builder to convert.</param>
    public static implicit operator CardResponse(CardResponseBuilder builder)
    {
        return builder.Build();
    }

    /// <summary>
    /// Parses a hex string into bytes using functional approach.
    /// </summary>
    /// <param name="hexString">The hex string to parse.</param>
    /// <returns>Maybe containing the parsed bytes, or None if parsing fails.</returns>
    private static Maybe<byte[]> ParseHexString(string hexString)
    {
        if (string.IsNullOrWhiteSpace(hexString))
            return Maybe<byte[]>.From([]);

        // Remove spaces and normalize
        string cleanHex = hexString.Replace(" ", "").Replace("\t", "").Replace("\n", "").Replace("\r", "");
        
        // Must have even number of characters
        if (cleanHex.Length % 2 != 0)
            return Maybe<byte[]>.None;

        return Maybe<byte[]>.From(
            Enumerable.Range(0, cleanHex.Length / 2)
                .Select(i => cleanHex.Substring(i * 2, 2))
                .Select(hex => Convert.ToByte(hex, 16))
                .ToArray()
        );
    }
}