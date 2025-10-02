using System;
using System.Collections.Immutable;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Core;

/// <summary>
/// Represents an APDU response with data and status word.
/// </summary>
[PublicAPI]
public class ApduResponse
{
    /// <summary>
    /// Gets the response data.
    /// </summary>
    public byte[] Data { get; }

    /// <summary>
    /// Gets the status word.
    /// </summary>
    public StatusWord StatusWord { get; }

    /// <summary>
    /// Gets a value indicating whether the command was successful.
    /// Includes both normal success (0x9000) and continuation responses (0x61XX, 0x9FXX).
    /// Per GP specification section 8.2, success responses include chained data responses.
    /// </summary>
    public bool IsSuccessful
    {
        get
        {
            return StatusWord == Constants.Constants.StatusWords.Success
                || IsSuccessWithContinuation;
        }
    }

    /// <summary>
    /// Gets a value indicating whether this is a success response with continuation data.
    /// </summary>
    private bool IsSuccessWithContinuation
    {
        get
        {
            ushort sw = StatusWord;
            return (sw & 0xFF00) == 0x6100 || (sw & 0xFF00) == 0x9F00; // 0x61XX or 0x9FXX
        }
    }

    /// <summary>
    /// Initializes a new instance of the ApduResponse class.
    /// </summary>
    /// <param name="data">The response data.</param>
    /// <param name="statusWord">The status word.</param>
    public ApduResponse(byte[] data, StatusWord statusWord)
    {
        Data = data;
        StatusWord = statusWord;
    }

    /// <summary>
    /// Creates a successful response with data.
    /// </summary>
    /// <param name="data">The response data.</param>
    /// <returns>A successful APDU response.</returns>
    public static ApduResponse Success(byte[] data)
    {
        return new ApduResponse(data, Constants.Constants.StatusWords.Success);
    }

    /// <summary>
    /// Creates an error response with the specified status word.
    /// </summary>
    /// <param name="statusWord">The error status word.</param>
    /// <returns>An error APDU response.</returns>
    public static ApduResponse Error(ushort statusWord)
    {
        return new ApduResponse([], statusWord);
    }

    /// <summary>
    /// Converts the response to a byte array suitable for transmission.
    /// </summary>
    /// <returns>The response bytes including status word.</returns>
    public ImmutableArray<byte> ToBytes()
    {
        byte[] result = new byte[Data.Length + 2];
        Array.Copy(Data, 0, result, 0, Data.Length);
        result[Data.Length] = (byte)(StatusWord >> 8);
        result[Data.Length + 1] = (byte)(StatusWord & 0xFF);
        return [.. result];
    }
}
