using System.Collections.Immutable;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Applications;

/// <summary>
/// Represents an APDU response from an application.
/// Immutable value type following functional programming principles.
/// </summary>
[PublicAPI]
public sealed record ApduResponse
{
    /// <summary>
    /// Response data (may be empty).
    /// </summary>
    public ImmutableArray<byte> Data { get; }

    /// <summary>
    /// Status word (SW1 and SW2).
    /// </summary>
    public StatusWord StatusWord { get; }

    private ApduResponse(ImmutableArray<byte> data, StatusWord statusWord)
    {
        Data = data;
        StatusWord = statusWord;
    }

    /// <summary>
    /// Creates a successful response with data.
    /// </summary>
    public static ApduResponse Success(ImmutableArray<byte> data)
    {
        return new ApduResponse(data, Constants.Constants.StatusWords.Legacy.Success);
    }

    /// <summary>
    /// Creates a successful response with data.
    /// </summary>
    public static ApduResponse Success(byte[] data)
    {
        return new ApduResponse([.. data], Constants.Constants.StatusWords.Legacy.Success);
    }

    /// <summary>
    /// Creates a successful response with no data.
    /// </summary>
    public static ApduResponse Success()
    {
        return new ApduResponse(
            ImmutableArray<byte>.Empty,
            Constants.Constants.StatusWords.Legacy.Success
        );
    }

    /// <summary>
    /// Creates an error response with specified status word.
    /// </summary>
    public static ApduResponse Error(StatusWord statusWord)
    {
        return new ApduResponse(ImmutableArray<byte>.Empty, statusWord);
    }

    /// <summary>
    /// Creates a response with explicit data and status word.
    /// </summary>
    public static ApduResponse From(byte[] data, StatusWord statusWord)
    {
        return new ApduResponse([.. data], statusWord);
    }

    /// <summary>
    /// Creates an error response for wrong length.
    /// </summary>
    public static ApduResponse WrongLength()
    {
        return Error(Constants.Constants.StatusWords.Legacy.WrongLength);
    }

    /// <summary>
    /// Creates an error response for instruction not supported.
    /// </summary>
    public static ApduResponse InstructionNotSupported()
    {
        return Error(Constants.Constants.StatusWords.Legacy.InstructionNotSupported);
    }

    /// <summary>
    /// Creates an error response for conditions not satisfied.
    /// </summary>
    public static ApduResponse ConditionsNotSatisfied()
    {
        return Error(Constants.Constants.StatusWords.Legacy.ConditionsNotSatisfied);
    }

    /// <summary>
    /// Creates an error response for security status not satisfied.
    /// </summary>
    public static ApduResponse SecurityStatusNotSatisfied()
    {
        return Error(Constants.Constants.StatusWords.Legacy.SecurityStatusNotSatisfied);
    }

    /// <summary>
    /// Converts response to byte array (data + SW).
    /// </summary>
    public byte[] ToByteArray()
    {
        var result = new byte[Data.Length + 2];
        if (Data.Length > 0)
        {
            Data.CopyTo(result, 0);
        }
        result[^2] = StatusWord.Sw1;
        result[^1] = StatusWord.Sw2;
        return result;
    }
}
