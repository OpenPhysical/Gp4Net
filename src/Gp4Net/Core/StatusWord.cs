using System;
using JetBrains.Annotations;

namespace Gp4Net.Core;

/// <summary>
/// Represents an ISO 7816-4 status word (SW1SW2).
/// Provides proper hexadecimal formatting for display.
/// </summary>
[PublicAPI]
public readonly struct StatusWord : IEquatable<StatusWord>, IComparable<StatusWord>
{
    private readonly ushort _value;

    /// <summary>
    /// Initializes a new instance of the <see cref="StatusWord"/> struct.
    /// </summary>
    /// <param name="value">The status word value as a 16-bit unsigned integer.</param>
    public StatusWord(ushort value)
    {
        _value = value;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="StatusWord"/> struct from SW1 and SW2 bytes.
    /// </summary>
    /// <param name="sw1">The first status byte (SW1).</param>
    /// <param name="sw2">The second status byte (SW2).</param>
    public StatusWord(byte sw1, byte sw2)
    {
        _value = (ushort)((sw1 << 8) | sw2);
    }

    /// <summary>
    /// Gets the status word value as a 16-bit unsigned integer.
    /// </summary>
    public ushort Value
    {
        get
        {
            return _value;
        }
    }

    /// <summary>
    /// Gets the first status byte (SW1).
    /// </summary>
    public byte SW1
    {
        get
        {
            return (byte)(_value >> 8);
        }
    }

    /// <summary>
    /// Gets the second status byte (SW2).
    /// </summary>
    public byte SW2
    {
        get
        {
            return (byte)(_value & 0xFF);
        }
    }

    /// <summary>
    /// Implicitly converts a ushort to a StatusWord.
    /// </summary>
    /// <param name="value">The ushort value to convert.</param>
    public static implicit operator StatusWord(ushort value) => new(value);

    /// <summary>
    /// Implicitly converts a StatusWord to a ushort.
    /// </summary>
    /// <param name="statusWord">The StatusWord to convert.</param>
    public static implicit operator ushort(StatusWord statusWord) => statusWord._value;

    /// <summary>
    /// Determines whether two StatusWord instances are equal.
    /// </summary>
    public static bool operator ==(StatusWord left, StatusWord right) => left._value == right._value;

    /// <summary>
    /// Determines whether two StatusWord instances are not equal.
    /// </summary>
    public static bool operator !=(StatusWord left, StatusWord right) => left._value != right._value;

    /// <summary>
    /// Determines whether one StatusWord is less than another.
    /// </summary>
    public static bool operator <(StatusWord left, StatusWord right) => left._value < right._value;

    /// <summary>
    /// Determines whether one StatusWord is greater than another.
    /// </summary>
    public static bool operator >(StatusWord left, StatusWord right) => left._value > right._value;

    /// <summary>
    /// Determines whether one StatusWord is less than or equal to another.
    /// </summary>
    public static bool operator <=(StatusWord left, StatusWord right) => left._value <= right._value;

    /// <summary>
    /// Determines whether one StatusWord is greater than or equal to another.
    /// </summary>
    public static bool operator >=(StatusWord left, StatusWord right) => left._value >= right._value;

    /// <inheritdoc />
    public bool Equals(StatusWord other)
    {
        return _value == other._value;
    }

    /// <inheritdoc />
    public override bool Equals(object obj)
    {
        return obj is StatusWord other && Equals(other);
    }

    /// <inheritdoc />
    public override int GetHashCode()
    {
        return _value.GetHashCode();
    }

    /// <inheritdoc />
    public int CompareTo(StatusWord other)
    {
        return _value.CompareTo(other._value);
    }

    /// <summary>
    /// Returns a string representation of the status word in hexadecimal format.
    /// </summary>
    /// <returns>The status word formatted as "0xXXXX".</returns>
    public override string ToString()
    {
        return $"0x{_value:X4}";
    }

    /// <summary>
    /// Returns a descriptive string representation of the status word.
    /// </summary>
    /// <returns>The status word with description if known.</returns>
    public string ToDescriptiveString()
    {
        string description = _value switch
        {
            0x9000 => "Success",
            0x6982 => "Security Status Not Satisfied",
            0x6A82 => "File or Application Not Found",
            0x6A86 => "Incorrect Parameters P1-P2",
            0x6A88 => "Referenced Data Not Found",
            0x6D00 => "Instruction Not Supported",
            0x6E00 => "Class Not Supported",
            0x6985 => "Conditions Not Satisfied",
            0x6C00 => "Wrong Length",
            0x6984 => "Invalid Data",
            0x6A80 => "Invalid Argument",
            0x6983 => "Authentication Method Blocked",
            0x6F00 => "General Error",
            0x6A84 => "Not Enough Memory",
            0x6A87 => "Lc Inconsistent with P1-P2",
            0x6987 => "Expected Secure Messaging Data Objects Missing",
            0x6988 => "Incorrect Secure Messaging Data Objects",
            0x6700 => "Wrong Length Le",
            0x6A81 => "Function Not Supported",
            0x6A83 => "Record Not Found",
            0x6986 => "Command Not Allowed",
            0x6F99 => "PIN Blocked",
            0x63C0 => "Authentication Failed (0 tries remaining)",
            0x63C1 => "Authentication Failed (1 try remaining)",
            0x63C2 => "Authentication Failed (2 tries remaining)",
            0x63C3 => "Authentication Failed (3 tries remaining)",
            0x69FF => "Unknown Error",
            _ => null
        };

        return description != null ? $"0x{_value:X4} ({description})" : ToString();
    }
}
