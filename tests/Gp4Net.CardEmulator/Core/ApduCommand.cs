using System;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Core;

/// <summary>
/// Represents a parsed APDU command with header and data fields.
/// </summary>
[PublicAPI]
public class ApduCommand
{
    /// <summary>
    /// Gets the class byte (CLA).
    /// </summary>
    public byte Cla { get; }

    /// <summary>
    /// Gets the instruction byte (INS).
    /// </summary>
    public byte Ins { get; }

    /// <summary>
    /// Gets the parameter 1 byte (P1).
    /// </summary>
    public byte P1 { get; }

    /// <summary>
    /// Gets the parameter 2 byte (P2).
    /// </summary>
    public byte P2 { get; }

    /// <summary>
    /// Gets the command data.
    /// </summary>
    public byte[] Data { get; }

    /// <summary>
    /// Gets the expected response length (Le). Null if not specified.
    /// </summary>
    public byte? Le { get; }

    /// <summary>
    /// Gets the raw APDU bytes.
    /// </summary>
    public byte[] RawBytes { get; }

    /// <summary>
    /// Initializes a new instance of the ApduCommand class.
    /// </summary>
    /// <param name="rawBytes">The raw APDU command bytes.</param>
    public ApduCommand(byte[] rawBytes)
    {
        ArgumentNullException.ThrowIfNull(rawBytes);
        if (rawBytes.Length < 4)
            throw new ArgumentException("APDU must be at least 4 bytes long", nameof(rawBytes));

        RawBytes = (byte[])rawBytes.Clone();

        Cla = rawBytes[0];
        Ins = rawBytes[1];
        P1 = rawBytes[2];
        P2 = rawBytes[3];

        if (rawBytes.Length == 4)
        {
            // Case 1: No data, no Le
            Data = Array.Empty<byte>();
            Le = null;
        }
        else if (rawBytes.Length == 5)
        {
            // Case 2: No data, Le present
            Data = Array.Empty<byte>();
            Le = rawBytes[4];
        }
        else
        {
            // Case 3 or 4: Data present
            var lc = rawBytes[4];

            if (rawBytes.Length == 5 + lc)
            {
                // Case 3: Data present, no Le
                Data = new byte[lc];
                Array.Copy(rawBytes, 5, Data, 0, lc);
                Le = null;
            }
            else if (rawBytes.Length == 5 + lc + 1)
            {
                // Case 4: Data present, Le present
                Data = new byte[lc];
                Array.Copy(rawBytes, 5, Data, 0, lc);
                Le = rawBytes[5 + lc];
            }
            else
            {
                throw new ArgumentException("Invalid APDU format", nameof(rawBytes));
            }
        }
    }

    /// <summary>
    /// Gets a value indicating whether this is a SELECT command.
    /// </summary>
    public bool IsSelect
    {
        get
        {
            return Ins == 0xA4;
        }
    }

    /// <summary>
    /// Gets a value indicating whether this is an INITIALIZE UPDATE command.
    /// </summary>
    public bool IsInitializeUpdate
    {
        get
        {
            return Cla == 0x80 && Ins == 0x50;
        }
    }

    /// <summary>
    /// Gets a value indicating whether this is an EXTERNAL AUTHENTICATE command.
    /// </summary>
    public bool IsExternalAuthenticate
    {
        get
        {
            return Cla == 0x84 && Ins == 0x82;
        }
    }

    /// <summary>
    /// Gets a value indicating whether this is an INSTALL command.
    /// </summary>
    public bool IsInstall
    {
        get
        {
            return (Cla == 0x80 || Cla == 0x84) && Ins == 0xE6;
        }
    }

    /// <summary>
    /// Gets a value indicating whether this is a LOAD command.
    /// </summary>
    public bool IsLoad
    {
        get
        {
            return (Cla == 0x80 || Cla == 0x84) && Ins == 0xE8;
        }
    }

    /// <summary>
    /// Gets a value indicating whether this is a GET STATUS command.
    /// </summary>
    public bool IsGetStatus
    {
        get
        {
            return (Cla == 0x80 || Cla == 0x84) && Ins == 0xF2;
        }
    }

    /// <summary>
    /// Gets a value indicating whether this is a DELETE command.
    /// </summary>
    public bool IsDelete
    {
        get
        {
            return (Cla == 0x80 || Cla == 0x84) && Ins == 0xE4;
        }
    }

    /// <summary>
    /// Gets a value indicating whether this is a GET DATA command.
    /// </summary>
    public bool IsGetData
    {
        get
        {
            return Ins == 0xCA;
        }
    }

    /// <summary>
    /// Gets a value indicating whether this is a PUT KEY command.
    /// </summary>
    public bool IsPutKey
    {
        get
        {
            return (Cla == 0x80 || Cla == 0x84) && Ins == 0xD8;
        }
    }

    /// <summary>
    /// Gets a value indicating whether this is a SET STATUS command.
    /// </summary>
    public bool IsSetStatus
    {
        get
        {
            return (Cla == 0x80 || Cla == 0x84) && Ins == 0xF0;
        }
    }

    /// <summary>
    /// Returns a string representation of the APDU command.
    /// </summary>
    /// <returns>A string representation of the command.</returns>
    public override string ToString()
    {
        return $"{Cla:X2} {Ins:X2} {P1:X2} {P2:X2} [{Data.Length:X2}] {Convert.ToHexString(Data)}"
               + (Le.HasValue ? $" [{Le.Value:X2}]" : "");
    }
}