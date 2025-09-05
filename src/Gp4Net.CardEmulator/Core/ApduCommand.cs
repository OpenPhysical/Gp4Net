using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;
using static Gp4Net.Constants.Constants;

namespace Gp4Net.CardEmulator.Core;

/// <summary>
/// Represents a parsed APDU command with header and data fields.
/// Immutable record following functional programming principles.
/// </summary>
[PublicAPI]
public sealed record ApduCommand
{
    /// <summary>
    /// Gets the class byte (CLA).
    /// </summary>
    public byte Cla { get; init; }

    /// <summary>
    /// Gets the instruction byte (INS).
    /// </summary>
    public byte Ins { get; init; }

    /// <summary>
    /// Gets the parameter 1 byte (P1).
    /// </summary>
    public byte P1 { get; init; }

    /// <summary>
    /// Gets the parameter 2 byte (P2).
    /// </summary>
    public byte P2 { get; init; }

    /// <summary>
    /// Gets the command data.
    /// </summary>
    public byte[] Data { get; init; }

    /// <summary>
    /// Gets the expected response length (Le). Use Maybe for optional values.
    /// </summary>
    public Maybe<byte> Le { get; init; }

    /// <summary>
    /// Gets the raw APDU bytes.
    /// </summary>
    public byte[] RawBytes { get; init; }

    /// <summary>
    /// Initializes a new instance of the ApduCommand record.
    /// </summary>
    private ApduCommand()
    {
        Data = [];
        RawBytes = [];
    }
    /// <summary>
    /// Functional factory method that creates ApduCommand using Result pattern.
    /// </summary>
    /// <param name="rawBytes">The raw APDU command bytes.</param>
    /// <returns>Result containing ApduCommand or error.</returns>
    public static Result<ApduCommand, SmartCardError> Create(byte[] rawBytes)
    {
        return Maybe
            .From(rawBytes)
            .ToResult(SmartCardError.InvalidArgument("APDU bytes cannot be null"))
            .Ensure(
                bytes => bytes.Length >= 4,
                SmartCardError.InvalidArgument("APDU must be at least 4 bytes long")
            )
            .Bind(ValidateApduFormat)
            .Map(bytes => CreateUnsafe(bytes));
    }

    /// <summary>
    /// Validates APDU format according to ISO 7816 specification.
    /// </summary>
    private static Result<byte[], SmartCardError> ValidateApduFormat(byte[] rawBytes)
    {
        return rawBytes.Length switch
        {
            4 => Result.Success<byte[], SmartCardError>(rawBytes), // Case 1: No Lc, no Le
            5 => Result.Success<byte[], SmartCardError>(rawBytes), // Case 2: No Lc, Le present
            >= 6 when rawBytes.Length == 5 + rawBytes[4] => Result.Success<byte[], SmartCardError>(
                rawBytes
            ), // Case 3: Lc present, data, no Le
            >= 7 when rawBytes.Length == 6 + rawBytes[4] => Result.Success<byte[], SmartCardError>(
                rawBytes
            ), // Case 4: Lc present, data, Le present
            _ => Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("Invalid APDU format")
            ),
        };
    }

    /// <summary>
    /// Creates ApduCommand without validation. Used internally after validation in Create method.
    /// </summary>
    private static ApduCommand CreateUnsafe(byte[] rawBytes) => 
        ParseApduBytes(rawBytes);

    /// <summary>
    /// Parses raw APDU bytes into structured components following ISO 7816 specification.
    /// </summary>
    private static ApduCommand ParseApduBytes(byte[] rawBytes) =>
        rawBytes.Length switch
        {
            4 => new ApduCommand
            {
                Cla = rawBytes[0],
                Ins = rawBytes[1],
                P1 = rawBytes[2],
                P2 = rawBytes[3],
                Data = [],
                Le = Maybe<byte>.None,
                RawBytes = (byte[])rawBytes.Clone()
            },
            5 => new ApduCommand
            {
                Cla = rawBytes[0],
                Ins = rawBytes[1],
                P1 = rawBytes[2],
                P2 = rawBytes[3],
                Data = [],
                Le = Maybe<byte>.From(rawBytes[4]),
                RawBytes = (byte[])rawBytes.Clone()
            },
            _ => ParseApduWithData(rawBytes)
        };

    /// <summary>
    /// Parses APDU with data component (Case 3 or 4).
    /// </summary>
    private static ApduCommand ParseApduWithData(byte[] rawBytes)
    {
        byte lc = rawBytes[4];
        byte[] data = new byte[lc];
        Array.Copy(rawBytes, 5, data, 0, lc);

        return rawBytes.Length == 5 + lc
            ? new ApduCommand
            {
                Cla = rawBytes[0],
                Ins = rawBytes[1],
                P1 = rawBytes[2],
                P2 = rawBytes[3],
                Data = data,
                Le = Maybe<byte>.None,
                RawBytes = (byte[])rawBytes.Clone()
            }
            : new ApduCommand
            {
                Cla = rawBytes[0],
                Ins = rawBytes[1],
                P1 = rawBytes[2],
                P2 = rawBytes[3],
                Data = data,
                Le = Maybe<byte>.From(rawBytes[5 + lc]),
                RawBytes = (byte[])rawBytes.Clone()
            };
    }

    /// <summary>
    /// Gets a value indicating whether this is a SELECT command.
    /// </summary>
    public bool IsSelect
    {
        get { return Ins == GlobalPlatform.Ins.Select; }
    }

    /// <summary>
    /// Gets a value indicating whether this is an INITIALIZE UPDATE command.
    /// </summary>
    public bool IsInitializeUpdate
    {
        get { return Cla == GlobalPlatform.Cla.GpStandard && Ins == GlobalPlatform.Ins.InitializeUpdate; }
    }

    /// <summary>
    /// Gets a value indicating whether this is an EXTERNAL AUTHENTICATE command.
    /// </summary>
    public bool IsExternalAuthenticate
    {
        get { return Cla == GlobalPlatform.Cla.Secured && Ins == GlobalPlatform.Ins.ExternalAuthenticate; }
    }

    /// <summary>
    /// Gets a value indicating whether this is an INSTALL command.
    /// </summary>
    public bool IsInstall
    {
        get { return Cla is GlobalPlatform.Cla.GpStandard or GlobalPlatform.Cla.Secured && Ins == GlobalPlatform.Ins.Install; }
    }

    /// <summary>
    /// Gets a value indicating whether this is a LOAD command.
    /// </summary>
    public bool IsLoad
    {
        get { return Cla is GlobalPlatform.Cla.GpStandard or GlobalPlatform.Cla.Secured && Ins == GlobalPlatform.Ins.Load; }
    }

    /// <summary>
    /// Gets a value indicating whether this is a GET STATUS command.
    /// </summary>
    public bool IsGetStatus
    {
        get { return Cla is GlobalPlatform.Cla.GpStandard or GlobalPlatform.Cla.Secured && Ins == GlobalPlatform.Ins.GetStatus; }
    }

    /// <summary>
    /// Gets a value indicating whether this is a DELETE command.
    /// </summary>
    public bool IsDelete
    {
        get { return Cla is GlobalPlatform.Cla.GpStandard or GlobalPlatform.Cla.Secured && Ins == GlobalPlatform.Ins.Delete; }
    }

    /// <summary>
    /// Gets a value indicating whether this is a GET DATA command.
    /// </summary>
    public bool IsGetData
    {
        get { return Ins == GlobalPlatform.Ins.GetData; }
    }

    /// <summary>
    /// Gets a value indicating whether this is a PUT KEY command.
    /// </summary>
    public bool IsPutKey
    {
        get { return Cla is GlobalPlatform.Cla.GpStandard or GlobalPlatform.Cla.Secured && Ins == GlobalPlatform.Ins.PutKey; }
    }

    /// <summary>
    /// Gets a value indicating whether this is a SET STATUS command.
    /// </summary>
    public bool IsSetStatus
    {
        get { return Cla is GlobalPlatform.Cla.GpStandard or GlobalPlatform.Cla.Secured && Ins == GlobalPlatform.Ins.SetStatus; }
    }

    /// <summary>
    /// Returns a string representation of the APDU command.
    /// </summary>
    /// <returns>A string representation of the command.</returns>
    public override string ToString()
    {
        return $"{Cla:X2} {Ins:X2} {P1:X2} {P2:X2} [{Data.Length:X2}] {Convert.ToHexString(Data)}"
            + Le.Map(le => $" [{le:X2}]").GetValueOrDefault("");
    }
}
