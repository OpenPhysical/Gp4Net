using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Pipeline;

/// <summary>
/// Represents an APDU command that has been wrapped with secure channel security.
/// Preserves the original command while carrying the secured bytes.
/// </summary>
[PublicAPI]
public sealed record WrappedApduCommand : ICompleteApduCommand
{
    /// <summary>
    /// The original unwrapped command.
    /// </summary>
    public IApduCommand OriginalCommand { get; }

    /// <summary>
    /// The complete wrapped command bytes including security.
    /// </summary>
    public byte[] WrappedBytes { get; }

    /// <summary>
    /// Private constructor for successful creation.
    /// </summary>
    private WrappedApduCommand(IApduCommand originalCommand, byte[] wrappedBytes)
    {
        OriginalCommand = originalCommand;
        WrappedBytes = wrappedBytes;
    }

    /// <summary>
    /// Creates a new WrappedApduCommand with functional validation.
    /// </summary>
    /// <param name="originalCommand">The original command before wrapping.</param>
    /// <param name="wrappedBytes">The secured command bytes.</param>
    /// <returns>A result containing the wrapped command or an error.</returns>
    public static Result<WrappedApduCommand, SmartCardError> Create(
        IApduCommand originalCommand,
        byte[] wrappedBytes
    )
    {
        if (originalCommand == null)
        {
            return Result.Failure<WrappedApduCommand, SmartCardError>(
                SmartCardError.InvalidArgument("Original command cannot be null")
            );
        }

        if (wrappedBytes == null)
        {
            return Result.Failure<WrappedApduCommand, SmartCardError>(
                SmartCardError.InvalidArgument("Wrapped bytes cannot be null")
            );
        }

        if (wrappedBytes.Length < 4)
        {
            return Result.Failure<WrappedApduCommand, SmartCardError>(
                SmartCardError.InvalidArgument("Wrapped bytes must contain at least header")
            );
        }

        return Result.Success<WrappedApduCommand, SmartCardError>(
            new WrappedApduCommand(originalCommand, wrappedBytes)
        );
    }

    /// <inheritdoc />
    public byte Cla => WrappedBytes[0];

    /// <inheritdoc />
    public byte Ins => WrappedBytes[1];

    /// <inheritdoc />
    public byte P1 => WrappedBytes[2];

    /// <inheritdoc />
    public byte P2 => WrappedBytes[3];

    /// <inheritdoc />
    public byte[] Data
    {
        get
        {
            switch (WrappedBytes.Length)
            {
                case <= 4:
                    return [];

                // Just Le byte
                case 5:
                    return [];
            }

            byte lc = WrappedBytes[4];
            switch (lc)
            {
                case 0 when WrappedBytes.Length > 6:
                {
                    // Extended length
                    int extendedLc = WrappedBytes[5] << 8 | WrappedBytes[6];
                    if (WrappedBytes.Length >= 7 + extendedLc)
                    {
                        byte[] data = new byte[extendedLc];
                        Array.Copy(WrappedBytes, 7, data, 0, extendedLc);
                        return data;
                    }
                    break;
                }
                case > 0 when WrappedBytes.Length >= 5 + lc:
                {
                    // Standard length
                    byte[] data = new byte[lc];
                    Array.Copy(WrappedBytes, 5, data, 0, lc);
                    return data;
                }
            }

            return [];
        }
    }

    /// <inheritdoc />
    public Maybe<int> ExpectedResponseLength
    {
        get
        {
            if (WrappedBytes.Length <= 4)
                return Maybe<int>.None;

            bool hasData = Data.Length > 0;

            if (hasData)
            {
                byte lc = WrappedBytes[4];
                int dataEndIndex = lc == 0 ? 7 + (WrappedBytes[5] << 8 | WrappedBytes[6]) : 5 + lc;
                if (WrappedBytes.Length > dataEndIndex)
                {
                    return Maybe<int>.From(
                        WrappedBytes[dataEndIndex] == 0 ? 256 : WrappedBytes[dataEndIndex]
                    );
                }
            }
            else if (WrappedBytes.Length == 5)
            {
                return Maybe<int>.From(WrappedBytes[4] == 0 ? 256 : WrappedBytes[4]);
            }

            return Maybe<int>.None;
        }
    }

    /// <inheritdoc />
    public bool IsExtendedLength => WrappedBytes.Length > 4 && WrappedBytes[4] == 0;

    /// <inheritdoc />
    public byte[] GetCompleteApdu()
    {
        return WrappedBytes;
    }
}
