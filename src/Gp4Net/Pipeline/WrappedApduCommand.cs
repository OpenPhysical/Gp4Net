using System;
using CSharpFunctionalExtensions;
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
    /// Initializes a new instance of WrappedApduCommand.
    /// </summary>
    /// <param name="originalCommand">The original command before wrapping.</param>
    /// <param name="wrappedBytes">The secured command bytes.</param>
    public WrappedApduCommand(IApduCommand originalCommand, byte[] wrappedBytes)
    {
        OriginalCommand = originalCommand ?? throw new ArgumentNullException(nameof(originalCommand));
        WrappedBytes = wrappedBytes ?? throw new ArgumentNullException(nameof(wrappedBytes));
        
        if (wrappedBytes.Length < 4)
        {
            throw new ArgumentException("Wrapped bytes must contain at least header", nameof(wrappedBytes));
        }
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
            if (WrappedBytes.Length <= 4)
            {
                return Array.Empty<byte>();
            }

            // Just Le byte
            if (WrappedBytes.Length == 5)
            {
                return Array.Empty<byte>();
            }

            var lc = WrappedBytes[4];
            if (lc == 0 && WrappedBytes.Length > 6)
            {
                // Extended length
                var extendedLc = (WrappedBytes[5] << 8) | WrappedBytes[6];
                if (WrappedBytes.Length >= 7 + extendedLc)
                {
                    var data = new byte[extendedLc];
                    Array.Copy(WrappedBytes, 7, data, 0, extendedLc);
                    return data;
                }
            }
            else if (lc > 0 && WrappedBytes.Length >= 5 + lc)
            {
                // Standard length
                var data = new byte[lc];
                Array.Copy(WrappedBytes, 5, data, 0, lc);
                return data;
            }

            return Array.Empty<byte>();
        }
    }

    /// <inheritdoc />
    public Maybe<int> ExpectedResponseLength
    {
        get
        {
            if (WrappedBytes.Length <= 4) return Maybe<int>.None;
            
            var hasData = Data.Length > 0;
            
            if (hasData)
            {
                var lc = WrappedBytes[4];
                var dataEndIndex = lc == 0 ? 7 + ((WrappedBytes[5] << 8) | WrappedBytes[6]) : 5 + lc;
                if (WrappedBytes.Length > dataEndIndex)
                {
                    return Maybe<int>.From(WrappedBytes[dataEndIndex] == 0 ? 256 : WrappedBytes[dataEndIndex]);
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
    public byte[] GetCompleteApdu() => WrappedBytes;
}