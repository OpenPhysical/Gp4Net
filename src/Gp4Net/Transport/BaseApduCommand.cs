using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using JetBrains.Annotations;

namespace Gp4Net.Transport;

/// <summary>
/// Base implementation of IApduCommand providing common functionality.
/// </summary>
[PublicAPI]
public abstract class BaseApduCommand : IApduCommand
{
    /// <inheritdoc />
    public abstract byte Cla { get; }

    /// <inheritdoc />
    public abstract byte Ins { get; }

    /// <inheritdoc />
    public abstract byte P1 { get; }

    /// <inheritdoc />
    public abstract byte P2 { get; }

    /// <inheritdoc />
    public abstract byte[] Data { get; }

    /// <inheritdoc />
    public abstract Maybe<int> ExpectedResponseLength { get; }

    /// <summary>
    /// Gets the Lc (length of command data) byte.
    /// </summary>
    public virtual byte Lc
    {
        get
        {
            int dataLength = Maybe<byte[]>.From(Data).Match(
                Some: data => data.Length,
                None: () => 0);
            return dataLength > 255 ? (byte)0 : (byte)dataLength;
        }
    }

    /// <inheritdoc />
    public virtual bool IsExtendedLength
    {
        get
        {
            int dataLength = Maybe<byte[]>.From(Data).Match(
                Some: data => data.Length,
                None: () => 0);
            int responseLength = ExpectedResponseLength.Match(
                Some: length => length,
                None: () => 0);

            return dataLength > ApduConstants.MaxShortLengthLc
                   || responseLength > ApduConstants.MaxShortLengthLe;
        }
    }

}