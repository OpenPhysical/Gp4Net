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

    /// <inheritdoc />
    public virtual bool IsExtendedLength
    {
        get
        {
            var dataLength = Data?.Length ?? 0;
            var responseLength = ExpectedResponseLength.GetValueOrDefault(0);

            return dataLength > ApduConstants.MaxShortLengthLc
                   || responseLength > ApduConstants.MaxShortLengthLe;
        }
    }

}