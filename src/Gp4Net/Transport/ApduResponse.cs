using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.Transport;

/// <summary>
/// Represents an APDU response with data and status word for transport operations.
/// </summary>
[PublicAPI]
public sealed class ApduResponse
{
    /// <summary>
    /// Gets the response data.
    /// </summary>
    public byte[] Data { get; }

    /// <summary>
    /// Gets the status word.
    /// </summary>
    public ushort StatusWord { get; }

    /// <summary>
    /// Initializes a new instance of the ApduResponse class.
    /// </summary>
    /// <param name="data">The response data.</param>
    /// <param name="statusWord">The status word.</param>
    public ApduResponse(byte[] data, ushort statusWord)
    {
        Data = data;
        StatusWord = statusWord;
    }

    /// <summary>
    /// Gets a value indicating whether the command was successful (SW=9000).
    /// </summary>
    public bool IsSuccessful => StatusWord == 0x9000;
}