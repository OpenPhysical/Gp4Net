using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.Transport;

/// <summary>
/// Defines the interface for APDU transport protocols (T=0, T=1, T=CL).
/// Handles protocol-specific APDU formatting and response processing.
/// </summary>
[PublicAPI]
public interface IApduTransport
{
    /// <summary>
    /// Gets the transport protocol type.
    /// </summary>
    TransportProtocol Protocol { get; }

    /// <summary>
    /// Gets the maximum data length supported for commands.
    /// </summary>
    int MaxCommandDataLength { get; }

    /// <summary>
    /// Gets the maximum data length supported for responses.
    /// </summary>
    int MaxResponseDataLength { get; }

    /// <summary>
    /// Gets whether extended length APDUs are supported.
    /// </summary>
    bool SupportsExtendedLength { get; }

    /// <summary>
    /// Transmits a command and receives the response.
    /// Handles protocol-specific requirements such as GET RESPONSE for T=0.
    /// </summary>
    /// <param name="command">The command to transmit.</param>
    /// <param name="channel">The card channel to use.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The complete response including all chained data.</returns>
    Task<ApduResponse> TransmitAsync(
        IApduCommand command,
        ICardChannel channel,
        CancellationToken cancellationToken = default
    );
}

/// <summary>
/// Represents the transport protocol type.
/// </summary>
public enum TransportProtocol
{
    /// <summary>
    /// T=0 character-oriented protocol.
    /// </summary>
    T0,

    /// <summary>
    /// T=1 block-oriented protocol.
    /// </summary>
    T1,

    /// <summary>
    /// T=CL contactless protocol.
    /// </summary>
    Tcl,
}

/// <summary>
/// Represents an APDU command in a protocol-agnostic way.
/// </summary>
[PublicAPI]
public interface IApduCommand
{
    /// <summary>
    /// Gets the class byte.
    /// </summary>
    byte Cla { get; }

    /// <summary>
    /// Gets the instruction byte.
    /// </summary>
    byte Ins { get; }

    /// <summary>
    /// Gets the parameter 1 byte.
    /// </summary>
    byte P1 { get; }

    /// <summary>
    /// Gets the parameter 2 byte.
    /// </summary>
    byte P2 { get; }

    /// <summary>
    /// Gets the command data (never null, may be empty).
    /// </summary>
    byte[] Data { get; }

    /// <summary>
    /// Gets the expected response length (None if no response expected).
    /// 0 means maximum length (256 for short, 65536 for extended).
    /// </summary>
    Maybe<int> ExpectedResponseLength { get; }

    /// <summary>
    /// Gets whether this command uses extended length.
    /// </summary>
    bool IsExtendedLength { get; }
}

/// <summary>
/// Represents an APDU response.
/// </summary>
[PublicAPI]
public class ApduResponse
{
    /// <summary>
    /// Gets the response data (excluding status words).
    /// </summary>
    public byte[] Data { get; }

    /// <summary>
    /// Gets the status word (SW1 and SW2).
    /// </summary>
    public StatusWord StatusWord { get; }

    /// <summary>
    /// Gets SW1.
    /// </summary>
    public byte Sw1
    {
        get
        {
            return (byte)(StatusWord >> 8);
        }
    }

    /// <summary>
    /// Gets SW2.
    /// </summary>
    public byte Sw2
    {
        get
        {
            return (byte)(StatusWord & 0xFF);
        }
    }

    /// <summary>
    /// Gets whether the command was successful (SW=9000).
    /// </summary>
    public bool IsSuccess
    {
        get
        {
            return StatusWord == 0x9000;
        }
    }

    /// <summary>
    /// Initializes a new instance of ApduResponse.
    /// </summary>
    public ApduResponse(byte[] data, StatusWord statusWord)
    {
        Data = data ?? [];
        StatusWord = statusWord;
    }
}

/// <summary>
/// Interface for commands that provide complete APDU bytes.
/// </summary>
public interface ICompleteApduCommand : IApduCommand
{
    /// <summary>
    /// Gets the complete APDU bytes.
    /// </summary>
    byte[] GetCompleteApdu();
}
