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
    Task<Result<ApduResponse, SmartCardError>> TransmitAsync(
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
