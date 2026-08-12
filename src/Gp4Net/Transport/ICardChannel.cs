using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.Transport;

/// <summary>
/// Represents a communication channel with a smart card.
/// This is the low-level interface for sending raw APDUs.
/// </summary>
[PublicAPI]
public interface ICardChannel
{
    /// <summary>
    /// Transmits a raw APDU command to the card.
    /// </summary>
    /// <param name="command">The raw APDU command bytes.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The raw response from the card.</returns>
    Task<Result<ChannelExchange, SmartCardError>> TransmitAsync(
        byte[] command,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Gets the active transport protocol for this channel.
    /// </summary>
    TransportProtocol Protocol { get; }

    /// <summary>
    /// Gets a value indicating whether the channel is open.
    /// </summary>
    bool IsOpen { get; }
}

/// <summary>
/// Raw response bytes paired with the channel state produced by the exchange.
/// </summary>
public sealed record ChannelExchange(byte[] Response, ICardChannel Channel);
