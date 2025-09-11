using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.Core;
using Gp4Net.Transport;
using JetBrains.Annotations;
using TransportApduResponse = Gp4Net.Transport.ApduResponse;

namespace Gp4Net.CardEmulator.Transport;

/// <summary>
/// Provides an IApduTransport implementation that communicates with a VirtualCard.
/// Enables virtual card testing through the standard transport interface.
/// </summary>
[PublicAPI]
public sealed class VirtualCardTransport : IApduTransport
{
    private readonly IVirtualCard _virtualCard;

    /// <summary>
    /// Gets the transport protocol type (always T=1 for virtual cards).
    /// </summary>
    public TransportProtocol Protocol => TransportProtocol.T1;

    /// <summary>
    /// Gets the maximum command data length (virtual cards support extended length).
    /// </summary>
    public int MaxCommandDataLength => 65535;

    /// <summary>
    /// Gets the maximum response data length (virtual cards support extended length).
    /// </summary>
    public int MaxResponseDataLength => 65535;

    /// <summary>
    /// Gets whether extended length APDUs are supported (always true for virtual cards).
    /// </summary>
    public bool SupportsExtendedLength => true;

    /// <summary>
    /// Initializes a new instance of VirtualCardTransport.
    /// </summary>
    /// <param name="virtualCard">The virtual card to communicate with.</param>
    private VirtualCardTransport(IVirtualCard virtualCard)
    {
        _virtualCard = virtualCard;
    }

    /// <summary>
    /// Creates a VirtualCardTransport instance.
    /// </summary>
    /// <param name="virtualCard">The virtual card to wrap.</param>
    /// <returns>A result containing the transport or an error.</returns>
    public static Result<VirtualCardTransport, SmartCardError> Create(IVirtualCard virtualCard)
    {
        return Maybe
            .From(virtualCard)
            .ToResult(SmartCardError.InvalidArgument("Virtual card cannot be null"))
            .Map(card => new VirtualCardTransport(card));
    }

    /// <summary>
    /// Transmits a command to the virtual card and receives the response.
    /// </summary>
    /// <param name="command">The command to transmit.</param>
    /// <param name="channel">The card channel (ignored for virtual cards).</param>
    /// <param name="cancellationToken">Cancellation token (ignored for virtual cards).</param>
    /// <returns>The response from the virtual card.</returns>
    public Task<Result<TransportApduResponse, SmartCardError>> TransmitAsync(
        IApduCommand command,
        ICardChannel channel,
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(
            Result.Success<TransportApduResponse, SmartCardError>(TransmitCommand(command))
        );
    }

    /// <summary>
    /// Synchronously transmits a command to the virtual card.
    /// </summary>
    private TransportApduResponse TransmitCommand(IApduCommand command)
    {
        byte[] commandBytes = BuildApduBytes(command);
        var result = _virtualCard.ProcessCommand(commandBytes);
        return result.Match(
            success => new TransportApduResponse(success.Response.Data, success.Response.StatusWord),
            error => new TransportApduResponse([], new StatusWord(0x6F, 0x00))
        );
    }

    /// <summary>
    /// Builds APDU bytes from an IApduCommand using ApduBuilder.
    /// </summary>
    private static byte[] BuildApduBytes(IApduCommand command)
    {
        // Use ApduBuilder and handle errors by returning empty array as fallback
        // This maintains compatibility with the existing synchronous interface
        return ApduBuilder.BuildApdu(Maybe<IApduCommand>.From(command)).GetValueOrDefault([]);
    }
}
