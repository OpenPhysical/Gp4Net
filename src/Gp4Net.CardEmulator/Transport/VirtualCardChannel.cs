using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.Core;
using Gp4Net.Transport;
using JetBrains.Annotations;
using EmulatorApduResponse = Gp4Net.CardEmulator.Core.ApduResponse;

namespace Gp4Net.CardEmulator.Transport;

/// <summary>
/// Provides an ICardChannel implementation that communicates with a VirtualCard.
/// Enables virtual card testing through the standard channel interface.
/// </summary>
[PublicAPI]
public sealed class VirtualCardChannel : ICardChannel
{
    private readonly IVirtualCard _virtualCard;

    /// <summary>
    /// Gets the active transport protocol for this channel (always T=1 for virtual cards).
    /// </summary>
    public TransportProtocol Protocol => TransportProtocol.T1;

    /// <summary>
    /// Gets a value indicating whether the channel is open (always true for virtual cards).
    /// </summary>
    public bool IsOpen => true;

    /// <summary>
    /// Initializes a new instance of VirtualCardChannel.
    /// </summary>
    /// <param name="virtualCard">The virtual card to communicate with.</param>
    private VirtualCardChannel(IVirtualCard virtualCard)
    {
        _virtualCard = virtualCard;
    }

    /// <summary>
    /// Creates a VirtualCardChannel instance.
    /// </summary>
    /// <param name="virtualCard">The virtual card to wrap.</param>
    /// <returns>A result containing the channel or an error.</returns>
    public static Result<VirtualCardChannel, SmartCardError> Create(IVirtualCard virtualCard)
    {
        return Maybe
            .From(virtualCard)
            .ToResult(SmartCardError.InvalidArgument("Virtual card cannot be null"))
            .Map(card => new VirtualCardChannel(card));
    }

    /// <summary>
    /// Transmits a raw APDU command to the virtual card.
    /// </summary>
    /// <param name="command">The raw APDU command bytes.</param>
    /// <param name="cancellationToken">Cancellation token (ignored for virtual cards).</param>
    /// <returns>The raw response from the virtual card.</returns>
    public Task<Result<ChannelExchange, SmartCardError>> TransmitAsync(
        byte[] command,
        CancellationToken cancellationToken = default
    )
    {
        var result = _virtualCard.ProcessCommand(command);
        return result.Match(
            success =>
                Task.FromResult(
                    Result.Success<ChannelExchange, SmartCardError>(
                        new ChannelExchange(
                            BuildResponseBytes(success.Response),
                            new VirtualCardChannel(success.UpdatedCard)
                        )
                    )
                ),
            error =>
                Task.FromResult(
                    Result.Success<ChannelExchange, SmartCardError>(
                        new ChannelExchange(VirtualCardErrorResponse.ToBytes(error), this)
                    )
                )
        );
    }

    /// <summary>
    /// Builds response bytes from an ApduResponse.
    /// </summary>
    private static byte[] BuildResponseBytes(EmulatorApduResponse response)
    {
        // Response format: [Data] SW1 SW2
        byte[] responseBytes = new byte[response.Data.Length + 2];

        if (response.Data.Length > 0)
        {
            response.Data.CopyTo(responseBytes, 0);
        }

        responseBytes[responseBytes.Length - 2] = response.StatusWord.Sw1;
        responseBytes[responseBytes.Length - 1] = response.StatusWord.Sw2;

        return responseBytes;
    }
}
