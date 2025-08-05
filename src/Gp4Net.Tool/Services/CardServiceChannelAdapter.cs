using System;
using System.Threading;
using System.Threading.Tasks;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Adapter that implements ICardChannel using ICardService.
/// Bridges the tool's card service with the domain's transport abstraction.
/// </summary>
[PublicAPI]
public class CardServiceChannelAdapter : ICardChannel
{
    private readonly ICardService _cardService;
    private readonly TransportProtocol _protocol;

    /// <summary>
    /// Initializes a new instance of CardServiceChannelAdapter.
    /// </summary>
    /// <param name="cardService">The card service to adapt.</param>
    /// <param name="protocol">The transport protocol (defaults to T=0).</param>
    public CardServiceChannelAdapter(
        ICardService cardService,
        TransportProtocol protocol = TransportProtocol.T0
    )
    {
        _cardService = cardService ?? throw new ArgumentNullException(nameof(cardService));
        _protocol = protocol;
    }

    /// <inheritdoc />
    public async Task<byte[]> TransmitAsync(
        byte[] command,
        CancellationToken cancellationToken = default
    )
    {
        ArgumentNullException.ThrowIfNull(command);

        // Check if connected
        if (!_cardService.IsConnected)
        {
            throw new InvalidOperationException("Card is not connected");
        }

        // For now, we'll use synchronous transmission wrapped in a Task
        // In a real implementation, the underlying card service should support async
        return await Task.Run(
                () =>
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var response = _cardService.SendCommand(command);

                    // Combine data and status word
                    var fullResponse = new byte[response.Data.Length + 2];
                    Array.Copy(response.Data, 0, fullResponse, 0, response.Data.Length);
                    fullResponse[fullResponse.Length - 2] = (byte)(response.StatusWord >> 8);
                    fullResponse[fullResponse.Length - 1] = (byte)(response.StatusWord & 0xFF);

                    return fullResponse;
                },
                cancellationToken
            )
            .ConfigureAwait(false);
    }

    /// <inheritdoc />
    public TransportProtocol Protocol
    {
        get
        {
            return _protocol;
        }
    }

    /// <inheritdoc />
    public bool IsOpen
    {
        get
        {
            return _cardService.IsConnected;
        }
    }
}