using System;
using WSCT.Core.APDU;
using WSCT.Wrapper;

namespace Gp4Net.Tool.Services.CardCommunication
{
    /// <summary>
    /// Wrapper interface for WSCT CardChannel to enable unit testing.
    /// </summary>
    public interface ICardChannelWrapper : IDisposable
    {
        /// <summary>
        /// Connects to the smart card.
        /// </summary>
        /// <param name="shareMode">The share mode for the connection.</param>
        /// <param name="protocol">The preferred protocol.</param>
        /// <returns>Error code indicating success or failure.</returns>
        ErrorCode Connect(ShareMode shareMode, Protocol protocol);

        /// <summary>
        /// Disconnects from the smart card.
        /// </summary>
        /// <param name="disposition">What to do with the card after disconnection.</param>
        /// <returns>Error code indicating success or failure.</returns>
        ErrorCode Disconnect(Disposition disposition);

        /// <summary>
        /// Gets the current status of the card channel.
        /// </summary>
        /// <returns>The current state of the channel.</returns>
        State GetStatus();

        /// <summary>
        /// Gets an attribute from the card.
        /// </summary>
        /// <param name="attrib">The attribute to retrieve.</param>
        /// <param name="buffer">Buffer to receive the attribute value.</param>
        /// <returns>Error code indicating success or failure.</returns>
        ErrorCode GetAttrib(Attrib attrib, ref byte[] buffer);

        /// <summary>
        /// Transmits a command to the card and receives a response.
        /// </summary>
        /// <param name="command">The command to send.</param>
        /// <param name="response">The response received.</param>
        /// <returns>Error code indicating success or failure.</returns>
        ErrorCode Transmit(ICardCommand command, ICardResponse response);
    }
}
