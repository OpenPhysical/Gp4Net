using System;
using System.Collections.Generic;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Services
{
    /// <summary>
    /// Interface for smart card communication services in the CardEmulator.
    /// </summary>
    [PublicAPI]
    public interface ICardService : IDisposable
    {
        /// <summary>
        /// Gets the available card readers.
        /// </summary>
        IReadOnlyList<string> GetReaders();

        /// <summary>
        /// Connects to a card in the specified reader.
        /// </summary>
        /// <param name="readerName">The reader name.</param>
        /// <returns>True if connection was successful.</returns>
        bool Connect(string readerName);

        /// <summary>
        /// Disconnects from the current card.
        /// </summary>
        void Disconnect();

        /// <summary>
        /// Gets a value indicating whether a card is connected.
        /// </summary>
        bool IsConnected { get; }

        /// <summary>
        /// Gets the ATR of the connected card.
        /// </summary>
        byte[]? GetAtr();

        /// <summary>
        /// Sends an APDU command to the card.
        /// </summary>
        /// <param name="command">The APDU command bytes.</param>
        /// <returns>The response from the card.</returns>
        CardResponse SendCommand(byte[] command);

        /// <summary>
        /// Sends an APDU command to the card.
        /// </summary>
        /// <param name="command">The APDU command.</param>
        /// <returns>The response from the card.</returns>
        CardResponse SendCommand(IApduCommand command);

        /// <summary>
        /// Establishes a secure channel with the card.
        /// </summary>
        /// <param name="keySet">The key set to use for authentication.</param>
        /// <param name="securityLevel">The security level to establish.</param>
        /// <returns>True if secure channel was established successfully.</returns>
        bool EstablishSecureChannel(byte[] keySet, byte securityLevel);

        /// <summary>
        /// Gets a value indicating whether a secure channel is established.
        /// </summary>
        bool IsSecureChannelEstablished { get; }
    }

}