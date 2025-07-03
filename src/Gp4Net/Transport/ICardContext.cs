using System;

namespace Gp4Net.Transport
{
    /// <summary>
    /// Represents a PC/SC card context for managing smart card operations.
    /// </summary>
    public interface ICardContext : IDisposable
    {
        /// <summary>
        /// Establishes the card context.
        /// </summary>
        void Establish();

        /// <summary>
        /// Gets the list of available readers.
        /// </summary>
        /// <returns>Array of reader names.</returns>
        string[] GetReaders();

        /// <summary>
        /// Connects to a card in the specified reader.
        /// </summary>
        /// <param name="readerName">The reader name.</param>
        /// <param name="shareMode">The share mode.</param>
        /// <returns>A card channel for communication.</returns>
        ILegacyCardChannel Connect(string readerName, ShareMode shareMode);

        /// <summary>
        /// Releases the card context.
        /// </summary>
        void Release();
    }

    /// <summary>
    /// Legacy card channel interface (replaced by new functional ICardChannel).
    /// </summary>
    public interface ILegacyCardChannel : IDisposable
    {
        /// <summary>
        /// Gets the Answer To Reset (ATR) of the card.
        /// </summary>
        byte[] Atr { get; }

        /// <summary>
        /// Gets the active protocol.
        /// </summary>
        Protocol Protocol { get; }

        /// <summary>
        /// Transmits an APDU command to the card.
        /// </summary>
        /// <param name="command">The command bytes.</param>
        /// <returns>The response bytes.</returns>
        byte[] Transmit(byte[] command);

        /// <summary>
        /// Disconnects from the card.
        /// </summary>
        /// <param name="disposition">The card disposition.</param>
        void Disconnect(CardDisposition disposition);
    }

    /// <summary>
    /// Card sharing modes.
    /// </summary>
    public enum ShareMode
    {
        /// <summary>
        /// Exclusive access to the card.
        /// </summary>
        Exclusive,

        /// <summary>
        /// Shared access to the card.
        /// </summary>
        Shared,

        /// <summary>
        /// Direct access to the reader.
        /// </summary>
        Direct
    }

    /// <summary>
    /// Communication protocols.
    /// </summary>
    public enum Protocol
    {
        /// <summary>
        /// T=0 protocol.
        /// </summary>
        T0 = 1,

        /// <summary>
        /// T=1 protocol.
        /// </summary>
        T1 = 2,

        /// <summary>
        /// Raw protocol.
        /// </summary>
        Raw = 65536,

        /// <summary>
        /// Any available protocol.
        /// </summary>
        Any = T0 | T1
    }

    /// <summary>
    /// Card disposition on disconnect.
    /// </summary>
    public enum CardDisposition
    {
        /// <summary>
        /// Leave the card in its current state.
        /// </summary>
        LeaveCard,

        /// <summary>
        /// Reset the card.
        /// </summary>
        ResetCard,

        /// <summary>
        /// Unpower the card.
        /// </summary>
        UnpowerCard,

        /// <summary>
        /// Eject the card.
        /// </summary>
        EjectCard
    }
}