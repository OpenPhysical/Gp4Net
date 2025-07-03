using System;
using System.Collections.Generic;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Functional;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Services
{
    /// <summary>
    /// Virtual implementation of a card service for testing with emulated cards.
    /// This service can be used as a drop-in replacement for WSCT-based services.
    /// </summary>
    [PublicAPI]
    public class VirtualCardService
    {
        protected internal readonly VirtualReaderManager _readerManager;
        private VirtualCardReader? _connectedReader;
        private bool _disposed;

        /// <summary>
        /// Gets a value indicating whether a card is connected.
        /// </summary>
        public bool IsConnected => _connectedReader?.IsConnected == true;

        /// <summary>
        /// Gets a value indicating whether a secure channel is established.
        /// </summary>
        public bool IsSecureChannelEstablished =>
            _connectedReader?.InsertedCard?.IsSecureChannelEstablished == true;

        /// <summary>
        /// Initializes a new instance of the VirtualCardService class.
        /// </summary>
        /// <param name="readerManager">The virtual reader manager.</param>
        public VirtualCardService(VirtualReaderManager? readerManager = null)
        {
            _readerManager = readerManager ?? new VirtualReaderManager();
        }

        /// <summary>
        /// Gets the available virtual card readers.
        /// </summary>
        /// <returns>The list of reader names.</returns>
        public IReadOnlyList<string> GetReaders()
        {
            return _readerManager.GetReaderNames();
        }

        /// <summary>
        /// Connects to a virtual card in the specified reader.
        /// </summary>
        /// <param name="readerName">The reader name.</param>
        /// <returns>True if connection was successful.</returns>
        public bool Connect(string readerName)
        {
            if (string.IsNullOrEmpty(readerName))
                throw new ArgumentException(
                    "Reader name cannot be null or empty",
                    nameof(readerName)
                );

            Disconnect(); // Ensure clean state

            var reader = _readerManager.GetReader(readerName);
            if (reader == null)
                return false;

            if (!reader.Connect())
                return false;

            _connectedReader = reader;
            return true;
        }

        /// <summary>
        /// Disconnects from the current virtual card.
        /// </summary>
        public void Disconnect()
        {
            _connectedReader?.Disconnect();
            _connectedReader = null;
        }

        /// <summary>
        /// Gets the ATR of the connected virtual card.
        /// </summary>
        /// <returns>The ATR bytes, or null if not connected.</returns>
        public byte[]? GetAtr()
        {
            return _connectedReader?.GetAtr();
        }

        /// <summary>
        /// Sends an APDU command to the connected virtual card.
        /// </summary>
        /// <param name="command">The APDU command bytes.</param>
        /// <returns>The response from the virtual card.</returns>
        public CardResponse SendCommand(byte[] command)
        {
            if (command == null)
                throw new ArgumentNullException(nameof(command));

            if (!IsConnected)
                throw new InvalidOperationException("Card is not connected");

            var response = _connectedReader!.TransmitCommand(command);
            return new CardResponse(response.Data, response.StatusWord);
        }

        /// <summary>
        /// Establishes a secure channel with the virtual card.
        /// </summary>
        /// <param name="keySet">The key set to use for authentication.</param>
        /// <param name="securityLevel">The security level to establish.</param>
        /// <returns>True if secure channel was established successfully.</returns>
        public bool EstablishSecureChannel(byte[] keySet, byte securityLevel)
        {
            // For the virtual card, secure channel is managed internally
            // This method would typically initiate the authentication sequence
            return IsSecureChannelEstablished;
        }

        /// <summary>
        /// Adds a virtual reader with a P71 card for testing.
        /// </summary>
        /// <param name="readerName">The name for the virtual reader.</param>
        /// <returns>The virtual reader.</returns>
        public VirtualCardReader AddVirtualP71Reader(string readerName = "Virtual P71 Reader 00 00")
        {
            var reader = new VirtualCardReader(readerName);
            var p71Card = VirtualCardTestBuilder.P71Card();

            reader.InsertCard(p71Card);
            _readerManager.AddReader(reader);

            return reader;
        }

        /// <summary>
        /// Sets up a standard test environment with virtual readers and cards.
        /// </summary>
        public void SetupTestEnvironment()
        {
            // Clear existing readers
            _readerManager.Clear();

            // Add P71 card reader
            AddVirtualP71Reader("Virtual P71 Reader 00 00");

            // Add another reader for multi-reader testing
            var reader2 = new VirtualCardReader("Virtual Test Reader 01 00");
            var p71Card2 = VirtualCardTestBuilder.P71Card();
            reader2.InsertCard(p71Card2);
            _readerManager.AddReader(reader2);
        }

        /// <summary>
        /// Gets the virtual reader manager for advanced operations.
        /// </summary>
        /// <returns>The virtual reader manager.</returns>
        public VirtualReaderManager GetReaderManager()
        {
            return _readerManager;
        }

        /// <summary>
        /// Disposes of the virtual card service.
        /// </summary>
        public void Dispose()
        {
            if (!_disposed)
            {
                Disconnect();
                _readerManager.Clear();
                _disposed = true;
            }
        }
    }

    /// <summary>
    /// Response from a virtual card command.
    /// </summary>
    [PublicAPI]
    public class CardResponse
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
        /// Gets a value indicating whether the command was successful.
        /// </summary>
        public bool IsSuccessful => StatusWord == 0x9000;

        /// <summary>
        /// Initializes a new instance of the CardResponse class.
        /// </summary>
        /// <param name="data">The response data.</param>
        /// <param name="statusWord">The status word.</param>
        public CardResponse(byte[] data, ushort statusWord)
        {
            Data = data ?? throw new ArgumentNullException(nameof(data));
            StatusWord = statusWord;
        }
    }
}
