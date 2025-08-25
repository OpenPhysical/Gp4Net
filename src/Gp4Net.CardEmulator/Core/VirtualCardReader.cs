using System;
using System.Collections.Generic;
using Gp4Net.CardEmulator.Functional;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Core;

/// <summary>
/// Emulates a smart card reader that can host virtual cards.
/// </summary>
[PublicAPI]
public class VirtualCardReader
{
    private readonly string _readerName;
    private IVirtualCard? _insertedCard;
    private bool _connected;

    /// <summary>
    /// Gets the name of the virtual reader.
    /// </summary>
    public string ReaderName
    {
        get
        {
            return _readerName;
        }
    }

    /// <summary>
    /// Gets a value indicating whether a card is present in the reader.
    /// </summary>
    public bool IsCardPresent
    {
        get
        {
            return _insertedCard != null;
        }
    }

    /// <summary>
    /// Gets a value indicating whether the reader is connected.
    /// </summary>
    public bool IsConnected
    {
        get
        {
            return _connected;
        }
    }

    /// <summary>
    /// Gets the currently inserted card, if any.
    /// </summary>
    public IVirtualCard? InsertedCard
    {
        get
        {
            return _insertedCard;
        }
    }

    /// <summary>
    /// Initializes a new instance of the VirtualCardReader class.
    /// </summary>
    /// <param name="readerName">The name of the virtual reader.</param>
    public VirtualCardReader(string readerName)
    {
        _readerName = readerName ?? throw new ArgumentNullException(nameof(readerName));
    }

    /// <summary>
    /// Inserts a virtual card into the reader.
    /// </summary>
    /// <param name="card">The virtual card to insert.</param>
    public void InsertCard(IVirtualCard card)
    {
        ArgumentNullException.ThrowIfNull(card);

        if (_insertedCard != null)
            throw new InvalidOperationException("A card is already inserted");

        _insertedCard = card;
        card.Reset();
    }

    /// <summary>
    /// Removes the virtual card from the reader.
    /// </summary>
    public void RemoveCard()
    {
        _insertedCard?.Reset();
        _insertedCard = null;
        _connected = false;
    }

    /// <summary>
    /// Connects to the card in the reader.
    /// </summary>
    /// <returns>True if connection was successful.</returns>
    public bool Connect()
    {
        if (!IsCardPresent)
            return false;

        _connected = true;
        return true;
    }

    /// <summary>
    /// Disconnects from the card.
    /// </summary>
    public void Disconnect()
    {
        _connected = false;
    }

    /// <summary>
    /// Gets the ATR of the inserted card.
    /// </summary>
    /// <returns>The ATR bytes, or null if no card is present or connected.</returns>
    public byte[]? GetAtr()
    {
        if (!IsConnected || !IsCardPresent)
            return null;

        return _insertedCard!.GetAtr();
    }

    /// <summary>
    /// Transmits an APDU command to the inserted card.
    /// </summary>
    /// <param name="command">The APDU command bytes.</param>
    /// <returns>The APDU response including status word.</returns>
    public ApduResponse TransmitCommand(byte[] command)
    {
        if (!IsConnected)
            throw new InvalidOperationException("Reader is not connected");

        if (!IsCardPresent)
            throw new InvalidOperationException("No card is present");

        return _insertedCard!.ProcessCommand(command);
    }
}

/// <summary>
/// Manages a collection of virtual card readers for testing.
/// </summary>
[PublicAPI]
public class VirtualReaderManager
{
    private readonly Dictionary<string, VirtualCardReader> _readers = new();

    /// <summary>
    /// Gets the list of available reader names.
    /// </summary>
    public IReadOnlyList<string> GetReaderNames()
    {
        return new List<string>(_readers.Keys);
    }

    /// <summary>
    /// Adds a virtual reader to the manager.
    /// </summary>
    /// <param name="reader">The virtual reader to add.</param>
    public void AddReader(VirtualCardReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);

        _readers[reader.ReaderName] = reader;
    }

    /// <summary>
    /// Removes a virtual reader from the manager.
    /// </summary>
    /// <param name="readerName">The name of the reader to remove.</param>
    public void RemoveReader(string readerName)
    {
        _readers.Remove(readerName);
    }

    /// <summary>
    /// Gets a virtual reader by name.
    /// </summary>
    /// <param name="readerName">The name of the reader.</param>
    /// <returns>The virtual reader, or null if not found.</returns>
    public VirtualCardReader? GetReader(string readerName)
    {
        _readers.TryGetValue(readerName, out var reader);
        return reader;
    }

    /// <summary>
    /// Clears all virtual readers.
    /// </summary>
    public void Clear()
    {
        foreach (var reader in _readers.Values)
        {
            reader.RemoveCard();
        }
        _readers.Clear();
    }

    /// <summary>
    /// Creates a standard test setup with a P71 Card.
    /// </summary>
    /// <returns>The name of the created reader.</returns>
    public string CreateStandardTestSetup()
    {
        const string readerName = "Virtual P71 Reader 00 00";

        var reader = new VirtualCardReader(readerName);
        var p71Card = VirtualCardTestBuilder.P71Card();

        reader.InsertCard(p71Card);
        AddReader(reader);

        return readerName;
    }
}