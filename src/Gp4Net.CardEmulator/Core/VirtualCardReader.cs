using System;
using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
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
    public UnitResult<SmartCardError> InsertCard(IVirtualCard card)
    {
        return Maybe<IVirtualCard>.From(card)
            .ToResult(SmartCardError.InvalidArgument("Card cannot be null"))
            .Bind(validCard => _insertedCard is not null
                ? Result.Failure<bool, SmartCardError>(SmartCardError.InvalidArgument("A card is already inserted"))
                : Result.Success<bool, SmartCardError>(true))
            .Tap(_ => _insertedCard = card)
            .Bind(_ => card.Reset())
;
    }

    /// <summary>
    /// Removes the virtual card from the reader.
    /// </summary>
    public UnitResult<SmartCardError> RemoveCard()
    {
        UnitResult<SmartCardError> resetResult = _insertedCard?.Reset() ?? UnitResult.Success<SmartCardError>();
        _insertedCard = null;
        _connected = false;
        return resetResult;
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
    public UnitResult<SmartCardError> Disconnect()
    {
        _connected = false;
        return UnitResult.Success<SmartCardError>();
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
    public UnitResult<SmartCardError> AddReader(VirtualCardReader reader)
    {
        return Maybe<VirtualCardReader>.From(reader)
            .ToResult(SmartCardError.InvalidArgument("Reader cannot be null"))
            .Tap(r => _readers[r.ReaderName] = r)
            .Map(_ => UnitResult.Success<SmartCardError>());
    }

    /// <summary>
    /// Removes a virtual reader from the manager.
    /// </summary>
    /// <param name="readerName">The name of the reader to remove.</param>
    public UnitResult<SmartCardError> RemoveReader(string readerName)
    {
        return Maybe<string>.From(readerName)
            .ToResult(SmartCardError.InvalidArgument("Reader name cannot be null"))
            .Tap(name => _readers.Remove(name))
            .Map(_ => UnitResult.Success<SmartCardError>());
    }

    /// <summary>
    /// Gets a virtual reader by name.
    /// </summary>
    /// <param name="readerName">The name of the reader.</param>
    /// <returns>The virtual reader, or null if not found.</returns>
    public VirtualCardReader? GetReader(string readerName)
    {
        _readers.TryGetValue(readerName, out VirtualCardReader? reader);
        return reader;
    }

    /// <summary>
    /// Clears all virtual readers.
    /// </summary>
    public UnitResult<SmartCardError> Clear()
    {
        // Remove cards from all readers and collect any errors
        IReadOnlyList<UnitResult<SmartCardError>> results = _readers.Values
            .Select(reader => reader.RemoveCard())
            .ToArray();

        UnitResult<SmartCardError> firstError = results
            .Where(result => result.IsFailure)
            .Cast<UnitResult<SmartCardError>>()
            .Aggregate(
                UnitResult.Success<SmartCardError>(),
                (first, current) => first.IsFailure ? first : current);

        _readers.Clear();
        return firstError;
    }

    /// <summary>
    /// Creates a standard test setup with a P71 Card.
    /// </summary>
    /// <returns>The name of the created reader.</returns>
    public string CreateStandardTestSetup()
    {
        const string readerName = "Virtual P71 Reader 00 00";

        VirtualCardReader reader = new VirtualCardReader(readerName);
        VirtualCard p71Card = VirtualCardTestBuilder.P71Card();

        reader.InsertCard(p71Card);
        AddReader(reader);

        return readerName;
    }
}