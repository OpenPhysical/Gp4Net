using System.Collections.Generic;
using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Core;

/// <summary>
/// Emulates a smart card reader that can host virtual cards.
/// </summary>
[PublicAPI]
public class VirtualCardReader
{
    private readonly string _readerName;
    private readonly Maybe<IVirtualCard> _insertedCard;
    private readonly bool _connected;

    /// <summary>
    /// Gets the name of the virtual reader.
    /// </summary>
    public string ReaderName
    {
        get { return _readerName; }
    }

    /// <summary>
    /// Gets a value indicating whether a card is present in the reader.
    /// </summary>
    public bool IsCardPresent => _insertedCard.HasValue;

    /// <summary>
    /// Gets a value indicating whether the reader is connected.
    /// </summary>
    public bool IsConnected => _connected;

    /// <summary>
    /// Gets the currently inserted card, if any.
    /// </summary>
    public Maybe<IVirtualCard> InsertedCard => _insertedCard;

    /// <summary>
    /// Initializes a new instance of the VirtualCardReader class.
    /// </summary>
    /// <param name="readerName">The name of the virtual reader.</param>
    /// <param name="insertedCard">The currently inserted card, if any.</param>
    /// <param name="connected">Whether the reader is connected.</param>
    public VirtualCardReader(string readerName, Maybe<IVirtualCard> insertedCard, bool connected)
    {
        _readerName = readerName;
        _insertedCard = insertedCard;
        _connected = connected;
    }

    /// <summary>
    /// Creates a new virtual card reader.
    /// </summary>
    /// <param name="readerName">The name of the virtual reader.</param>
    /// <returns>A new virtual card reader instance, or an error.</returns>
    public static Result<VirtualCardReader, SmartCardError> Create(string readerName)
    {
        return Maybe
            .From(readerName)
            .ToResult(SmartCardError.InvalidArgument("Reader name cannot be null"))
            .Map(validName => new VirtualCardReader(validName, Maybe<IVirtualCard>.None, false));
    }

    /// <summary>
    /// Creates a new reader instance with the card inserted.
    /// Returns a new VirtualCardReader instance with the card - functional approach.
    /// </summary>
    /// <param name="card">The virtual card to insert.</param>
    /// <returns>A new reader instance with the card inserted, or an error.</returns>
    public Result<VirtualCardReader, SmartCardError> WithCard(IVirtualCard card)
    {
        return Maybe<IVirtualCard>
            .From(card)
            .ToResult(SmartCardError.InvalidArgument("Card cannot be null"))
            .Bind(validCard =>
                _insertedCard.HasValue
                    ? Result.Failure<IVirtualCard, SmartCardError>(
                        SmartCardError.InvalidArgument("A card is already inserted")
                    )
                    : Result.Success<IVirtualCard, SmartCardError>(validCard)
            )
            .Map(validCard => new VirtualCardReader(
                _readerName,
                Maybe<IVirtualCard>.From(validCard),
                _connected
            ));
    }

    /// <summary>
    /// Creates a new reader instance without a card.
    /// Returns a new VirtualCardReader instance with no card - functional approach.
    /// </summary>
    /// <returns>A new reader instance with no card.</returns>
    public VirtualCardReader WithoutCard()
    {
        return new VirtualCardReader(_readerName, Maybe<IVirtualCard>.None, false);
    }

    /// <summary>
    /// Creates a new reader instance in connected state.
    /// Returns a new VirtualCardReader instance with connection established - functional approach.
    /// </summary>
    /// <returns>A new reader instance in connected state, or an error if no card present.</returns>
    public Result<VirtualCardReader, SmartCardError> Connected()
    {
        return IsCardPresent
            ? Result.Success<VirtualCardReader, SmartCardError>(
                new VirtualCardReader(_readerName, _insertedCard, true)
            )
            : Result.Failure<VirtualCardReader, SmartCardError>(
                SmartCardError.InvalidArgument("No card present to connect to")
            );
    }

    /// <summary>
    /// Creates a new reader instance in disconnected state.
    /// Returns a new VirtualCardReader instance with connection closed - functional approach.
    /// </summary>
    /// <returns>A new reader instance in disconnected state.</returns>
    public VirtualCardReader Disconnected()
    {
        return new VirtualCardReader(_readerName, _insertedCard, false);
    }

    /// <summary>
    /// Gets the ATR of the inserted card.
    /// </summary>
    /// <returns>The ATR bytes, or error if no card is present or connected.</returns>
    public Result<byte[], SmartCardError> GetAtr()
    {
        return (!IsConnected || !IsCardPresent)
            ? Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("Reader not connected or no card present")
            )
            : _insertedCard.Match(
                card => Result.Success<byte[], SmartCardError>(card.GetAtr()),
                () =>
                    Result.Failure<byte[], SmartCardError>(
                        SmartCardError.InvalidArgument("No card present")
                    )
            );
    }

    /// <summary>
    /// Transmits an APDU command to the inserted card.
    /// </summary>
    /// <param name="command">The APDU command bytes.</param>
    /// <returns>The APDU response including status word, or error.</returns>
    public Result<ApduResponse, SmartCardError> TransmitCommand(byte[] command)
    {
        return Maybe<byte[]>
            .From(command)
            .ToResult(SmartCardError.InvalidArgument("Command cannot be null"))
            .Bind(validCommand =>
                !IsConnected
                    ? Result.Failure<ApduResponse, SmartCardError>(
                        SmartCardError.InvalidArgument("Reader is not connected")
                    )
                    : !IsCardPresent
                        ? Result.Failure<ApduResponse, SmartCardError>(
                            SmartCardError.InvalidArgument("No card is present")
                        )
                        : _insertedCard.Match(
                            card =>
                                card.ProcessCommand(validCommand).Map(result => result.Response),
                            () =>
                                Result.Failure<ApduResponse, SmartCardError>(
                                    SmartCardError.InvalidArgument("No card present")
                                )
                        )
            );
    }
}

/// <summary>
/// Builder for constructing immutable VirtualReaders instances.
/// Allows mutation during construction, produces immutable manager.
/// </summary>
[PublicAPI]
public class VirtualReaderManagerBuilder
{
    private readonly Dictionary<string, VirtualCardReader> _readers = new();

    /// <summary>
    /// Adds a virtual reader to the builder.
    /// </summary>
    /// <param name="reader">The virtual reader to add.</param>
    /// <returns>Result containing this builder for fluent chaining.</returns>
    public Result<VirtualReaderManagerBuilder, SmartCardError> WithReader(VirtualCardReader reader)
    {
        return Maybe<VirtualCardReader>
            .From(reader)
            .ToResult(SmartCardError.InvalidArgument("Invalid Reader"))
            .Map(r =>
            {
                _readers[r.ReaderName] = r;
                return this;
            });
    }

    /// <summary>
    /// Adds a P71 virtual reader with the specified name.
    /// </summary>
    /// <param name="readerName">The name for the P71 reader.</param>
    /// <returns>Result containing this builder for fluent chaining.</returns>
    public Result<VirtualReaderManagerBuilder, SmartCardError> WithP71Reader(string readerName)
    {
        return CardConfiguration
            .P71()
            .Bind(config =>
                Maybe<VirtualCard>
                    .From(VirtualCardTestBuilder.CreateWithSecureRng(config))
                    .ToResult(SmartCardError.InvalidData("Failed to create virtual card"))
            )
            .Bind(p71Card =>
                VirtualCardReader.Create(readerName).Bind(reader => reader.WithCard(p71Card))
            )
            .Bind(readerWithCard => WithReader(readerWithCard));
    }

    /// <summary>
    /// Builds an immutable VirtualReaders from the accumulated readers.
    /// </summary>
    /// <returns>Immutable VirtualReaders instance.</returns>
    public VirtualReaders Build()
    {
        return new VirtualReaders(_readers.ToImmutableDictionary());
    }
}

/// <summary>
/// Manages a collection of virtual card readers.
/// Immutable once constructed - use VirtualReaderManagerBuilder to create instances.
/// </summary>
[PublicAPI]
public class VirtualReaders
{
    private readonly ImmutableDictionary<string, VirtualCardReader> _readers;

    /// <summary>
    /// Initializes a new instance with an empty reader collection.
    /// </summary>
    public VirtualReaders()
        : this(ImmutableDictionary<string, VirtualCardReader>.Empty) { }

    /// <summary>
    /// Internal constructor for builder use.
    /// </summary>
    /// <param name="readers">The immutable dictionary of readers.</param>
    internal VirtualReaders(ImmutableDictionary<string, VirtualCardReader> readers)
    {
        _readers = readers;
    }

    /// <summary>
    /// Gets the list of available reader names.
    /// </summary>
    /// <returns>Read-only list of reader names.</returns>
    public IReadOnlyList<string> GetReaderNames()
    {
        return _readers.Keys.ToImmutableList();
    }

    /// <summary>
    /// Gets a virtual reader by name.
    /// </summary>
    /// <param name="readerName">The name of the reader.</param>
    /// <returns>The virtual reader if found, or None if not found.</returns>
    public Maybe<VirtualCardReader> GetReader(string readerName)
    {
        return _readers.TryGetValue(readerName, out var reader)
            ? Maybe<VirtualCardReader>.From(reader)
            : Maybe<VirtualCardReader>.None;
    }
}
