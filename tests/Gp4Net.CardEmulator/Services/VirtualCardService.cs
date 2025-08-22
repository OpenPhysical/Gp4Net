using System;
using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.Domain.Keys;
using Gp4Net.Pipeline;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Services;

/// <summary>
/// Virtual implementation of a card service for testing with emulated cards.
/// This service can be used as a drop-in replacement for WSCT-based services.
/// Implements ICardService for integration with GlobalPlatformService and provides
/// additional methods for test environment setup and CLI integration.
/// </summary>
[PublicAPI]
public class VirtualCardService : ICardService
{
    protected internal readonly VirtualReaderManager ReaderManager;
    private Maybe<VirtualCardReader> _connectedReader = Maybe<VirtualCardReader>.None;
    private Maybe<VirtualCard> _currentCard = Maybe<VirtualCard>.None;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the VirtualCardService class.
    /// </summary>
    /// <param name="readerManager">The virtual reader manager.</param>
    public VirtualCardService(VirtualReaderManager readerManager)
    {
        ReaderManager = readerManager;
    }
    
    /// <summary>
    /// Initializes a new instance with a default reader manager.
    /// </summary>
    public VirtualCardService() : this(CreateDefaultReaderManager())
    {
    }

    /// <inheritdoc />
    public IReadOnlyList<string> GetReaders()
    {
        return ReaderManager.GetReaderNames();
    }

    /// <inheritdoc />
    public bool Connect(string readerName)
    {
        if (string.IsNullOrEmpty(readerName))
            throw new ArgumentException("Reader name cannot be null or empty", nameof(readerName));

        Disconnect(); // Ensure clean state

        var reader = ReaderManager.GetReader(readerName);
        if (reader == null)
            return false;

        if (!reader.Connect())
            return false;

        _connectedReader = Maybe<VirtualCardReader>.From(reader);
        _currentCard = reader.InsertedCard is VirtualCard card 
            ? Maybe<VirtualCard>.From(card) 
            : Maybe<VirtualCard>.None;
        return true;
    }

    /// <inheritdoc />
    public void Disconnect()
    {
        _connectedReader.Execute(reader => reader.Disconnect());
        _connectedReader = Maybe<VirtualCardReader>.None;
        _currentCard = Maybe<VirtualCard>.None;
    }

    /// <inheritdoc />
    public bool IsConnected
    {
        get
        {
            return _connectedReader.Match(
                Some: reader => reader.IsConnected,
                None: () => false
            );
        }
    }

    /// <inheritdoc />
    public byte[]? GetAtr()
    {
        return _connectedReader.Match(
            Some: reader => reader.GetAtr(),
            None: () => null
        );
    }

    /// <inheritdoc />
    public CardResponse SendCommand(byte[] command)
    {
        ArgumentNullException.ThrowIfNull(command);

        if (!IsConnected)
            throw new InvalidOperationException("Card is not connected");

        var response = _connectedReader.Match(
            Some: reader => reader.TransmitCommand(command),
            None: () => throw new InvalidOperationException("Card is not connected")
        );
        return new CardResponse(response.Data, response.StatusWord);
    }

    /// <inheritdoc />
    public CardResponse SendCommand(IApduCommand command)
    {
        ArgumentNullException.ThrowIfNull(command);

        // Convert IApduCommand to byte array
        var apduBytes = new List<byte> { command.Cla, command.Ins, command.P1, command.P2 };

        if (command.Data is { Length: > 0 })
        {
            if (command.IsExtendedLength && command.Data.Length > 255)
            {
                apduBytes.Add(0x00);
                apduBytes.Add((byte)(command.Data.Length >> 8));
                apduBytes.Add((byte)(command.Data.Length & 0xFF));
            }
            else
            {
                apduBytes.Add((byte)command.Data.Length);
            }
            apduBytes.AddRange(command.Data);
        }

        if (command.ExpectedResponseLength.HasValue)
        {
            var expectedLength = command.ExpectedResponseLength.Value;
            if (command.IsExtendedLength && expectedLength > 255)
            {
                if (command.Data == null || command.Data.Length == 0)
                {
                    apduBytes.Add(0x00); // Extended length prefix if no data
                }
                apduBytes.Add((byte)(expectedLength >> 8));
                apduBytes.Add((byte)(expectedLength & 0xFF));
            }
            else
            {
                apduBytes.Add(expectedLength is 0 or 256
                    ? (byte)0x00
                    : (byte)expectedLength);
            }
        }

        return SendCommand(apduBytes.ToArray());
    }

    /// <inheritdoc />
    public bool EstablishSecureChannel(byte[] keySet, byte securityLevel)
    {
        ArgumentNullException.ThrowIfNull(keySet);

        if (!IsConnected)
            throw new InvalidOperationException("Card is not connected");

        try
        {
            // Create appropriate key set based on current card protocol
            IKeySet keys;
            var hasScp03 = _currentCard.Match(
                Some: card => HasScp03Capability(card),
                None: () => false
            );
            if (hasScp03)
            {
                keys = Scp03KeySet.Create(keySet, keySet, keySet, 0xFF).Match(
                    onSuccess: static k => k,
                    onFailure: static error => throw new InvalidOperationException($"Failed to create Scp03KeySet: {error.Message}"));
            }
            else
            {
                keys = Scp02KeySet.Create(keySet, keySet, keySet, 0xFF).Match(
                    onSuccess: static k => k,
                    onFailure: error => throw new InvalidOperationException($"Failed to create Scp02KeySet: {error.Message}"));
            }

            // Note: Functional cards use immutable configuration,
            // so key override would require creating a new card instance
            // For now, we rely on the test cryptographic service

            // Send INITIALIZE UPDATE command
            var hostChallenge = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
            var initUpdateCmd = new byte[] { 0x80, 0x50, 0x00, 0x00, 0x08 }
                .Concat(hostChallenge).ToArray();

            var initResponse = SendCommand(initUpdateCmd);
            if (!initResponse.IsSuccessful)
                return false;

            // Send EXTERNAL AUTHENTICATE command
            var extAuthCmd = new byte[] { 0x84, 0x82, securityLevel, 0x00, 0x10 }
                .Concat(new byte[16]).ToArray(); // Simplified authentication data

            var authResponse = SendCommand(extAuthCmd);
            return authResponse.IsSuccessful;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <inheritdoc />
    public bool IsSecureChannelEstablished
    {
        get
        {
            return _currentCard.Match(
                Some: card => card.IsSecureChannelEstablished,
                None: () => false
            );
        }
    }

    /// <summary>
    /// Processes an APDU command and returns a pipeline-compatible response.
    /// This method is used by the VirtualCardServiceAdapter for CLI integration.
    /// </summary>
    /// <param name="command">The APDU command to process.</param>
    /// <returns>The command response with context.</returns>
    public CommandResponse ProcessCommand(IApduCommand command)
    {
        ArgumentNullException.ThrowIfNull(command);

        if (!IsConnected)
        {
            return CommandResponse.Failure(0x6F00); // Internal error - not connected
        }

        try
        {
            // Convert IApduCommand to byte array
            byte[] commandBytes;
            switch (command)
            {
                case ICompleteApduCommand completeCommand:
                    commandBytes = completeCommand.GetCompleteApdu();
                    break;
                case BaseApduCommand baseCommand:
                    commandBytes = baseCommand.ToApdu();
                    break;
                default:
                {
                    // Manual construction for basic IApduCommand
                    var apdu = new List<byte> { command.Cla, command.Ins, command.P1, command.P2 };
                    
                    if (command.Data is { Length: > 0 })
                    {
                        apdu.Add((byte)command.Data.Length);
                        apdu.AddRange(command.Data);
                    }
                    
                    if (command.ExpectedResponseLength.HasValue)
                    {
                        var le = command.ExpectedResponseLength.Value;
                        apdu.Add(le == 256 ? (byte)0 : (byte)le);
                    }
                    
                    commandBytes = apdu.ToArray();
                    break;
                }
            }
                
            // Send to virtual card
            var response = _connectedReader.Match(
                Some: reader => reader.TransmitCommand(commandBytes),
                None: () => throw new InvalidOperationException("Card is not connected")
            );
                
            // Create CommandResponse with empty context (virtual cards don't need context)
            return new CommandResponse(
                response.Data,
                response.StatusWord,
                ImmutablePipelineContext.Empty,
                new Dictionary<string, object>
                {
                    [ResponseMetadata.TransmittedBytes] = commandBytes,
                    [ResponseMetadata.ReceivedBytes] = response.Data.Concat([
                        (byte)(response.StatusWord >> 8), 
                        (byte)(response.StatusWord & 0xFF)
                    ]).ToArray()
                });
        }
        catch (Exception ex)
        {
            return CommandResponse.Failure(0x6F00) // Internal error
                .WithMetadata("Error", ex.Message);
        }
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
        ReaderManager.AddReader(reader);

        return reader;
    }

    /// <summary>
    /// Adds a virtual reader with a dual-protocol card for testing.
    /// </summary>
    /// <param name="readerName">The name for the virtual reader.</param>
    /// <returns>The virtual reader.</returns>
    public VirtualCardReader AddVirtualDualProtocolReader(string readerName = "Virtual Dual Protocol Reader 00 00")
    {
        var reader = new VirtualCardReader(readerName);
        var dualProtocolCard = VirtualCardTestBuilder.DualProtocolCard();

        reader.InsertCard(dualProtocolCard);
        ReaderManager.AddReader(reader);

        return reader;
    }

    /// <summary>
    /// Adds a virtual reader with an SCP03-first card for testing.
    /// </summary>
    /// <param name="readerName">The name for the virtual reader.</param>
    /// <returns>The virtual reader.</returns>
    public VirtualCardReader AddVirtualScp03Reader(string readerName = "Virtual SCP03 Reader 00 00")
    {
        var reader = new VirtualCardReader(readerName);
        var scp03Card = VirtualCardTestBuilder.Scp03FirstCard();

        reader.InsertCard(scp03Card);
        ReaderManager.AddReader(reader);

        return reader;
    }

    /// <summary>
    /// Sets up a standard test environment with virtual readers and cards.
    /// </summary>
    public void SetupTestEnvironment()
    {
        // Clear existing readers
        ReaderManager.Clear();

        // Add P71 card reader (SCP02 only)
        AddVirtualP71Reader("Virtual P71 Reader 00 00");

        // Add dual-protocol card reader (SCP02 + SCP03)
        AddVirtualDualProtocolReader("Virtual Dual Protocol Reader 01 00");

        // Add SCP03-first card reader
        AddVirtualScp03Reader("Virtual SCP03 Reader 02 00");
    }

    /// <summary>
    /// Sets up a comprehensive test environment with multiple card types.
    /// </summary>
    public void SetupComprehensiveTestEnvironment()
    {
        // Clear existing readers
        ReaderManager.Clear();

        // Add various card types for comprehensive testing
        AddVirtualP71Reader("Virtual P71 Reader 00 00");
        AddVirtualDualProtocolReader("Virtual Dual Protocol Reader 01 00");
        AddVirtualScp03Reader("Virtual SCP03 Reader 02 00");

        // Add additional readers for stress testing
        var reader4 = new VirtualCardReader("Virtual Generic Reader 03 00");
        var genericCard = VirtualCardTestBuilder.GenericCard();
        reader4.InsertCard(genericCard);
        ReaderManager.AddReader(reader4);

        var reader5 = new VirtualCardReader("Virtual SCP02 Reader 04 00");
        var scp02Card = VirtualCardTestBuilder.Scp02Card();
        reader5.InsertCard(scp02Card);
        ReaderManager.AddReader(reader5);
    }

    /// <summary>
    /// Gets the virtual reader manager for advanced operations.
    /// </summary>
    /// <returns>The virtual reader manager.</returns>
    public VirtualReaderManager GetReaderManager()
    {
        return ReaderManager;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (!_disposed)
        {
            Disconnect();
            ReaderManager.Clear();
            _disposed = true;
        }
    }

    /// <summary>
    /// Creates a default reader manager with standard test cards.
    /// </summary>
    private static VirtualReaderManager CreateDefaultReaderManager()
    {
        var manager = new VirtualReaderManager();

        // Add standard test cards using functional architecture
        var p71Reader = new VirtualCardReader("Enhanced P71 SCP02 Card");
        var p71Card = VirtualCardTestBuilder.ForSecureChannelTesting(0x02);
        p71Reader.InsertCard(p71Card);
        manager.AddReader(p71Reader);

        // Create P71 card configured for SCP03
        var p71Scp03Reader = new VirtualCardReader("Enhanced P71 SCP03 Card");
        var p71Scp03Card = VirtualCardTestBuilder.ForSecureChannelTesting(0x03);
        p71Scp03Reader.InsertCard(p71Scp03Card);
        manager.AddReader(p71Scp03Reader);

        return manager;
    }

    /// <summary>
    /// Checks if the card has SCP03 capability.
    /// </summary>
    private static bool HasScp03Capability(VirtualCard card)
    {
        // Check the card configuration for SCP03 support
        return card.Configuration.DefaultScpVersion == 0x03;
    }
}