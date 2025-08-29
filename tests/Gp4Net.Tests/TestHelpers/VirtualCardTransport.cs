using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.Core;
using Gp4Net.Transport;
using JetBrains.Annotations;
using ApduResponse = Gp4Net.CardEmulator.Core.ApduResponse;

namespace Gp4Net.Tests.TestHelpers;

/// <summary>
/// APDU transport implementation for VirtualCard testing.
/// Provides a functional bridge between APDU transport interface and VirtualCard.
/// Uses functional programming patterns with Result&lt;T&gt; for error handling.
/// </summary>
[PublicAPI]
public class VirtualCardTransport : IApduTransport
{
    private readonly VirtualCard _virtualCard;

    /// <summary>
    /// Creates a VirtualCardTransport with the specified virtual card.
    /// </summary>
    /// <param name="virtualCard">The virtual card to use for APDU processing.</param>
    /// <returns>A Result containing the transport or an error.</returns>
    public static Result<VirtualCardTransport, SmartCardError> Create(VirtualCard virtualCard)
    {
        return Maybe<VirtualCard>.From(virtualCard)
            .ToResult(SmartCardError.InvalidArgument("VirtualCard cannot be null"))
            .Map(card => new VirtualCardTransport(card));
    }

    /// <summary>
    /// Private constructor - use Create method for functional instantiation.
    /// </summary>
    private VirtualCardTransport(VirtualCard virtualCard)
    {
        _virtualCard = virtualCard;
    }

    /// <summary>
    /// Gets the transport protocol type (T=1 for virtual card).
    /// </summary>
    public TransportProtocol Protocol => TransportProtocol.T1;

    /// <summary>
    /// Gets the maximum command data length (65535 for virtual card).
    /// </summary>
    public int MaxCommandDataLength => 65535;

    /// <summary>
    /// Gets the maximum response data length (65535 for virtual card).
    /// </summary>
    public int MaxResponseDataLength => 65535;

    /// <summary>
    /// Gets whether extended length APDUs are supported (true for virtual card).
    /// </summary>
    public bool SupportsExtendedLength => true;

    /// <summary>
    /// Transmits a command to the virtual card and receives the response.
    /// Uses functional error handling with Result&lt;T&gt; patterns.
    /// </summary>
    /// <param name="command">The APDU command to transmit.</param>
    /// <param name="channel">The card channel (ignored for virtual card).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The APDU response from the virtual card.</returns>
    public async Task<Gp4Net.Transport.ApduResponse> TransmitAsync(
        IApduCommand command,
        ICardChannel channel,
        CancellationToken cancellationToken = default)
    {
        var result = await Maybe<IApduCommand>.From(command)
            .ToResult(SmartCardError.InvalidArgument("Command cannot be null"))
            .Map(cmd => ProcessCommandWithVirtualCard(cmd));

        return result.Match(
            onSuccess: response => response,
            onFailure: error => new Gp4Net.Transport.ApduResponse(System.Array.Empty<byte>(), 0x6F00)); // General error
    }

    /// <summary>
    /// Processes the command using the virtual card and converts to ApduResponse.
    /// Uses pure functional approach without exceptions.
    /// </summary>
    private Gp4Net.Transport.ApduResponse ProcessCommandWithVirtualCard(IApduCommand command)
    {
        // Convert IApduCommand to byte array for virtual card
        Result<byte[], SmartCardError> apduBytesResult = ConvertCommandToBytes(command);
        
        return apduBytesResult.Match(
            apduBytes =>
            {
                // Process with virtual card
                ApduResponse cardResponse = _virtualCard.ProcessCommand(apduBytes);
                
                // Convert virtual card response to ApduResponse
                return new Gp4Net.Transport.ApduResponse(
                    data: cardResponse.Data,
                    statusWord: (StatusWord)cardResponse.StatusWord);
            },
            error => new Gp4Net.Transport.ApduResponse([], 0x6F00)); // General error
    }

    /// <summary>
    /// Converts IApduCommand to byte array using functional composition.
    /// </summary>
    private static Result<byte[], SmartCardError> ConvertCommandToBytes(IApduCommand command)
    {
        return ApduCommandExtensions.ToApduResult(command);
    }
}

/// <summary>
/// Card channel implementation for VirtualCard testing.
/// Provides a functional bridge between ICardChannel interface and VirtualCard.
/// Uses functional programming patterns with Maybe&lt;T&gt; for safe operations.
/// </summary>
[PublicAPI]
public class VirtualCardChannel : ICardChannel
{
    private readonly VirtualCard _virtualCard;

    /// <summary>
    /// Creates a VirtualCardChannel with the specified virtual card.
    /// </summary>
    /// <param name="virtualCard">The virtual card to use for channel operations.</param>
    /// <returns>A Result containing the channel or an error.</returns>
    public static Result<VirtualCardChannel, SmartCardError> Create(VirtualCard virtualCard)
    {
        return Maybe<VirtualCard>.From(virtualCard)
            .ToResult(SmartCardError.InvalidArgument("VirtualCard cannot be null"))
            .Map(card => new VirtualCardChannel(card));
    }

    /// <summary>
    /// Private constructor - use Create method for functional instantiation.
    /// </summary>
    private VirtualCardChannel(VirtualCard virtualCard)
    {
        _virtualCard = virtualCard;
    }

    /// <summary>
    /// Gets the active transport protocol (T=1 for virtual card).
    /// </summary>
    public TransportProtocol Protocol => TransportProtocol.T1;

    /// <summary>
    /// Gets whether the channel is open (always true for virtual card).
    /// </summary>
    public bool IsOpen => true;

    /// <summary>
    /// Transmits a raw APDU command to the virtual card.
    /// Uses functional error handling patterns.
    /// </summary>
    /// <param name="command">The raw APDU command bytes.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The raw response bytes from the virtual card.</returns>
    public async Task<byte[]> TransmitAsync(byte[] command, CancellationToken cancellationToken = default)
    {
        var result = await Maybe<byte[]>.From(command)
            .Where(cmd => cmd.Length > 0)
            .ToResult(SmartCardError.InvalidArgument("Command cannot be null or empty"))
            .Map(cmd => ProcessCommandWithVirtualCard(cmd));

        return result.Match(
            onSuccess: response => response,
            onFailure: error => new byte[] { 0x6F, 0x00 }); // General error status
    }

    /// <summary>
    /// Processes the raw command bytes with the virtual card.
    /// Returns the complete response including status words.
    /// </summary>
    private byte[] ProcessCommandWithVirtualCard(byte[] commandBytes)
    {
        // Process with virtual card
        ApduResponse cardResponse = _virtualCard.ProcessCommand(commandBytes);
        
        // Combine data and status words into complete response
        byte[] responseBytes = new byte[cardResponse.Data.Length + 2];
        System.Array.Copy(cardResponse.Data, 0, responseBytes, 0, cardResponse.Data.Length);
        responseBytes[cardResponse.Data.Length] = (byte)(cardResponse.StatusWord >> 8);     // SW1
        responseBytes[cardResponse.Data.Length + 1] = (byte)(cardResponse.StatusWord & 0xFF); // SW2
        
        return responseBytes;
    }
}

/// <summary>
/// Extension methods for IApduCommand to convert to byte arrays.
/// Provides functional utilities for APDU command processing.
/// </summary>
public static class ApduCommandExtensions
{
    /// <summary>
    /// Converts an IApduCommand to a complete APDU byte array using functional composition.
    /// </summary>
    /// <param name="command">The APDU command to convert.</param>
    /// <returns>A Result containing the APDU byte array or an error.</returns>
    public static Result<byte[], SmartCardError> ToApduResult(IApduCommand command)
    {
        return Maybe<IApduCommand>.From(command)
            .ToResult(SmartCardError.InvalidArgument("Command cannot be null"))
            .Bind(cmd => BuildApduBytes(cmd));
    }

    /// <summary>
    /// Builds the APDU byte array from command components using functional composition.
    /// </summary>
    private static Result<byte[], SmartCardError> BuildApduBytes(IApduCommand command)
    {
        // Get data length safely using functional patterns
        int dataLength = Maybe<byte[]>.From(command.Data).Match(
            data => data.Length,
            () => 0);
            
        bool hasData = dataLength > 0;
        
        // Handle expected response length using functional patterns
        Result<int, SmartCardError> expectedResponseResult = command.ExpectedResponseLength.Match(
            length => Result.Success<int, SmartCardError>(length),
            () => Result.Success<int, SmartCardError>(0)); // No expected response
            
        return expectedResponseResult.Map(expectedLength =>
        {
            bool hasExpectedResponse = expectedLength > 0;
            
            // Calculate lengths using functional composition
            int headerLength = 4;
            int lcLength = hasData ? (command.IsExtendedLength && dataLength > 255 ? 3 : 1) : 0;
            int leLength = hasExpectedResponse ? (command.IsExtendedLength ? 2 : 1) : 0;
            
            int totalLength = headerLength + lcLength + dataLength + leLength;
            byte[] apdu = new byte[totalLength];
            
            // Build APDU using functional composition
            int index = 0;
            
            // Header
            apdu[index++] = command.Cla;
            apdu[index++] = command.Ins;
            apdu[index++] = command.P1;
            apdu[index++] = command.P2;
            
            // Lc (command data length)
            if (hasData)
            {
                if (command.IsExtendedLength && dataLength > 255)
                {
                    apdu[index++] = 0; // Extended length marker
                    apdu[index++] = (byte)(dataLength >> 8);
                    apdu[index++] = (byte)(dataLength & 0xFF);
                }
                else
                {
                    apdu[index++] = (byte)dataLength;
                }
            }
            
            // Data
            if (hasData)
            {
                System.Array.Copy(command.Data, 0, apdu, index, dataLength);
                index += dataLength;
            }
            
            // Le (expected response length)
            if (hasExpectedResponse)
            {
                if (command.IsExtendedLength)
                {
                    if (expectedLength == 0 || expectedLength == 65536)
                    {
                        apdu[index++] = 0x00;
                        apdu[index++] = 0x00;
                    }
                    else
                    {
                        apdu[index++] = (byte)(expectedLength >> 8);
                        apdu[index++] = (byte)(expectedLength & 0xFF);
                    }
                }
                else
                {
                    apdu[index++] = expectedLength == 0 || expectedLength == 256 ? (byte)0 : (byte)expectedLength;
                }
            }
            
            return apdu;
        });
    }
}