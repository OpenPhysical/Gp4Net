using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Transport;

/// <summary>
/// Implements T=1 block-oriented transport protocol.
/// Supports extended length APDUs and command/response chaining.
/// </summary>
[PublicAPI]
public class T1ApduTransport : IApduTransport
{
    private readonly ILogger<T1ApduTransport> _logger;
    private readonly bool _supportsExtendedLength;

    /// <inheritdoc />
    public TransportProtocol Protocol
    {
        get { return TransportProtocol.T1; }
    }

    /// <inheritdoc />
    public int MaxCommandDataLength
    {
        get { return _supportsExtendedLength ? 65535 : 255; }
    }

    /// <inheritdoc />
    public int MaxResponseDataLength
    {
        get { return _supportsExtendedLength ? 65536 : 256; }
    }

    /// <inheritdoc />
    public bool SupportsExtendedLength
    {
        get { return _supportsExtendedLength; }
    }

    /// <summary>
    /// Initializes a new instance of T1ApduTransport.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="supportsExtendedLength">Whether extended length is supported.</param>
    public T1ApduTransport(ILogger<T1ApduTransport> logger, bool supportsExtendedLength = true)
    {
        _logger = logger;
        _supportsExtendedLength = supportsExtendedLength;
    }

    /// <inheritdoc />
    public async Task<Result<ApduResponse, SmartCardError>> TransmitAsync(
        IApduCommand command,
        ICardChannel channel,
        CancellationToken cancellationToken = default
    )
    {
        // Build APDU bytes from IApduCommand
        var apduBytesResult = ApduBuilder.BuildApdu(Maybe<IApduCommand>.From(command));
        if (apduBytesResult.IsFailure)
        {
            return Result.Failure<ApduResponse, SmartCardError>(
                SmartCardError.InvalidArgument($"APDU build failed: {apduBytesResult.Error}")
            );
        }

        byte[] apduBytes = apduBytesResult.Value;

        // Validate extended length support
        if (
            apduBytes.Length > Apdu.Formats.APDU_HEADER_LENGTH + Apdu.Formats.MAX_SHORT_LENGTH_LC + 1
            && !_supportsExtendedLength
        ) // 5 header + 255 data + 1 Le for short APDU
        {
            return Result.Failure<ApduResponse, SmartCardError>(
                SmartCardError.InvalidArgument(
                    "Extended length APDUs not supported by this transport"
                )
            );
        }
        _logger.LogDebug("T=1 Transmit: {Apdu}", BitConverter.ToString(apduBytes));

        // Send command and handle exceptions functionally
        var responseResult = await Gp4Net.Core.Functional.ResultExtensions.TryAsync<byte[], SmartCardError>(
            async () => await channel.TransmitAsync(apduBytes, cancellationToken).ConfigureAwait(false),
            ex =>
            {
                _logger.LogError(ex, "T=1 transmission failed");
                return SmartCardError.CommunicationFailed($"T=1 transmission failed: {ex.Message}");
            }
        ).ConfigureAwait(false);

        // If transmission failed, return error
        if (responseResult.IsFailure)
        {
            return Result.Failure<ApduResponse, SmartCardError>(responseResult.Error);
        }

        // Process the response
        return Result.Success<ApduResponse, SmartCardError>(ProcessResponse(responseResult.Value));
    }

    private static byte GetLeByte(int expectedLength)
    {
        // Le=0 means maximum (256 for short length)
        return expectedLength == 256 ? (byte)0 : (byte)expectedLength;
    }

    private static ApduResponse ProcessResponse(byte[] response)
    {
        if (response.Length < 2)
        {
            return new ApduResponse([], 0x6F00); // No precise diagnosis
        }

        byte sw1 = response[^2];
        byte sw2 = response[^1];
        ushort statusWord = (ushort)((sw1 << 8) | sw2);

        byte[] data = new byte[response.Length - 2];
        if (data.Length > 0)
        {
            Array.Copy(response, 0, data, 0, data.Length);
        }

        // T=1 handles all chaining at protocol level
        // No need for GET RESPONSE
        return new ApduResponse(data, statusWord);
    }
}
