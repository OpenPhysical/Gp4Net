using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
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
        get
        {
            return TransportProtocol.T1;
        }
    }

    /// <inheritdoc />
    public int MaxCommandDataLength
    {
        get
        {
            return _supportsExtendedLength ? 65535 : 255;
        }
    }

    /// <inheritdoc />
    public int MaxResponseDataLength
    {
        get
        {
            return _supportsExtendedLength ? 65536 : 256;
        }
    }

    /// <inheritdoc />
    public bool SupportsExtendedLength
    {
        get
        {
            return _supportsExtendedLength;
        }
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
    public async Task<ApduResponse> TransmitAsync(
        IApduCommand command,
        ICardChannel channel,
        CancellationToken cancellationToken = default
    )
    {

        if (command.IsExtendedLength && !_supportsExtendedLength)
        {
            throw new NotSupportedException("Extended length APDUs not supported");
        }

        // Build APDU according to T=1 rules
        var apdu = ApduBuilder.BuildApdu(command);

        _logger.LogDebug("T=1 Transmit: {Apdu}", BitConverter.ToString(apdu));

        // T=1 handles chaining at the protocol level
        var response = await channel
            .TransmitAsync(apdu, cancellationToken)
            .ConfigureAwait(false);

        return ProcessResponse(response);
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
            throw new InvalidOperationException("Response too short");
        }

        var sw1 = response[response.Length - 2];
        var sw2 = response[response.Length - 1];
        var statusWord = (ushort)((sw1 << 8) | sw2);

        var data = new byte[response.Length - 2];
        if (data.Length > 0)
        {
            Array.Copy(response, 0, data, 0, data.Length);
        }

        // T=1 handles all chaining at protocol level
        // No need for GET RESPONSE
        return new ApduResponse(data, statusWord);
    }
}