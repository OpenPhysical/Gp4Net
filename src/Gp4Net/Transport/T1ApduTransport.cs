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
    public TransportProtocol Protocol => TransportProtocol.T1;

    /// <inheritdoc />
    public int MaxCommandDataLength => _supportsExtendedLength ? 65535 : 255;

    /// <inheritdoc />
    public int MaxResponseDataLength => _supportsExtendedLength ? 65536 : 256;

    /// <inheritdoc />
    public bool SupportsExtendedLength => _supportsExtendedLength;

    /// <summary>
    /// Initializes a new instance of T1ApduTransport.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="supportsExtendedLength">Whether extended length is supported.</param>
    public T1ApduTransport(ILogger<T1ApduTransport> logger, bool supportsExtendedLength = true)
    {
        ArgumentNullException.ThrowIfNull(logger);
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
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(channel);

        if (command.IsExtendedLength && !_supportsExtendedLength)
        {
            throw new NotSupportedException("Extended length APDUs not supported");
        }

        // Build APDU according to T=1 rules
        var apdu = BuildApdu(command);

        _logger.LogDebug("T=1 Transmit: {Apdu}", BitConverter.ToString(apdu));

        // T=1 handles chaining at the protocol level
        var response = await channel
            .TransmitAsync(apdu, cancellationToken)
            .ConfigureAwait(false);

        return ProcessResponse(response);
    }

    private static byte[] BuildApdu(IApduCommand command)
    {
        var apduList = new List<byte> { command.Cla, command.Ins, command.P1, command.P2 };

        var hasData = command.Data is { Length: > 0 };
        var expectsResponse = command.ExpectedResponseLength.HasValue;

        if (command.IsExtendedLength)
        {
            // Extended length encoding
            if (hasData && expectsResponse)
            {
                // Case 4E
                apduList.Add(0x00); // Extended length marker
                apduList.Add((byte)(command.Data!.Length >> 8));
                apduList.Add((byte)(command.Data.Length & 0xFF));
                apduList.AddRange(command.Data);

                var le = command.ExpectedResponseLength!.Value;
                if (le == 65536)
                {
                    apduList.Add(0x00);
                    apduList.Add(0x00);
                }
                else
                {
                    apduList.Add((byte)(le >> 8));
                    apduList.Add((byte)(le & 0xFF));
                }
            }
            else if (hasData)
            {
                // Case 3E
                apduList.Add(0x00);
                apduList.Add((byte)(command.Data!.Length >> 8));
                apduList.Add((byte)(command.Data.Length & 0xFF));
                apduList.AddRange(command.Data);
            }
            else if (expectsResponse)
            {
                // Case 2E
                apduList.Add(0x00);

                var le = command.ExpectedResponseLength!.Value;
                if (le == 65536)
                {
                    apduList.Add(0x00);
                    apduList.Add(0x00);
                }
                else
                {
                    apduList.Add((byte)(le >> 8));
                    apduList.Add((byte)(le & 0xFF));
                }
            }
        }
        else
        {
            // Short length encoding
            if (hasData && expectsResponse)
            {
                // Case 4S
                apduList.Add((byte)command.Data!.Length);
                apduList.AddRange(command.Data);
                apduList.Add(GetLeByte(command.ExpectedResponseLength!.Value));
            }
            else if (hasData)
            {
                // Case 3S
                apduList.Add((byte)command.Data!.Length);
                apduList.AddRange(command.Data);
            }
            else if (expectsResponse)
            {
                // Case 2S
                apduList.Add(GetLeByte(command.ExpectedResponseLength!.Value));
            }
            // Case 1: No Lc, no Le
        }

        return [.. apduList];
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