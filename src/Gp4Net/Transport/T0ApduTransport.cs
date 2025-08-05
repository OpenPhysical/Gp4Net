using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Transport;

/// <summary>
/// Implements T=0 character-oriented transport protocol.
/// Handles GET RESPONSE chaining and protocol-specific requirements.
/// </summary>
[PublicAPI]
public class T0ApduTransport : IApduTransport
{
    private readonly ILogger<T0ApduTransport> _logger;

    /// <inheritdoc />
    public TransportProtocol Protocol
    {
        get
        {
            return TransportProtocol.T0;
        }
    }

    /// <inheritdoc />
    public int MaxCommandDataLength
    {
        get
        {
            return 255;
        }
    }

    /// <inheritdoc />
    public int MaxResponseDataLength
    {
        get
        {
            return 256;
        }
    }

    /// <inheritdoc />
    public bool SupportsExtendedLength
    {
        get
        {
            return false;
        }
    }

    /// <summary>
    /// Initializes a new instance of T0ApduTransport.
    /// </summary>
    public T0ApduTransport(ILogger<T0ApduTransport> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;
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

        if (command.IsExtendedLength)
        {
            throw new NotSupportedException("T=0 does not support extended length APDUs");
        }

        // Build APDU according to T=0 rules
        var apdu = BuildApdu(command);

        _logger.LogDebug("T=0 Transmit: {Apdu}", BitConverter.ToString(apdu));

        // Send command
        var response = await channel
            .TransmitAsync(apdu, cancellationToken)
            .ConfigureAwait(false);

        // Handle T=0 specific response processing
        return await ProcessResponseAsync(command, response, channel, cancellationToken)
            .ConfigureAwait(false);
    }

    private static byte[] BuildApdu(IApduCommand command)
    {
        var apduList = new List<byte> { command.Cla, command.Ins, command.P1, command.P2 };

        var hasData = command.Data is { Length: > 0 };
        var expectsResponse = command.ExpectedResponseLength.HasValue;

        if (hasData && expectsResponse)
        {
            // Case 4: Lc + Data + Le
            apduList.Add((byte)command.Data!.Length);
            apduList.AddRange(command.Data);
            apduList.Add(GetLeByte(command.ExpectedResponseLength.Value));
        }
        else if (hasData)
        {
            // Case 3: Lc + Data (no Le for T=0)
            apduList.Add((byte)command.Data!.Length);
            apduList.AddRange(command.Data);
        }
        else if (expectsResponse)
        {
            // Case 2: Le only
            apduList.Add(GetLeByte(command.ExpectedResponseLength.Value));
        }
        // Case 1: No Lc, no Le

        return [.. apduList];
    }

    private static byte GetLeByte(int expectedLength)
    {
        // In T=0, Le=0 means 256 bytes
        return expectedLength == 256 ? (byte)0 : (byte)expectedLength;
    }

    private async Task<ApduResponse> ProcessResponseAsync(
        IApduCommand command,
        byte[] response,
        ICardChannel channel,
        CancellationToken cancellationToken
    )
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

        // Handle T=0 specific status words
        if (sw1 == 0x61)
        {
            // More data available, send GET RESPONSE
            var remainingData = await GetResponseAsync(sw2, channel, cancellationToken)
                .ConfigureAwait(false);

            // Combine data
            var combinedData = new byte[data.Length + remainingData.Data.Length];
            Array.Copy(data, 0, combinedData, 0, data.Length);
            Array.Copy(
                remainingData.Data,
                0,
                combinedData,
                data.Length,
                remainingData.Data.Length
            );

            return new ApduResponse(combinedData, remainingData.StatusWord);
        }
        else if (sw1 == 0x6C && command.ExpectedResponseLength.HasValue)
        {
            // Wrong Le, retry with correct length
            _logger.LogDebug("Wrong Le, retrying with Le={Le}", sw2);

            var retryCommand = new ApduCommandWrapper(command, sw2);
            return await TransmitAsync(retryCommand, channel, cancellationToken)
                .ConfigureAwait(false);
        }

        return new ApduResponse(data, statusWord);
    }

    private async Task<ApduResponse> GetResponseAsync(
        byte length,
        ICardChannel channel,
        CancellationToken cancellationToken
    )
    {
        // GET RESPONSE: CLA=00 INS=C0 P1=00 P2=00 Le=length
        var getResponse = new byte[] { 0x00, 0xC0, 0x00, 0x00, length };

        _logger.LogDebug("T=0 GET RESPONSE for {Length} bytes", length == 0 ? 256 : length);

        var response = await channel
            .TransmitAsync(getResponse, cancellationToken)
            .ConfigureAwait(false);

        if (response.Length < 2)
        {
            throw new InvalidOperationException("GET RESPONSE failed");
        }

        var sw1 = response[response.Length - 2];
        var sw2 = response[response.Length - 1];
        var statusWord = (ushort)((sw1 << 8) | sw2);

        var data = new byte[response.Length - 2];
        if (data.Length > 0)
        {
            Array.Copy(response, 0, data, 0, data.Length);
        }

        // Check if more data is available
        if (sw1 == 0x61)
        {
            // Recursively get more data
            var moreData = await GetResponseAsync(sw2, channel, cancellationToken)
                .ConfigureAwait(false);

            var combinedData = new byte[data.Length + moreData.Data.Length];
            Array.Copy(data, 0, combinedData, 0, data.Length);
            Array.Copy(moreData.Data, 0, combinedData, data.Length, moreData.Data.Length);

            return new ApduResponse(combinedData, moreData.StatusWord);
        }

        return new ApduResponse(data, statusWord);
    }

    /// <summary>
    /// Wrapper to modify expected response length for retry.
    /// </summary>
    private class ApduCommandWrapper : IApduCommand
    {
        private readonly IApduCommand _inner;
        private readonly int _newExpectedLength;

        public ApduCommandWrapper(IApduCommand inner, int newExpectedLength)
        {
            _inner = inner;
            _newExpectedLength = newExpectedLength;
        }

        public byte Cla
        {
            get
            {
                return _inner.Cla;
            }
        }
        public byte Ins
        {
            get
            {
                return _inner.Ins;
            }
        }
        public byte P1
        {
            get
            {
                return _inner.P1;
            }
        }
        public byte P2
        {
            get
            {
                return _inner.P2;
            }
        }
        public byte[] Data
        {
            get
            {
                return _inner.Data;
            }
        }
        public Maybe<int> ExpectedResponseLength
        {
            get
            {
                return Maybe<int>.From(_newExpectedLength);
            }
        }
        public bool IsExtendedLength
        {
            get
            {
                return false;
            }
        }
    }
}