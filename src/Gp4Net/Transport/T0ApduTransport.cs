using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Services;
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
        get { return TransportProtocol.T0; }
    }

    /// <inheritdoc />
    public int MaxCommandDataLength
    {
        get { return 255; }
    }

    /// <inheritdoc />
    public int MaxResponseDataLength
    {
        get { return 256; }
    }

    /// <inheritdoc />
    public bool SupportsExtendedLength
    {
        get { return false; }
    }

    /// <summary>
    /// Initializes a new instance of T0ApduTransport.
    /// </summary>
    public T0ApduTransport(ILogger<T0ApduTransport> logger)
    {
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<ApduResponse> TransmitAsync(
        IApduCommand command,
        ICardChannel channel,
        CancellationToken cancellationToken = default
    )
    {
        // Validate extended length support
        if (command.IsExtendedLength)
        {
            return new ApduResponse([], new Core.StatusWord(0x6A, 0x80)); // Wrong parameters P1-P2
        }

        // Build APDU according to T=0 rules using unified service
        return await ApduService.Formatting.ToBytes(command)
            .Match(
                async apdu =>
                {
                    _logger.LogDebug("T=0 Transmit: {Apdu}", BitConverter.ToString(apdu));

                    // Send command
                    byte[] response = await channel
                        .TransmitAsync(apdu, cancellationToken)
                        .ConfigureAwait(false);

                    // Handle T=0 specific response processing
                    return await ProcessResponseAsync(command, response, channel, cancellationToken)
                        .ConfigureAwait(false);
                },
                error =>
                {
                    _logger.LogError("Failed to build APDU: {Error}", error.Message);
                    return Task.FromResult(new ApduResponse([], new Core.StatusWord(0x69, 0x87))); // Wrong data
                });
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

        byte sw1 = response[^2];
        byte sw2 = response[^1];
        ushort statusWord = (ushort)(sw1 << 8 | sw2);

        byte[] data = new byte[response.Length - 2];
        if (data.Length > 0)
        {
            Array.Copy(response, 0, data, 0, data.Length);
        }

        switch (sw1)
        {
            // Handle T=0 specific status words
            case 0x61:
            {
                // More data available, send GET RESPONSE
                ApduResponse remainingData = await GetResponseAsync(sw2, channel, cancellationToken)
                    .ConfigureAwait(false);

                // Security check: Validate combined data size before allocation
                int totalLength = data.Length + remainingData.Data.Length;
                if (totalLength > Constants.Constants.Apdu.ChainLimits.MaxTotalResponseSize)
                {
                    throw new InvalidOperationException(
                        $"Combined response size ({totalLength}) exceeds maximum ({Constants.Constants.Apdu.ChainLimits.MaxTotalResponseSize})"
                    );
                }

                // Combine data
                byte[] combinedData = new byte[totalLength];
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
            case 0x6C when command.ExpectedResponseLength.HasValue:
            {
                // Wrong Le, retry with correct length
                _logger.LogDebug("Wrong Le, retrying with Le={Le}", sw2);

                ApduCommandWrapper retryCommand = new ApduCommandWrapper(command, sw2);
                return await TransmitAsync(retryCommand, channel, cancellationToken)
                    .ConfigureAwait(false);
            }
            default:
                return new ApduResponse(data, statusWord);
        }
    }

    private async Task<ApduResponse> GetResponseAsync(
        byte length,
        ICardChannel channel,
        CancellationToken cancellationToken
    )
    {
        List<byte> allData = [];
        byte currentLength = length;
        int chainCount = 0;
        int totalSize = 0;
        ushort finalStatusWord = 0;

        // Iterative approach to prevent stack overflow from malicious cards
        while (true)
        {
            // Security check: Prevent infinite loops from malicious cards
            if (chainCount >= Constants.Constants.Apdu.ChainLimits.MaxResponseChainLength)
            {
                throw new InvalidOperationException(
                    $"Maximum GET RESPONSE chain length ({Constants.Constants.Apdu.ChainLimits.MaxResponseChainLength}) exceeded"
                );
            }

            // GET RESPONSE: CLA=00 INS=C0 P1=00 P2=00 Le=currentLength
            byte[] getResponse = [0x00, 0xC0, 0x00, 0x00, currentLength];

            _logger.LogDebug(
                "T=0 GET RESPONSE for {Length} bytes (chain {ChainCount})",
                currentLength == 0 ? 256 : currentLength,
                chainCount
            );

            byte[] response = await channel
                .TransmitAsync(getResponse, cancellationToken)
                .ConfigureAwait(false);

            if (response.Length < 2)
            {
                throw new InvalidOperationException("GET RESPONSE failed");
            }

            byte sw1 = response[^2];
            byte sw2 = response[^1];
            finalStatusWord = (ushort)(sw1 << 8 | sw2);

            // Extract data portion
            int dataLength = response.Length - 2;
            if (dataLength > 0)
            {
                // Security check: Prevent memory exhaustion from excessive response data
                if (totalSize + dataLength > Constants.Constants.Apdu.ChainLimits.MaxTotalResponseSize)
                {
                    throw new InvalidOperationException(
                        $"Total response size ({totalSize + dataLength}) exceeds maximum ({Constants.Constants.Apdu.ChainLimits.MaxTotalResponseSize})"
                    );
                }

                // Add data to accumulator
                for (int i = 0; i < dataLength; i++)
                {
                    allData.Add(response[i]);
                }
                totalSize += dataLength;
            }

            // Check if more data is available
            if (sw1 == 0x61)
            {
                // Continue chain with next length
                currentLength = sw2;
                chainCount++;
            }
            else
            {
                // Chain complete
                break;
            }
        }

        return new ApduResponse([.. allData], finalStatusWord);
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
            get { return _inner.Cla; }
        }
        public byte Ins
        {
            get { return _inner.Ins; }
        }
        public byte P1
        {
            get { return _inner.P1; }
        }
        public byte P2
        {
            get { return _inner.P2; }
        }
        public byte[] Data
        {
            get { return _inner.Data; }
        }
        public Maybe<int> ExpectedResponseLength
        {
            get { return Maybe<int>.From(_newExpectedLength); }
        }
        public bool IsExtendedLength
        {
            get { return false; }
        }
    }
}
