using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using WSCT.ISO7816;

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
    public async Task<Result<TransportExchange, SmartCardError>> TransmitAsync(
        IApduCommand command,
        ICardChannel channel,
        CancellationToken cancellationToken = default
    )
    {
        // Build APDU bytes from IApduCommand
        var apduBytesResult = ApduBuilder.BuildApdu(Maybe<IApduCommand>.From(command));
        if (apduBytesResult.IsFailure)
        {
            return Result.Failure<TransportExchange, SmartCardError>(
                SmartCardError.InvalidArgument($"APDU build failed: {apduBytesResult.Error}")
            );
        }

        byte[] apduBytes = apduBytesResult.Value;

        // T=0 does not support extended length APDUs (check command length)
        if (
            apduBytes.Length
            > Apdu.Formats.APDU_HEADER_LENGTH + Apdu.Formats.MAX_SHORT_LENGTH_LC + 1
        ) // 5 header + 255 data + 1 Le
        {
            _logger.LogWarning("T=0 does not support extended length APDUs");
            return Result.Failure<TransportExchange, SmartCardError>(
                SmartCardError.InvalidArgument("T=0 does not support extended length APDUs")
            );
        }
        _logger.LogDebug("T=0 Transmit: {Apdu}", BitConverter.ToString(apduBytes));

        var responseResult = await channel
            .TransmitAsync(apduBytes, cancellationToken)
            .ConfigureAwait(false);

        // If transmission failed, return error
        if (responseResult.IsFailure)
        {
            return Result.Failure<TransportExchange, SmartCardError>(responseResult.Error);
        }

        // Process the response
        return await ProcessResponseAsync(
                responseResult.Value.Response,
                responseResult.Value.Channel,
                apduBytes,
                cancellationToken
            )
            .ConfigureAwait(false);
    }

    private static byte GetLeByte(int expectedLength)
    {
        // In T=0, Le=0 means 256 bytes
        return expectedLength == 256 ? (byte)0 : (byte)expectedLength;
    }

    private async Task<Result<TransportExchange, SmartCardError>> ProcessResponseAsync(
        byte[] response,
        ICardChannel channel,
        byte[] originalApduBytes,
        CancellationToken cancellationToken
    )
    {
        if (response.Length < 2)
        {
            _logger.LogError("T=0 response too short: {Length} bytes", response.Length);
            return Result.Success<TransportExchange, SmartCardError>(
                new TransportExchange(new ApduResponse([], 0x6987), channel)
            );
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
                var remainingResult = await GetResponseAsync(
                        originalApduBytes[0],
                        sw2,
                        channel,
                        cancellationToken
                    )
                    .ConfigureAwait(false);

                if (remainingResult.IsFailure)
                {
                    return Result.Failure<TransportExchange, SmartCardError>(remainingResult.Error);
                }

                var remainingData = remainingResult.Value.Response;
                int totalLength = data.Length + remainingData.Data.Length;
                byte[] combinedData = new byte[totalLength];
                Array.Copy(data, 0, combinedData, 0, data.Length);
                Array.Copy(
                    remainingData.Data,
                    0,
                    combinedData,
                    data.Length,
                    remainingData.Data.Length
                );

                return Result.Success<TransportExchange, SmartCardError>(
                    new TransportExchange(
                        new ApduResponse(combinedData, remainingData.StatusWord),
                        remainingResult.Value.Channel
                    )
                );
            }
            case 0x6C:
            {
                _logger.LogDebug("Wrong Le, retrying with Le={Le}", sw2);

                var retryBytes = CreateShortLeRetry(originalApduBytes, sw2);
                if (retryBytes.HasValue)
                {
                    var retryCommand = new WrappedApduCommand(new CommandAPDU(retryBytes.Value));
                    return await TransmitAsync(retryCommand, channel, cancellationToken)
                        .ConfigureAwait(false);
                }

                // If retry failed, return original response
                return Result.Success<TransportExchange, SmartCardError>(
                    new TransportExchange(new ApduResponse(data, statusWord), channel)
                );
            }
            default:
                return Result.Success<TransportExchange, SmartCardError>(
                    new TransportExchange(new ApduResponse(data, statusWord), channel)
                );
        }
    }

    private static Maybe<byte[]> CreateShortLeRetry(byte[] command, byte le)
    {
        // ISO/IEC 7816-4:2020 §5.6 requires the same command with SW2 as the short Le.
        if (command.Length == 4)
        {
            return Maybe<byte[]>.From([.. command, le]);
        }

        if (command.Length == 5)
        {
            byte[] retry = (byte[])command.Clone();
            retry[4] = le;
            return Maybe<byte[]>.From(retry);
        }

        int dataLength = command[4];
        if (command.Length == 5 + dataLength)
        {
            return Maybe<byte[]>.From([.. command, le]);
        }

        if (command.Length == 6 + dataLength)
        {
            byte[] retry = (byte[])command.Clone();
            retry[^1] = le;
            return Maybe<byte[]>.From(retry);
        }

        return Maybe<byte[]>.None;
    }

    private async Task<Result<TransportExchange, SmartCardError>> GetResponseAsync(
        byte cla,
        byte length,
        ICardChannel channel,
        CancellationToken cancellationToken
    )
    {
        List<byte> allData = [];
        byte currentLength = length;
        int chainCount = 0;
        ushort finalStatusWord = 0;

        // Iterative approach to prevent stack overflow from malicious cards
        while (true)
        {
            // ISO/IEC 7816-4:2020 §5.3.4 requires the same CLA throughout response chaining.
            byte[] getResponse = [cla, 0xC0, 0x00, 0x00, currentLength];

            _logger.LogDebug(
                "T=0 GET RESPONSE for {Length} bytes (chain {ChainCount})",
                currentLength == 0 ? 256 : currentLength,
                chainCount
            );

            var exchange = await channel
                .TransmitAsync(getResponse, cancellationToken)
                .ConfigureAwait(false);
            if (exchange.IsFailure)
            {
                return Result.Failure<TransportExchange, SmartCardError>(exchange.Error);
            }

            channel = exchange.Value.Channel;
            byte[] response = exchange.Value.Response;

            if (response.Length < 2)
            {
                _logger.LogError(
                    "T=0 GET RESPONSE failed: response too short ({Length} bytes)",
                    response.Length
                );
                return Result.Success<TransportExchange, SmartCardError>(
                    new TransportExchange(new ApduResponse([], 0x6F00), channel)
                );
            }

            byte sw1 = response[^2];
            byte sw2 = response[^1];
            finalStatusWord = (ushort)(sw1 << 8 | sw2);

            // Extract data portion
            int dataLength = response.Length - 2;
            if (dataLength > 0)
            {
                // Add data to accumulator
                for (int i = 0; i < dataLength; i++)
                {
                    allData.Add(response[i]);
                }
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

        return Result.Success<TransportExchange, SmartCardError>(
            new TransportExchange(new ApduResponse([.. allData], finalStatusWord), channel)
        );
    }
}
