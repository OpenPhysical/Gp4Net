using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Core.Functional;
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

        // T=0 does not support extended length APDUs (check command length)
        if (apduBytes.Length > Apdu.Formats.APDU_HEADER_LENGTH + Apdu.Formats.MAX_SHORT_LENGTH_LC + 1) // 5 header + 255 data + 1 Le
        {
            _logger.LogWarning("T=0 does not support extended length APDUs");
            return Result.Failure<ApduResponse, SmartCardError>(
                SmartCardError.InvalidArgument("T=0 does not support extended length APDUs")
            );
        }
        _logger.LogDebug("T=0 Transmit: {Apdu}", BitConverter.ToString(apduBytes));

        // Send command and handle exceptions functionally
        var responseResult = await Gp4Net.Core.Functional.ResultExtensions.TryAsync<byte[], SmartCardError>(
            async () => await channel.TransmitAsync(apduBytes, cancellationToken).ConfigureAwait(false),
            ex =>
            {
                _logger.LogError(ex, "T=0 transmission failed");
                return SmartCardError.CommunicationFailed($"T=0 transmission failed: {ex.Message}");
            }
        ).ConfigureAwait(false);

        // If transmission failed, return error
        if (responseResult.IsFailure)
        {
            return Result.Failure<ApduResponse, SmartCardError>(responseResult.Error);
        }

        // Process the response
        return await ProcessResponseAsync(
            command,
            responseResult.Value,
            channel,
            apduBytes,
            cancellationToken
        ).ConfigureAwait(false);
    }

    private static byte GetLeByte(int expectedLength)
    {
        // In T=0, Le=0 means 256 bytes
        return expectedLength == 256 ? (byte)0 : (byte)expectedLength;
    }

    private async Task<Result<ApduResponse, SmartCardError>> ProcessResponseAsync(
        IApduCommand command,
        byte[] response,
        ICardChannel channel,
        byte[] originalApduBytes,
        CancellationToken cancellationToken
    )
    {
        if (response.Length < 2)
        {
            _logger.LogError("T=0 response too short: {Length} bytes", response.Length);
            return Result.Success<ApduResponse, SmartCardError>(new ApduResponse([], 0x6987)); // Wrong data
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
                    var remainingData = await GetResponseAsync(sw2, channel, cancellationToken)
                        .ConfigureAwait(false);

                    // Combine data
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

                    return Result.Success<ApduResponse, SmartCardError>(
                        new ApduResponse(combinedData, remainingData.StatusWord)
                    );
                }
            case 0x6C:
                {
                    // Wrong Le, retry with correct length
                    _logger.LogDebug("Wrong Le, retrying with Le={Le}", sw2);

                    // For T=0 retry, we need to rebuild the command with the correct Le
                    // This is a simplified approach - in practice would need to parse original command
                    if (originalApduBytes.Length >= 4)
                    {
                        var retryBytes = new byte[
                            originalApduBytes.Length >= 5 ? originalApduBytes.Length : 5
                        ];
                        Array.Copy(
                            originalApduBytes,
                            retryBytes,
                            Math.Min(4, originalApduBytes.Length)
                        );
                        if (retryBytes.Length == 5)
                        {
                            retryBytes[4] = sw2; // Set correct Le
                        }
                        var retryCommand = new WrappedApduCommand(new CommandAPDU(retryBytes));
                        return await TransmitAsync(retryCommand, channel, cancellationToken)
                            .ConfigureAwait(false);
                    }

                    // If retry failed, return original response
                    return Result.Success<ApduResponse, SmartCardError>(
                        new ApduResponse(data, statusWord)
                    );
                }
            default:
                return Result.Success<ApduResponse, SmartCardError>(
                    new ApduResponse(data, statusWord)
                );
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
                _logger.LogError(
                    "T=0 GET RESPONSE failed: response too short ({Length} bytes)",
                    response.Length
                );
                return new ApduResponse([], 0x6F00); // Unknown error
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
}
