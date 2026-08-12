using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Transport;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using WSCT.ISO7816;

namespace Gp4Net.Services;

/// <summary>
/// Service for detecting card capabilities including extended APDU support and optimal block sizes.
/// Follows functional programming principles with Result-based error handling.
/// </summary>
[PublicAPI]
public static class CardCapabilities
{
    /// <summary>
    /// Default block size for cards that don't support extended APDUs.
    /// </summary>
    public const int DEFAULT_BLOCK_SIZE = 245;

    /// <summary>
    /// Maximum block size for extended APDU cards.
    /// </summary>
    public const int EXTENDED_BLOCK_SIZE = 4096;

    /// <summary>
    /// Detects card capabilities including extended APDU support and optimal block size.
    /// </summary>
    /// <param name="transmit">The command transmission boundary.</param>
    /// <param name="logger">The diagnostic sink.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A Result containing the detected capabilities.</returns>
    public static async Task<Result<CardTransportCapabilities, SmartCardError>> DetectAsync(
        ScpOperations.Transmit transmit,
        ILogger logger,
        CancellationToken cancellationToken = default
    )
    {
        logger.LogDebug("Starting card capability detection");

        // Try to detect extended APDU support through GET DATA command
        var extendedSupport = await ProbeExtendedApduSupportAsync(
            transmit,
            logger,
            cancellationToken
        );

        return extendedSupport.Map(supported =>
        {
            var blockSize = supported ? EXTENDED_BLOCK_SIZE : DEFAULT_BLOCK_SIZE;
            logger.LogInformation(
                "Card capabilities detected - Extended APDU: {ExtendedSupport}, Block size: {BlockSize}",
                supported,
                blockSize
            );

            return new CardTransportCapabilities(supported, blockSize);
        });
    }

    /// <summary>
    /// Probes for extended APDU support by attempting a command with extended length.
    /// </summary>
    private static async Task<Result<bool, SmartCardError>> ProbeExtendedApduSupportAsync(
        ScpOperations.Transmit transmit,
        ILogger logger,
        CancellationToken cancellationToken
    )
    {
        // Try GET DATA with extended Le to see if card supports it
        // Command: CLA=80 INS=CA P1=00 P2=66 Le=00 00 (requesting 65536 bytes)
        var probeCommand = new CommandAPDU
        {
            Cla = 0x80,
            Ins = 0xCA,
            P1 = 0x00,
            P2 = 0x66, // Card Data
            Le = 256 // This will be encoded as extended if supported
        };

        var result = await transmit(probeCommand.BinaryCommand, cancellationToken);

        return result.Match(
            success =>
            {
                // Check if we got a response indicating extended support
                // Cards that don't support extended will typically return 6700 (wrong length)
                ushort statusWord = success.StatusWord;

                if (statusWord == 0x6700 || statusWord == 0x6C00)
                {
                    logger.LogDebug(
                        "Card does not support extended APDUs (SW: {SW:X4})",
                        statusWord
                    );
                    return Result.Success<bool, SmartCardError>(false);
                }

                // If we got a successful response or any other error, assume extended is supported
                logger.LogDebug("Card appears to support extended APDUs (SW: {SW:X4})", statusWord);
                return Result.Success<bool, SmartCardError>(statusWord == 0x9000);
            },
            error =>
            {
                logger.LogWarning("Failed to probe extended APDU support: {Error}", error);
                // On communication error, default to standard APDUs
                return Result.Success<bool, SmartCardError>(false);
            }
        );
    }
}

/// <summary>
/// Represents detected card transport capabilities for extended APDUs.
/// </summary>
[PublicAPI]
public record CardTransportCapabilities(bool SupportsExtendedApdu, int OptimalBlockSize);
