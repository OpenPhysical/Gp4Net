using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Transport;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Pipeline.Middleware
{
    /// <summary>
    /// Terminal middleware that sends commands to the card via transport layer.
    /// This should be the last middleware in the pipeline.
    /// </summary>
    public class TransportMiddleware : CommandMiddlewareBase
    {
        private readonly IApduTransport _transport;
        private readonly ILogger<TransportMiddleware>? _logger;

        /// <summary>
        /// Initializes a new instance of TransportMiddleware.
        /// </summary>
        public TransportMiddleware(IApduTransport transport, ILogger<TransportMiddleware>? logger = null)
        {
            _transport = transport ?? throw new ArgumentNullException(nameof(transport));
            _logger = logger;
        }

        /// <inheritdoc/>
        public override async Task<Result<CommandResponse, SmartCardError>> InvokeAsync(
            CommandRequest request,
            CommandDelegate next,
            CancellationToken cancellationToken = default)
        {
            var stopwatch = Stopwatch.StartNew();

            try
            {
                // Get card channel from context
                var channelMaybe = request.Context.Get<ICardChannel>("CardChannel");
                if (!channelMaybe.HasValue)
                {
                    return Result.Failure<CommandResponse, SmartCardError>(
                        SmartCardError.CommunicationError("No card channel available in context"));
                }
                var channel = channelMaybe.Value;

                // Get command bytes for logging
                byte[] commandBytes = GetCommandBytes(request.Command);
                _logger?.LogDebug("Sending APDU: {APDU}", Convert.ToHexString(commandBytes));

                // Send command to card
                var (responseData, statusWord) = await SendCommandAsync(
                    request.Command,
                    channel,
                    cancellationToken);

                stopwatch.Stop();

                _logger?.LogDebug("Received response SW={SW:X4}, Data={Data}", 
                    statusWord, 
                    responseData.Length > 0 ? Convert.ToHexString(responseData) : "none");

                // Create response
                var response = new CommandResponse(
                    responseData,
                    statusWord,
                    request.Context)
                    .WithMetadata(ResponseMetadata.ExecutionTime, stopwatch.Elapsed)
                    .WithMetadata(ResponseMetadata.TransmittedBytes, commandBytes)
                    .WithMetadata(ResponseMetadata.ReceivedBytes, CombineResponseBytes(responseData, statusWord));

                // Check for errors
                if (!IsSuccessStatusWord(statusWord))
                {
                    return Result.Failure<CommandResponse, SmartCardError>(
                        SmartCardError.FromStatusWord(statusWord)
                            .WithContext("Command", request.Command.GetType().Name)
                            .WithContext("Response", response));
                }

                return Result.Success<CommandResponse, SmartCardError>(response);
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                _logger?.LogError(ex, "Failed to execute command");
                
                return Result.Failure<CommandResponse, SmartCardError>(
                    SmartCardError.CommunicationError("Failed to execute command", ex));
            }
        }

        private static byte[] GetCommandBytes(IApduCommand command)
        {
            // Build standard APDU: CLA INS P1 P2 [Lc Data] [Le]
            var buffer = new List<byte> { command.Cla, command.Ins, command.P1, command.P2 };

            // Add data if present
            if (command.Data != null && command.Data.Length > 0)
            {
                if (command.Data.Length > 255)
                {
                    // Extended length
                    buffer.Add(0x00);
                    buffer.Add((byte)(command.Data.Length >> 8));
                    buffer.Add((byte)(command.Data.Length & 0xFF));
                }
                else
                {
                    // Standard length
                    buffer.Add((byte)command.Data.Length);
                }
                buffer.AddRange(command.Data);
            }

            // Add Le if specified
            if (command.ExpectedResponseLength.HasValue)
            {
                var le = command.ExpectedResponseLength.Value;
                if (le == 0)
                {
                    buffer.Add(0x00); // Maximum length
                }
                else if (le <= 255)
                {
                    buffer.Add((byte)le);
                }
                else
                {
                    // Extended length Le
                    buffer.Add((byte)(le >> 8));
                    buffer.Add((byte)(le & 0xFF));
                }
            }

            return buffer.ToArray();
        }

        private async Task<(byte[] Data, ushort StatusWord)> SendCommandAsync(
            IApduCommand command,
            ICardChannel channel,
            CancellationToken cancellationToken)
        {
            // Send via transport
            var response = await _transport.TransmitAsync(command, channel, cancellationToken);

            // Return response data and status word
            return (response.Data, response.StatusWord);
        }

        private static bool IsSuccessStatusWord(ushort sw) =>
            sw == 0x9000 || (sw & 0xFF00) == 0x6100;

        private static byte[] CombineResponseBytes(byte[] data, ushort statusWord)
        {
            var combined = new byte[data.Length + 2];
            Array.Copy(data, 0, combined, 0, data.Length);
            combined[^2] = (byte)(statusWord >> 8);
            combined[^1] = (byte)(statusWord & 0xFF);
            return combined;
        }
    }
}