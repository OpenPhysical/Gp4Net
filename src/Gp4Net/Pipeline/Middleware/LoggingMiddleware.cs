using System;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Pipeline;
using Gp4Net.Services;
using Gp4Net.Transport;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Pipeline.Middleware
{
    /// <summary>
    /// Middleware that logs command execution details.
    /// </summary>
    public class LoggingMiddleware : CommandMiddlewareBase
    {
        private readonly ILogger<LoggingMiddleware> _logger;
        private readonly LoggingOptions _options;

        /// <summary>
        /// Initializes a new instance of LoggingMiddleware.
        /// </summary>
        public LoggingMiddleware(ILogger<LoggingMiddleware> logger, LoggingOptions? options = null)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _options = options ?? new LoggingOptions();
        }

        /// <inheritdoc/>
        public override async Task<Result<CommandResponse, SmartCardError>> InvokeAsync(
            CommandRequest request,
            CommandDelegate next,
            CancellationToken cancellationToken = default)
        {
            var commandType = request.Command.GetType().Name;
            var requestId = Guid.NewGuid().ToString("N")[..8];
            var stopwatch = Stopwatch.StartNew();

            using (_logger.BeginScope(new { RequestId = requestId, CommandType = commandType }))
            {
                try
                {
                    // Log request
                    LogRequest(request, requestId);

                    // Execute command
                    var result = await next(request, cancellationToken);

                    stopwatch.Stop();

                    // Log response
                    LogResponse(result, stopwatch.Elapsed, requestId);

                    return result;
                }
                catch (Exception ex)
                {
                    stopwatch.Stop();
                    LogException(ex, stopwatch.Elapsed, requestId);
                    throw;
                }
            }
        }

        private void LogRequest(CommandRequest request, string requestId)
        {
            if (!_logger.IsEnabled(LogLevel.Debug))
                return;

            var logBuilder = new StringBuilder();
            logBuilder.AppendLine($"[{requestId}] Executing {request.Command.GetType().Name}");

            if (_options.LogCommandDetails)
            {
                logBuilder.AppendLine($"  CLA: {request.Command.Cla:X2}");
                logBuilder.AppendLine($"  INS: {request.Command.Ins:X2}");
                logBuilder.AppendLine($"  P1:  {request.Command.P1:X2}");
                logBuilder.AppendLine($"  P2:  {request.Command.P2:X2}");

                if (_options.LogCommandData && request.Command.Data != null)
                {
                    var data = request.Command.Data;
                    if (data.Length <= _options.MaxDataLogLength)
                    {
                        logBuilder.AppendLine($"  Data: {Convert.ToHexString(data)}");
                    }
                    else
                    {
                        logBuilder.AppendLine($"  Data: {Convert.ToHexString(data[.._options.MaxDataLogLength])}... ({data.Length} bytes)");
                    }
                }

                if (request.Command.ExpectedResponseLength.HasValue)
                {
                    logBuilder.AppendLine($"  Le: {request.Command.ExpectedResponseLength}");
                }
            }

            if (_options.LogContext)
            {
                // Log relevant context values
                var secureChannel = request.Context.Get<Domain.SecureChannelSession>(ContextKeys.SecureChannelSession);
                if (secureChannel.HasValue)
                {
                    logBuilder.AppendLine($"  Secure Channel: SCP{secureChannel.Value.ProtocolVersion:X2}");
                }

                var selectedAid = request.Context.Get<byte[]>(ContextKeys.SelectedAid);
                if (selectedAid.HasValue)
                {
                    logBuilder.AppendLine($"  Selected AID: {Convert.ToHexString(selectedAid.Value)}");
                }
            }

            _logger.LogDebug(logBuilder.ToString().TrimEnd());
        }

        private void LogResponse(Result<CommandResponse, SmartCardError> result, TimeSpan elapsed, string requestId)
        {
            if (result.IsSuccess)
            {
                LogSuccessResponse(result.Value, elapsed, requestId);
            }
            else
            {
                LogFailureResponse(result.Error, elapsed, requestId);
            }
        }

        private void LogSuccessResponse(CommandResponse response, TimeSpan elapsed, string requestId)
        {
            var level = response.IsSuccess ? LogLevel.Debug : LogLevel.Warning;

            if (!_logger.IsEnabled(level))
                return;

            var logBuilder = new StringBuilder();
            logBuilder.AppendLine($"[{requestId}] Command completed in {elapsed.TotalMilliseconds:F1}ms");
            logBuilder.AppendLine($"  SW: {response.StatusWord:X4} ({GetStatusWordDescription(response.StatusWord)})");

            if (_options.LogResponseData && response.Data.Length > 0)
            {
                if (response.Data.Length <= _options.MaxDataLogLength)
                {
                    logBuilder.AppendLine($"  Response: {Convert.ToHexString(response.Data)}");
                }
                else
                {
                    logBuilder.AppendLine($"  Response: {Convert.ToHexString(response.Data[.._options.MaxDataLogLength])}... ({response.Data.Length} bytes)");
                }
            }

            if (_options.LogMetadata && response.Metadata != null)
            {
                foreach (var (key, value) in response.Metadata)
                {
                    if (key != ResponseMetadata.TransmittedBytes && key != ResponseMetadata.ReceivedBytes)
                    {
                        logBuilder.AppendLine($"  {key}: {value}");
                    }
                }
            }

            _logger.Log(level, logBuilder.ToString().TrimEnd());
        }

        private void LogFailureResponse(SmartCardError error, TimeSpan elapsed, string requestId)
        {
            var logBuilder = new StringBuilder();
            logBuilder.AppendLine($"[{requestId}] Command failed in {elapsed.TotalMilliseconds:F1}ms");
            logBuilder.AppendLine($"  Error: {error.Code} - {error.Message}");

            if (error.StatusWord.HasValue)
            {
                logBuilder.AppendLine($"  SW: {error.StatusWord.Value:X4} ({GetStatusWordDescription(error.StatusWord.Value)})");
            }

            if (_options.LogErrorContext && error.Context != null)
            {
                foreach (var (key, value) in error.Context)
                {
                    logBuilder.AppendLine($"  {key}: {value}");
                }
            }

            _logger.LogWarning(logBuilder.ToString().TrimEnd());
        }

        private void LogException(Exception exception, TimeSpan elapsed, string requestId)
        {
            _logger.LogError(exception, 
                "[{RequestId}] Command execution failed after {ElapsedMs:F1}ms",
                requestId, elapsed.TotalMilliseconds);
        }

        private static string GetStatusWordDescription(ushort sw) => sw switch
        {
            0x9000 => "Success",
            0x6283 => "Selected file invalidated",
            0x6300 => "Authentication failed",
            0x6581 => "Memory failure",
            0x6700 => "Wrong length",
            0x6881 => "Logical channel not supported",
            0x6882 => "Secure messaging not supported",
            0x6982 => "Security status not satisfied",
            0x6983 => "Authentication method blocked",
            0x6984 => "Referenced data invalidated",
            0x6985 => "Conditions of use not satisfied",
            0x6986 => "Command not allowed",
            0x6987 => "Expected SM data objects missing",
            0x6988 => "SM data objects incorrect",
            0x6A80 => "Incorrect parameters in data field",
            0x6A81 => "Function not supported",
            0x6A82 => "File not found",
            0x6A83 => "Record not found",
            0x6A84 => "Not enough memory space",
            0x6A85 => "Lc inconsistent with TLV structure",
            0x6A86 => "Incorrect P1 P2",
            0x6A87 => "Lc inconsistent with P1 P2",
            0x6A88 => "Referenced data not found",
            0x6D00 => "INS not supported",
            0x6E00 => "CLA not supported",
            0x6F00 => "No precise diagnosis",
            _ when (sw & 0xFF00) == 0x6100 => "More data available",
            _ when (sw & 0xFF00) == 0x6C00 => "Wrong length",
            _ => "Unknown"
        };
    }

    /// <summary>
    /// Options for logging middleware.
    /// </summary>
    public class LoggingOptions
    {
        /// <summary>
        /// Whether to log command details (CLA, INS, P1, P2).
        /// </summary>
        public bool LogCommandDetails { get; set; } = true;

        /// <summary>
        /// Whether to log command data.
        /// </summary>
        public bool LogCommandData { get; set; } = true;

        /// <summary>
        /// Whether to log response data.
        /// </summary>
        public bool LogResponseData { get; set; } = true;

        /// <summary>
        /// Whether to log context information.
        /// </summary>
        public bool LogContext { get; set; } = true;

        /// <summary>
        /// Whether to log response metadata.
        /// </summary>
        public bool LogMetadata { get; set; } = true;

        /// <summary>
        /// Whether to log error context details.
        /// </summary>
        public bool LogErrorContext { get; set; } = true;

        /// <summary>
        /// Maximum length of data to log (bytes will be truncated).
        /// </summary>
        public int MaxDataLogLength { get; set; } = 64;
    }
}