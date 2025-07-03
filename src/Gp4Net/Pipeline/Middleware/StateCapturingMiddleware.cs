using System;
using System.Threading;
using System.Threading.Tasks;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Pipeline;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Pipeline.Middleware
{
    /// <summary>
    /// Middleware that captures state information from command responses.
    /// </summary>
    public class StateCapturingMiddleware : CommandMiddlewareBase
    {
        private readonly ILogger<StateCapturingMiddleware>? _logger;

        /// <summary>
        /// Initializes a new instance of StateCapturingMiddleware.
        /// </summary>
        public StateCapturingMiddleware(ILogger<StateCapturingMiddleware>? logger = null)
        {
            _logger = logger;
        }

        /// <inheritdoc/>
        public override async Task<Result<CommandResponse, SmartCardError>> InvokeAsync(
            CommandRequest request,
            CommandDelegate next,
            CancellationToken cancellationToken = default)
        {
            // Execute the command
            var result = await next(request, cancellationToken);

            // Process successful responses to capture state
            return await result.MatchAsync(
                async success => await CaptureStateFromResponse(request, success),
                failure => Task.FromResult(Result<CommandResponse, SmartCardError>.Fail(failure)));
        }

        private async Task<Result<CommandResponse, SmartCardError>> CaptureStateFromResponse(
            CommandRequest request,
            CommandResponse response)
        {
            try
            {
                var updatedContext = response.UpdatedContext;

                // Capture state based on command type
                updatedContext = request.Command switch
                {
                    SelectCommand select => CaptureSelectState(select, response, updatedContext),
                    InitializeUpdateCommand => CaptureInitializeUpdateState(response, updatedContext),
                    GetStatusCommand => CaptureGetStatusState(response, updatedContext),
                    GetDataCommand getData => CaptureGetDataState(getData, response, updatedContext),
                    _ => updatedContext
                };

                // Update response with new context if changed
                if (!ReferenceEquals(updatedContext, response.UpdatedContext))
                {
                    _logger?.LogDebug("State captured from {CommandType} response", 
                        request.Command.GetType().Name);
                    
                    return Result<CommandResponse, SmartCardError>.Ok(
                        response.WithContext(updatedContext));
                }

                return Result<CommandResponse, SmartCardError>.Ok(response);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to capture state from response");
                // Don't fail the command, just return the original response
                return Result<CommandResponse, SmartCardError>.Ok(response);
            }
        }

        private ICommandContext CaptureSelectState(
            SelectCommand command,
            CommandResponse response,
            ICommandContext context)
        {
            if (!response.IsSuccess || response.Data.Length == 0)
                return context;

            // Capture selected AID
            var selectedAid = command.Aid;
            context = context.With(ContextKeys.SelectedAid, selectedAid);

            // If selecting empty AID (ISD), capture the actual ISD AID from response
            if ((selectedAid == null || selectedAid.Length == 0) && response.Data.Length >= 2)
            {
                // Parse FCI template to extract actual ISD AID
                var isdAid = ExtractAidFromFci(response.Data);
                if (isdAid != null)
                {
                    _logger?.LogDebug("Captured ISD AID: {AID}", Convert.ToHexString(isdAid));
                    context = context.With(ContextKeys.IssuerSecurityDomainAid, isdAid);
                }
            }

            return context;
        }

        private ICommandContext CaptureInitializeUpdateState(
            CommandResponse response,
            ICommandContext context)
        {
            if (!response.IsSuccess || response.Data.Length < 28)
                return context;

            // Capture card challenge and other session data
            var cardChallenge = new byte[8];
            Array.Copy(response.Data, 12, cardChallenge, 0, 8);
            context = context.With(ContextKeys.CardChallenge, cardChallenge);

            // Capture SCP version
            var scpVersion = response.Data[11];
            context = context.With(ContextKeys.SecureChannelProtocol, scpVersion);

            return context;
        }

        private ICommandContext CaptureGetStatusState(
            CommandResponse response,
            ICommandContext context)
        {
            if (!response.IsSuccess || response.Data.Length == 0)
                return context;

            // TODO: Parse application/domain status information
            // This would involve TLV parsing of the response data
            
            return context;
        }

        private ICommandContext CaptureGetDataState(
            GetDataCommand command,
            CommandResponse response,
            ICommandContext context)
        {
            if (!response.IsSuccess || response.Data.Length == 0)
                return context;

            // Capture specific data based on tag
            return command.DataObjectIdentifier switch
            {
                0x9F7F => context.With(ContextKeys.CardProductionLifeCycleData, response.Data),
                0x0066 => context.With(ContextKeys.CardData, response.Data),
                0x00E0 => context.With(ContextKeys.KeyInformationTemplate, response.Data),
                _ => context
            };
        }

        private byte[]? ExtractAidFromFci(byte[] fciData)
        {
            try
            {
                // Simple FCI parsing to extract AID
                // FCI is typically: 6F xx 84 yy AID ...
                if (fciData.Length < 4 || fciData[0] != 0x6F)
                    return null;

                var offset = 2; // Skip tag and length
                while (offset < fciData.Length - 2)
                {
                    var tag = fciData[offset];
                    var length = fciData[offset + 1];

                    if (tag == 0x84 && length > 0 && offset + 2 + length <= fciData.Length)
                    {
                        // Found AID tag
                        var aid = new byte[length];
                        Array.Copy(fciData, offset + 2, aid, 0, length);
                        return aid;
                    }

                    offset += 2 + length;
                }

                return null;
            }
            catch
            {
                return null;
            }
        }
    }

    // ContextKeys are now centralized in Pipeline/ContextKeys.cs
}