using System;
using System.Threading;
using System.Threading.Tasks;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Pipeline;
using Gp4Net.Transport;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Pipeline.Middleware
{
    /// <summary>
    /// Middleware that handles secure channel wrapping and unwrapping of commands.
    /// </summary>
    public class SecureChannelMiddleware : CommandMiddlewareBase
    {
        private readonly ILogger<SecureChannelMiddleware>? _logger;

        /// <summary>
        /// Initializes a new instance of SecureChannelMiddleware.
        /// </summary>
        public SecureChannelMiddleware(ILogger<SecureChannelMiddleware>? logger = null)
        {
            _logger = logger;
        }

        /// <inheritdoc/>
        public override async Task<Result<CommandResponse, SmartCardError>> InvokeAsync(
            CommandRequest request,
            CommandDelegate next,
            CancellationToken cancellationToken = default)
        {
            var session = request.Context.Get<SecureChannelSession>(ContextKeys.SecureChannelSession);
            
            // If no secure channel or command doesn't require it, pass through
            if (session == null || !RequiresSecureChannel(request))
            {
                _logger?.LogTrace("Passing command through without secure channel wrapping");
                return await next(request, cancellationToken);
            }

            _logger?.LogDebug("Wrapping command with secure channel (SCP{ScpVersion:X2})", 
                session.ProtocolVersion);

            try
            {
                // Wrap the command
                var (wrappedData, expectedResponseLength) = session.WrapCommand(request.Command);
                
                // Create wrapped command - the wrappedData already includes the complete APDU
                var wrappedCommand = new WrappedCommand(wrappedData, expectedResponseLength);
                
                // Create new request with wrapped command
                var wrappedRequest = request with { Command = wrappedCommand };
                
                // Execute wrapped command
                var result = await next(wrappedRequest, cancellationToken);
                
                // Process result
                return await result.MatchAsync(
                    async success => await ProcessSuccessResponse(success, session),
                    failure => Task.FromResult(Result<CommandResponse, SmartCardError>.Fail(failure)));
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to wrap command with secure channel");
                return Result<CommandResponse, SmartCardError>.Fail(
                    SmartCardError.SecurityError("Secure channel wrapping failed", null)
                        .WithContext("Exception", ex.Message));
            }
        }

        private bool RequiresSecureChannel(CommandRequest request)
        {
            // Check command options first
            if (request.Options?.RequiresSecureChannel == false)
                return false;

            // Some commands never require secure channel (e.g., SELECT before establishing SC)
            return request.Command switch
            {
                // Add specific command types that don't require SC if needed
                _ => true
            };
        }

        private Task<Result<CommandResponse, SmartCardError>> ProcessSuccessResponse(
            CommandResponse response,
            SecureChannelSession session)
        {
            try
            {
                // Check if response needs unwrapping (R-MAC or R-ENC)
                if (session.SecurityLevel.HasRMac() || session.SecurityLevel.HasREncryption())
                {
                    _logger?.LogDebug("Unwrapping response with secure channel");
                    
                    // Combine data and SW for unwrapping
                    var fullResponse = new byte[response.Data.Length + 2];
                    Array.Copy(response.Data, 0, fullResponse, 0, response.Data.Length);
                    fullResponse[^2] = (byte)(response.StatusWord >> 8);
                    fullResponse[^1] = (byte)(response.StatusWord & 0xFF);

                    // Unwrap response
                    var unwrapped = session.UnwrapResponse(fullResponse);
                    
                    // Extract unwrapped data and SW
                    byte[] unwrappedData = Array.Empty<byte>();
                    ushort unwrappedSw = 0x6F00; // Default error SW
                    
                    if (unwrapped.Length >= 2)
                    {
                        unwrappedData = new byte[unwrapped.Length - 2];
                        Array.Copy(unwrapped, 0, unwrappedData, 0, unwrappedData.Length);
                        unwrappedSw = (ushort)((unwrapped[^2] << 8) | unwrapped[^1]);
                    }

                    // Create unwrapped response
                    var unwrappedResponse = response with
                    {
                        Data = unwrappedData,
                        StatusWord = unwrappedSw
                    };

                    // Add metadata about secure channel processing
                    unwrappedResponse = unwrappedResponse
                        .WithMetadata(ResponseMetadata.SecureChannelWrapped, true)
                        .WithMetadata("SecureChannelProtocol", $"SCP{session.ProtocolVersion:X2}");

                    return Task.FromResult(Result<CommandResponse, SmartCardError>.Ok(unwrappedResponse));
                }

                // No unwrapping needed, just add metadata
                var updatedResponse = response
                    .WithMetadata(ResponseMetadata.SecureChannelWrapped, true)
                    .WithMetadata("SecureChannelProtocol", $"SCP{session.ProtocolVersion:X2}");

                return Task.FromResult(Result<CommandResponse, SmartCardError>.Ok(updatedResponse));
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to unwrap response with secure channel");
                return Task.FromResult(Result<CommandResponse, SmartCardError>.Fail(
                    SmartCardError.SecurityError("Secure channel unwrapping failed", response.StatusWord)
                        .WithContext("Exception", ex.Message)));
            }
        }

        /// <summary>
        /// Internal command wrapper that represents a complete wrapped APDU.
        /// </summary>
        private record WrappedCommand(byte[] WrappedApdu, int? ExpectedResponseLength) : Transport.IApduCommand, ICompleteApduCommand
        {
            // These properties are not used as the wrapped APDU is complete
            public byte Cla => WrappedApdu[0];
            public byte Ins => WrappedApdu[1];
            public byte P1 => WrappedApdu[2];
            public byte P2 => WrappedApdu[3];
            
            // Return null as the wrapped APDU already contains everything
            public byte[]? Data => null;
            
            // ExpectedResponseLength is handled separately
            int? Transport.IApduCommand.ExpectedResponseLength => ExpectedResponseLength;
            
            public bool IsExtendedLength => false; // Wrapped commands handle this internally
            
            /// <summary>
            /// Gets the complete wrapped APDU bytes.
            /// </summary>
            public byte[] GetCompleteApdu() => WrappedApdu;
        }
    }

    // SecurityLevel extension methods are now in Domain/SecurityLevel.cs
}