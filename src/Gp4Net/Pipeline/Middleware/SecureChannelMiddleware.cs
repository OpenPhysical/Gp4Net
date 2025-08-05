using System;
using System.Collections.Immutable;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Security;
using Gp4Net.Transport;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Pipeline.Middleware;

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
        var session = request.Context.Get<SecureChannelState>(ContextKeys.SecureChannelSession);
            
        // If no secure channel or command doesn't require it, pass through
        if (!session.HasValue || !RequiresSecureChannel(request))
        {
            _logger?.LogTrace("Passing command through without secure channel wrapping");
            return await next(request, cancellationToken);
        }

        var secureSession = session.Value;
        _logger?.LogDebug("Wrapping command with secure channel (SCP{ScpVersion:X2})", 
            secureSession.ProtocolVersion);

        try
        {
            // Use functional security processors based on protocol version
            var wrapResult = secureSession.ProtocolVersion switch
            {
                0x02 => WrapCommandWithScp02(request.Command, secureSession),
                0x03 => WrapCommandWithScp03(request.Command, secureSession),
                _ => Result.Failure<(byte[] wrappedData, int? expectedResponseLength, SecureChannelState newState), SmartCardError>(
                    SmartCardError.InvalidArgument($"Unsupported protocol version: {secureSession.ProtocolVersion:X2}"))
            };
            
            if (wrapResult.IsFailure)
            {
                return Result.Failure<CommandResponse, SmartCardError>(wrapResult.Error);
            }
                
            var (wrappedData, expectedResponseLength, newState) = wrapResult.Value;
                
            // Create wrapped command - the wrappedData already includes the complete APDU
            var wrappedCommand = new WrappedCommand(wrappedData, expectedResponseLength);
                
            // Create new request with wrapped command
            var wrappedRequest = request with { Command = wrappedCommand };
                
            // Execute wrapped command
            var result = await next(wrappedRequest, cancellationToken);
                
            // Process result
            if (result.IsSuccess)
            {
                return await ProcessSuccessResponse(result.Value, secureSession);
            }
            else
            {
                return Result.Failure<CommandResponse, SmartCardError>(result.Error);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to wrap command with secure channel");
            return Result.Failure<CommandResponse, SmartCardError>(
                SmartCardError.SecurityError("Secure channel wrapping failed", Maybe<ushort>.None)
                    .WithContext("Exception", ex.Message));
        }
    }

    private static bool RequiresSecureChannel(CommandRequest request)
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
        SecureChannelState session)
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

                // Use functional security processors for response processing
                var unwrapResult = session.ProtocolVersion switch
                {
                    0x02 => ProcessResponseWithScp02(fullResponse, session),
                    0x03 => ProcessResponseWithScp03(fullResponse, session),
                    _ => Result.Failure<(byte[] processedResponse, SecureChannelState newState), SmartCardError>(
                        SmartCardError.InvalidArgument($"Unsupported protocol version: {session.ProtocolVersion:X2}"))
                };
                
                if (unwrapResult.IsFailure)
                {
                    return Task.FromResult(Result.Failure<CommandResponse, SmartCardError>(unwrapResult.Error));
                }
                    
                var (unwrapped, _) = unwrapResult.Value;
                    
                // Extract unwrapped data and SW
                var unwrappedData = Array.Empty<byte>();
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

                return Task.FromResult(Result.Success<CommandResponse, SmartCardError>(unwrappedResponse));
            }

            // No unwrapping needed, just add metadata
            var updatedResponse = response
                .WithMetadata(ResponseMetadata.SecureChannelWrapped, true)
                .WithMetadata("SecureChannelProtocol", $"SCP{session.ProtocolVersion:X2}");

            return Task.FromResult(Result.Success<CommandResponse, SmartCardError>(updatedResponse));
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to unwrap response with secure channel");
            return Task.FromResult(Result.Failure<CommandResponse, SmartCardError>(
                SmartCardError.SecurityError("Secure channel unwrapping failed", (ushort)response.StatusWord)
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

    private static Result<(byte[] wrappedData, int? expectedResponseLength, SecureChannelState newState), SmartCardError> 
        WrapCommandWithScp02(Transport.IApduCommand command, SecureChannelState session)
    {
        // Use existing immutable array for functional processing
        var macChainingValue = session.MacChaining.Value;
        
        return Scp02SecurityProcessor.ApplyCommandSecurity(
            command, 
            session.SecurityLevel, 
            session.SessionKeys,
            macChainingValue,
            session.EncryptionCounter)
            .Map(result => (result.securedCommand, (int?)null, result.newState));
    }

    private static Result<(byte[] wrappedData, int? expectedResponseLength, SecureChannelState newState), SmartCardError> 
        WrapCommandWithScp03(Transport.IApduCommand command, SecureChannelState session)
    {
        // Use existing immutable array for functional processing
        var macChainingValue = session.MacChaining.Value;
        
        return Scp03SecurityProcessor.ApplyCommandSecurity(
            command, 
            session.SecurityLevel, 
            session.SessionKeys,
            macChainingValue,
            session.EncryptionCounter)
            .Map(result => (result.securedCommand, (int?)null, result.newState));
    }

    private static Result<(byte[] processedResponse, SecureChannelState newState), SmartCardError> 
        ProcessResponseWithScp02(byte[] response, SecureChannelState session)
    {
        var macChainingValue = session.MacChaining.Value;
        
        return Scp02SecurityProcessor.ApplyResponseSecurity(
            response,
            session.SecurityLevel,
            session.SessionKeys,
            macChainingValue,
            session.EncryptionCounter);
    }

    private static Result<(byte[] processedResponse, SecureChannelState newState), SmartCardError> 
        ProcessResponseWithScp03(byte[] response, SecureChannelState session)
    {
        var macChainingValue = session.MacChaining.Value;
        
        return Scp03SecurityProcessor.ApplyResponseSecurity(
            response,
            session.SecurityLevel,
            session.SessionKeys,
            macChainingValue,
            session.EncryptionCounter);
    }
}

// SecurityLevel extension methods are now in Domain/SecurityLevel.cs