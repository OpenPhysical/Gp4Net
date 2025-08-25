using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Adapter that implements IResponseSecurityProcessor by delegating to the static ResponseSecurityProcessor.
/// This allows dependency injection while maintaining the functional static implementation.
/// </summary>
[PublicAPI]
public class ResponseSecurityProcessorAdapter : IResponseSecurityProcessor
{
    /// <inheritdoc />
    public Result<(byte[] processedResponse, SecureChannelState newState), SmartCardError> ApplyResponseSecurity(
        byte[] response,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        uint encryptionCounter,
        byte protocolVersion)
    {
        return ResponseSecurityProcessor.ApplyResponseSecurity(
            response,
            securityLevel,
            sessionKeys,
            macChainingValue,
            encryptionCounter,
            protocolVersion);
    }
}