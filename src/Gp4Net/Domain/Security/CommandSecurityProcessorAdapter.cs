using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Adapter that implements ICommandSecurityProcessor by delegating to the static CommandSecurityProcessor.
/// This allows dependency injection while maintaining the functional static implementation.
/// </summary>
[PublicAPI]
public class CommandSecurityProcessorAdapter : ICommandSecurityProcessor
{
    /// <inheritdoc />
    public Result<(byte[] securedCommand, SecureChannelState newState), SmartCardError> ApplyCommandSecurity(
        IApduCommand command,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        uint encryptionCounter,
        byte protocolVersion)
    {
        return CommandSecurityProcessor.ApplyCommandSecurity(
            command,
            securityLevel,
            sessionKeys,
            macChainingValue,
            encryptionCounter,
            protocolVersion);
    }
}