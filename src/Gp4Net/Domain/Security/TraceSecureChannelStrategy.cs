using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.CapFile;
using Gp4Net.Domain.Keys;
using Gp4Net.Pipeline;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Trace-based secure channel strategy that creates secure channel state from trace data.
/// Parses INITIALIZE UPDATE responses from traces to derive session keys deterministically.
/// Used for trace replay and validation scenarios.
/// </summary>
[PublicAPI]
public class TraceSecureChannelStrategy : ISecureChannelStrategy
{
    private readonly CapInstallationTrace _trace;
    private readonly IKeySet _keySet;

    /// <summary>
    /// Initializes a new instance of the TraceSecureChannelStrategy.
    /// </summary>
    /// <param name="trace">The trace data containing secure channel establishment commands.</param>
    /// <param name="keySet">The key set to use for session key derivation.</param>
    public TraceSecureChannelStrategy(CapInstallationTrace trace, IKeySet keySet)
    {
        _trace = trace;
        _keySet = keySet;
    }

    /// <summary>
    /// Creates secure channel state using the existing SecureChannelEstablishment module.
    /// Uses the Virtual Card to provide trace-compliant responses for deterministic testing.
    /// </summary>
    public async Task<Result<SecureChannelState, SmartCardError>> EstablishSecureChannel(
        SecurityLevel securityLevel,
        CommandProcessing.CommandEnvironment environment)
    {
        // Create command execution function that works with the environment
        System.Func<Transport.IApduCommand, CancellationToken, Task<Result<Pipeline.CommandResponse, SmartCardError>>> executeCommand = 
            async (command, cancellationToken) =>
            {
                var response = await environment.Transport.TransmitAsync(command, environment.Channel, cancellationToken);
                
                // Convert to CommandResponse format expected by SecureChannelEstablishment
                var commandResponse = response.StatusWord == Gp4Net.Constants.StatusWords.Success 
                    ? Pipeline.CommandResponse.Success(response.Data)
                    : Pipeline.CommandResponse.Failure(response.StatusWord);
                
                return Result.Success<Pipeline.CommandResponse, SmartCardError>(commandResponse);
            };
        
        // Use the existing secure channel establishment module with trace-compliant keys
        return await Modules.SecureChannelEstablishment.EstablishAsync(
            _keySet, 
            securityLevel, 
            executeCommand, 
            selectedAid: null,
            CancellationToken.None);
    }

}

