using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Modules;
using Gp4Net.Pipeline;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Live secure channel strategy that performs actual secure channel establishment.
/// Uses the SecureChannelEstablishment module to execute the full SCP protocol flow.
/// </summary>
[PublicAPI]
public class LiveSecureChannelStrategy : ISecureChannelStrategy
{
    private readonly IKeySet _keySet;

    /// <summary>
    /// Initializes a new instance of the LiveSecureChannelStrategy.
    /// </summary>
    /// <param name="keySet">The key set to use for secure channel establishment.</param>
    public LiveSecureChannelStrategy(IKeySet keySet)
    {
        _keySet = keySet;
    }

    /// <summary>
    /// Establishes a secure channel by executing the full SCP protocol flow.
    /// Sends INITIALIZE UPDATE and EXTERNAL AUTHENTICATE commands to the card.
    /// </summary>
    public async Task<Result<SecureChannelState, SmartCardError>> EstablishSecureChannel(
        SecurityLevel securityLevel,
        CommandProcessing.CommandEnvironment environment)
    {
        // Create command execution function that works with our environment
        System.Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand = 
            async (command, cancellationToken) =>
            {
                var response = await environment.Transport.TransmitAsync(command, environment.Channel, cancellationToken);
                
                // Convert to CommandResponse format expected by SecureChannelEstablishment
                var commandResponse = response.StatusWord == Gp4Net.Constants.StatusWords.Success 
                    ? CommandResponse.Success(response.Data)
                    : CommandResponse.Failure(response.StatusWord);
                
                return Result.Success<CommandResponse, SmartCardError>(commandResponse);
            };
        
        // Use the existing secure channel establishment module
        return await SecureChannelEstablishment.EstablishAsync(
            _keySet, 
            securityLevel, 
            executeCommand, 
            selectedAid: null,
            CancellationToken.None);
    }
}