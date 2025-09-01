using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Services;

/// <summary>
/// Manager implementation for secure channel lifecycle operations.
/// Provides functional secure channel establishment and state management.
/// </summary>
[PublicAPI]
public sealed class SecureChannelManager : ISecureChannelManager
{
    private readonly ISmartCardService _cardService;
    private readonly IKeysetResolver _keysetResolver;
    private readonly ISecureChannelProtocolFactory _protocolFactory;
    private readonly ILogger<SecureChannelManager> _logger;
    private readonly Maybe<SecureChannelState> _currentChannel = Maybe<SecureChannelState>.None;

    /// <summary>
    /// Initializes a new instance of the SecureChannelManager class.
    /// </summary>
    public SecureChannelManager(
        ISmartCardService cardService,
        IKeysetResolver keysetResolver,
        ISecureChannelProtocolFactory protocolFactory,
        ILogger<SecureChannelManager> logger
    )
    {
        _cardService = cardService;
        _keysetResolver = keysetResolver;
        _protocolFactory = protocolFactory;
        _logger = logger;
    }

    /// <inheritdoc />
    public Task<Result<SecureChannelState, SmartCardError>> EstablishSecureChannelAsync(
        IKeySet keySet,
        SecurityLevel securityLevel,
        CancellationToken cancellationToken = default
    )
    {
        _logger.LogInformation(
            "Establishing secure channel with keyset type: {KeysetType}, security level: {SecurityLevel}",
            keySet.GetType().Name,
            securityLevel
        );

        return _protocolFactory
            .CreateEstablishmentFunction(keySet)
            .Bind(establishFunction => establishFunction(securityLevel, cancellationToken));
    }

    /// <inheritdoc />
    public Task<Result<SecureChannelState, SmartCardError>> EstablishSecureChannelAsync(
        string keysetName,
        SecurityLevel securityLevel,
        byte keyVersion = 0x01,
        CancellationToken cancellationToken = default
    )
    {
        _logger.LogInformation(
            "Establishing secure channel with keyset name: {KeysetName}, security level: {SecurityLevel}",
            keysetName,
            securityLevel
        );

        return _keysetResolver
            .ResolveScp02KeySet(keysetName, keyVersion)
            .Map(keySet => (IKeySet)keySet)
            .Bind(keySet => EstablishSecureChannelAsync(keySet, securityLevel, cancellationToken));
    }

    /// <inheritdoc />
    public Maybe<SecureChannelState> GetCurrentChannel()
    {
        return _currentChannel;
    }

    /// <inheritdoc />
    public UnitResult<SmartCardError> CloseChannel()
    {
        _logger.LogInformation("Closing secure channel");
        return UnitResult.Success<SmartCardError>();
    }
}
