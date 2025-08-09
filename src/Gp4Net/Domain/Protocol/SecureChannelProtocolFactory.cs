using System;
using Gp4Net.Constants;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// Factory for creating secure channel protocol implementations.
/// </summary>
[PublicAPI]
public class SecureChannelProtocolFactory : ISecureChannelProtocolFactory
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<SecureChannelProtocolFactory> _logger;

    /// <summary>
    /// Initializes a new instance of SecureChannelProtocolFactory.
    /// </summary>
    /// <param name="serviceProvider">The service provider.</param>
    /// <param name="logger">The logger.</param>
    public SecureChannelProtocolFactory(
        IServiceProvider serviceProvider,
        ILogger<SecureChannelProtocolFactory> logger
    )
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    /// <inheritdoc />
    public ISecureChannelProtocol CreateProtocol(byte protocolVersion, IKeySet keySet)
    {

        var protocol = protocolVersion & ProtocolIdentifiers.ProtocolMask;

        _logger.LogDebug(
            "Creating secure channel protocol for version {Protocol:X2}",
            protocol
        );

        return protocol switch
        {
            ProtocolIdentifiers.Scp02 => CreateScp02Protocol(keySet),
            ProtocolIdentifiers.Scp03 => CreateScp03Protocol(keySet),
            _
                => throw new NotSupportedException(
                    $"Protocol version {protocolVersion:X2} is not supported"
                ),
        };
    }

    /// <inheritdoc />
    public byte DetectProtocolVersion(InitializeUpdateResponse response)
    {

        var protocol = response.ScpId & ProtocolIdentifiers.ProtocolMask;

        _logger.LogDebug("Detected protocol version {Protocol:X2} from response", protocol);

        return (byte)protocol;
    }

    /// <summary>
    /// Creates an SCP02 protocol instance.
    /// </summary>
    private ISecureChannelProtocol CreateScp02Protocol(IKeySet keySet)
    {
        if (keySet is not Scp02KeySet scp02KeySet)
        {
            throw new ArgumentException(
                "SCP02 protocol requires SCP02 key set",
                nameof(keySet)
            );
        }

        var keyDerivationService = _serviceProvider.GetRequiredService<IKeyDerivationService>();
        var logger = _serviceProvider.GetRequiredService<ILogger<Scp02Protocol>>();

        return new Scp02Protocol(scp02KeySet, keyDerivationService, logger);
    }

    /// <summary>
    /// Creates an SCP03 protocol instance.
    /// </summary>
    private ISecureChannelProtocol CreateScp03Protocol(IKeySet keySet)
    {
        if (keySet is not Scp03KeySet scp03KeySet)
        {
            throw new ArgumentException(
                "SCP03 protocol requires SCP03 key set",
                nameof(keySet)
            );
        }

        var keyDerivationService = _serviceProvider.GetRequiredService<IKeyDerivationService>();
        return new Scp03Protocol(scp03KeySet, keyDerivationService);
    }
}