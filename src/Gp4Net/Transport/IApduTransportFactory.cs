using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Transport;

/// <summary>
/// Factory for creating APDU transport instances based on protocol type.
/// </summary>
[PublicAPI]
public interface IApduTransportFactory
{
    /// <summary>
    /// Creates an APDU transport for the specified protocol.
    /// </summary>
    /// <param name="protocol">The transport protocol.</param>
    /// <param name="supportsExtendedLength">Whether extended length is supported (for T=1).</param>
    /// <returns>The transport instance.</returns>
    IApduTransport CreateTransport(
        TransportProtocol protocol,
        bool supportsExtendedLength = true
    );
}

/// <summary>
/// Default implementation of IApduTransportFactory.
/// </summary>
[PublicAPI]
public class ApduTransportFactory : IApduTransportFactory
{
    private readonly Microsoft.Extensions.Logging.ILoggerFactory _loggerFactory;

    /// <summary>
    /// Initializes a new instance of ApduTransportFactory.
    /// </summary>
    /// <param name="loggerFactory">The logger factory.</param>
    public ApduTransportFactory(Microsoft.Extensions.Logging.ILoggerFactory loggerFactory)
    {
        _loggerFactory = loggerFactory;
    }

    /// <inheritdoc />
    public IApduTransport CreateTransport(
        TransportProtocol protocol,
        bool supportsExtendedLength = true
    )
    {
        return protocol switch
        {
            TransportProtocol.T0
                => new T0ApduTransport(_loggerFactory.CreateLogger<T0ApduTransport>()),
            TransportProtocol.T1
                => new T1ApduTransport(
                    _loggerFactory.CreateLogger<T1ApduTransport>(),
                    supportsExtendedLength
                ),
            TransportProtocol.Tcl
                => new ClApduTransport(
                    _loggerFactory.CreateLogger<ClApduTransport>(),
                    _loggerFactory.CreateLogger<T1ApduTransport>()
                ),
            _
                => throw new System.NotSupportedException(
                    $"Transport protocol {protocol} is not supported"
                ),
        };
    }
}