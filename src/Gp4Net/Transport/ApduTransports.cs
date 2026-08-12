using System;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Transport;

/// <summary>
/// Default implementation of IApduTransports.
/// </summary>
[PublicAPI]
public class ApduTransports
{
    private readonly ILoggerFactory _loggerFactory;

    /// <summary>
    /// Initializes a new instance of ApduTransports.
    /// </summary>
    /// <param name="loggerFactory">The logger factory.</param>
    public ApduTransports(ILoggerFactory loggerFactory)
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
            _ => throw new NotSupportedException($"Transport protocol {protocol} is not supported"),
        };
    }
}
