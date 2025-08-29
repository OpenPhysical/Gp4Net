using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Transport;

/// <summary>
/// Implements T=CL contactless transport protocol.
/// Based on T=1 but with contactless-specific restrictions.
/// </summary>
[PublicAPI]
public class ClApduTransport : IApduTransport
{
    private readonly T1ApduTransport _t1Transport;
    private readonly ILogger<ClApduTransport> _logger;

    /// <inheritdoc />
    public TransportProtocol Protocol
    {
        get
        {
            return TransportProtocol.Tcl;
        }
    }

    /// <inheritdoc />
    public int MaxCommandDataLength
    {
        get
        {
            return 255;

            // Contactless typically limits to short length
        }
    }

    /// <inheritdoc />
    public int MaxResponseDataLength
    {
        get
        {
            return 256;
        }
    }

    /// <inheritdoc />
    public bool SupportsExtendedLength
    {
        get
        {
            return false;

            // Most contactless cards don't support extended
        }
    }

    /// <summary>
    /// Initializes a new instance of ClApduTransport.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="t1Logger">Logger for the underlying T=1 transport.</param>
    public ClApduTransport(ILogger<ClApduTransport> logger, ILogger<T1ApduTransport> t1Logger)
    {
        _logger = logger;
        _t1Transport = new T1ApduTransport(t1Logger, supportsExtendedLength: false);
    }

    /// <inheritdoc />
    public async Task<ApduResponse> TransmitAsync(
        IApduCommand command,
        ICardChannel channel,
        CancellationToken cancellationToken = default
    )
    {

        // Validate contactless-specific restrictions
        ValidateContactlessCommand(command);

        _logger.LogDebug(
            "T=CL Transmit for CLA={Cla:X2} INS={Ins:X2}",
            command.Cla,
            command.Ins
        );

        // Delegate to T=1 implementation with contactless wrapper
        ContactlessCommandWrapper contactlessCommand = new ContactlessCommandWrapper(command);
        return await _t1Transport
            .TransmitAsync(contactlessCommand, channel, cancellationToken)
            .ConfigureAwait(false);
    }

    private void ValidateContactlessCommand(IApduCommand command)
    {
        if (command.IsExtendedLength)
        {
            throw new NotSupportedException(
                "Extended length APDUs not supported in contactless mode"
            );
        }

        if (command.Data != null && command.Data.Length > MaxCommandDataLength)
        {
            throw new ArgumentException(
                $"Command data length {command.Data.Length} exceeds contactless limit of {MaxCommandDataLength}"
            );
        }

        // Per GlobalPlatform specifications, contactless validation is handled by the wrapper.
        // The ContactlessCommandWrapper ensures proper Le handling for T=CL protocol.
    }

    /// <summary>
    /// Wrapper to ensure contactless-specific behavior.
    /// </summary>
    private class ContactlessCommandWrapper : IApduCommand
    {
        private readonly IApduCommand _inner;

        public ContactlessCommandWrapper(IApduCommand inner)
        {
            _inner = inner;
        }

        public byte Cla
        {
            get
            {
                return _inner.Cla;
            }
        }
        public byte Ins
        {
            get
            {
                return _inner.Ins;
            }
        }
        public byte P1
        {
            get
            {
                return _inner.P1;
            }
        }
        public byte P2
        {
            get
            {
                return _inner.P2;
            }
        }
        public byte[] Data
        {
            get
            {
                return _inner.Data;
            }
        }

        public Maybe<int> ExpectedResponseLength
        {
            get
            {
                // Per GlobalPlatform Card Specification v2.3.1 Section 11.1.4:
                // Contactless cards (T=CL) should include Le byte.
                // If inner command expects no response, we still pass through the None
                // at the interface boundary, letting the APDU encoder handle it appropriately.
                if (_inner.ExpectedResponseLength.HasValue)
                {
                    // Le=0 means maximum (256 for short length)
                    return Maybe<int>.From(_inner.ExpectedResponseLength.Value == 0
                        ? 256
                        : _inner.ExpectedResponseLength.Value);
                }
                // Interface allows None - the APDU encoder will handle this per T=CL requirements
                return _inner.ExpectedResponseLength;
            }
        }

        public bool IsExtendedLength
        {
            get
            {
                return false;

                // Never extended for contactless
            }
        }
    }
}