using System;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Transport
{
    /// <summary>
    /// Implements T=CL contactless transport protocol.
    /// Based on T=1 but with contactless-specific restrictions.
    /// </summary>
    [PublicAPI]
    public class TClApduTransport : IApduTransport
    {
        private readonly T1ApduTransport _t1Transport;
        private readonly ILogger<TClApduTransport> _logger;

        /// <inheritdoc />
        public TransportProtocol Protocol => TransportProtocol.TCL;

        /// <inheritdoc />
        public int MaxCommandDataLength => 255; // Contactless typically limits to short length

        /// <inheritdoc />
        public int MaxResponseDataLength => 256;

        /// <inheritdoc />
        public bool SupportsExtendedLength => false; // Most contactless cards don't support extended

        /// <summary>
        /// Initializes a new instance of TClApduTransport.
        /// </summary>
        /// <param name="logger">The logger.</param>
        /// <param name="t1Logger">Logger for the underlying T=1 transport.</param>
        public TClApduTransport(ILogger<TClApduTransport> logger, ILogger<T1ApduTransport> t1Logger)
        {
            ArgumentNullException.ThrowIfNull(logger);
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
            ArgumentNullException.ThrowIfNull(command);

            ArgumentNullException.ThrowIfNull(channel);

            // Validate contactless-specific restrictions
            ValidateContactlessCommand(command);

            _logger.LogDebug(
                "T=CL Transmit for CLA={Cla:X2} INS={Ins:X2}",
                command.Cla,
                command.Ins
            );

            // Delegate to T=1 implementation with contactless wrapper
            var contactlessCommand = new ContactlessCommandWrapper(command);
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

            // Contactless cards must always include Le for commands expecting response
            if (command.ExpectedResponseLength.HasValue && command.ExpectedResponseLength == null)
            {
                throw new ArgumentException(
                    "Contactless cards require explicit Le for response commands"
                );
            }
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

            public byte Cla => _inner.Cla;
            public byte Ins => _inner.Ins;
            public byte P1 => _inner.P1;
            public byte P2 => _inner.P2;
            public byte[]? Data => _inner.Data;

            public int? ExpectedResponseLength
            {
                get
                {
                    // Contactless always needs explicit Le for response commands
                    if (_inner.ExpectedResponseLength.HasValue)
                    {
                        return _inner.ExpectedResponseLength.Value == 0
                            ? 256
                            : _inner.ExpectedResponseLength.Value;
                    }
                    return null;
                }
            }

            public bool IsExtendedLength => false; // Never extended for contactless
        }
    }
}
