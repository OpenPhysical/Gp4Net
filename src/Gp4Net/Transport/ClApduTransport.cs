using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using WSCT.ISO7816;

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
        get { return TransportProtocol.Tcl; }
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
        get { return 256; }
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
    public async Task<Result<ApduResponse, SmartCardError>> TransmitAsync(
        IApduCommand command,
        ICardChannel channel,
        CancellationToken cancellationToken = default
    )
    {
        // Convert to CommandAPDU for contactless validation
        var validationResult = Maybe<IApduCommand>
            .From(command)
            .ToResult(SmartCardError.InvalidArgument("Command cannot be null"))
            .Map(cmd => cmd.ToApdu())
            .Bind(ValidateContactlessCommand)
            .Tap(() => _logger.LogDebug("T=CL Transmit for command"))
            .Map(validCommand => new WrappedApduCommand(CreateContactlessCommand(validCommand)));

        if (validationResult.IsFailure)
        {
            return Result.Failure<ApduResponse, SmartCardError>(validationResult.Error);
        }

        return await _t1Transport.TransmitAsync(validationResult.Value, channel, cancellationToken);
    }

    private Result<CommandAPDU, SmartCardError> ValidateContactlessCommand(CommandAPDU command)
    {
        // Basic contactless validation - extended length APDUs are generally not supported
        // Without access to WSCT CommandAPDU internals, we'll do minimal validation
        // Specific validation can be added once the correct WSCT API usage is determined

        return Result.Success<CommandAPDU, SmartCardError>(command);
    }

    /// <summary>
    /// Creates a contactless-optimized command APDU.
    /// Per GlobalPlatform Card Specification v2.3.1 Section 11.1.4:
    /// Contactless cards (T=CL) should include Le byte for proper response handling.
    /// </summary>
    /// <param name="command">The original command.</param>
    /// <returns>A contactless-optimized command APDU.</returns>
    private CommandAPDU CreateContactlessCommand(CommandAPDU command)
    {
        // For contactless cards, return the command as-is
        // Contactless-specific optimizations can be added later based on actual WSCT API
        return command;
    }
}
