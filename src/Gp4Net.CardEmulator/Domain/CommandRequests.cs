using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Domain;

/// <summary>
/// Shared command request types for the card emulator.
/// These represent parsed incoming APDU commands.
/// </summary>
[PublicAPI]
public static class CommandRequests
{
    /// <summary>
    /// Represents a parsed INITIALIZE UPDATE command request.
    /// </summary>
    public record InitializeUpdateRequest(
        byte KeyVersion,
        byte KeyIdentifier,
        byte[] HostChallenge
    );

    /// <summary>
    /// Represents a parsed EXTERNAL AUTHENTICATE command request.
    /// </summary>
    public record ExternalAuthenticateRequest(
        byte SecurityLevel,
        byte[] HostCryptogram,
        byte[] HostMac,
        byte Cla = 0x84
    );

    /// <summary>
    /// Represents a parsed GET DATA command request.
    /// </summary>
    public record GetDataRequest(ushort Tag);

    /// <summary>
    /// Represents a parsed SELECT command request.
    /// </summary>
    public record SelectRequest(byte[] Aid);
}
