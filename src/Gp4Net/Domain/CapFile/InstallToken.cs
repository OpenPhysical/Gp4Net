namespace Gp4Net.Domain.CapFile;

/// <summary>
/// Represents an install token structure per GlobalPlatform Card Specification v2.3.1.
/// Install tokens provide authorization and integrity verification for INSTALL commands.
/// </summary>
/// <param name="Signature">The HMAC signature providing authentication (typically first 8 bytes of full HMAC).</param>
/// <param name="Algorithm">The cryptographic algorithm used for the token signature (e.g., "HMAC_SHA256").</param>
/// <param name="KeyIdentifier">The identifier of the key used for HMAC computation.</param>
/// <param name="AuthorizationLevel">The authorization level indicating required privileges for the operation.</param>
internal sealed record InstallToken(
    byte[] Signature,
    string Algorithm,
    byte[] KeyIdentifier,
    byte[] AuthorizationLevel
);