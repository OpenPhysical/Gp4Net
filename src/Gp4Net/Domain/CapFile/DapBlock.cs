using System.Collections.Immutable;

namespace Gp4Net.Domain.CapFile;

/// <summary>
/// Represents a Data Authentication Pattern (DAP) block from a CAP file.
/// DAP provides cryptographic authentication and integrity verification for CAP files
/// according to GlobalPlatform Card Specification v2.3.1 Section 9.7.
/// </summary>
/// <param name="Algorithm">The cryptographic algorithm used for the DAP signature (e.g., "RSA_SHA256", "ECDSA-P256").</param>
/// <param name="Signature">The cryptographic signature bytes providing authentication.</param>
/// <param name="CertificateChain">The certificate chain used for signature verification.</param>
public sealed record DapBlock(
    string Algorithm,
    byte[] Signature,
    ImmutableArray<byte[]> CertificateChain
);