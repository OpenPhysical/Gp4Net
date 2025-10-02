namespace Gp4Net.Domain.Security;

/// <summary>
/// Immutable record representing the input data for MAC calculation.
/// Contains the bytes to be MAC'd and any extracted MAC from secured commands.
/// </summary>
/// <param name="Bytes">The complete byte array for MAC calculation (CLA|INS|P1|P2|Lc|Data)</param>
/// <param name="ExtractedMac">MAC bytes extracted from a secured command (empty for unsecured)</param>
/// <param name="PlaintextData">The plaintext data portion without MAC (for secured commands)</param>
public record MacInput(byte[] Bytes, byte[] ExtractedMac, byte[] PlaintextData)
{
    /// <summary>
    /// Indicates whether this represents a secured command with an extracted MAC.
    /// </summary>
    public bool IsSecured => ExtractedMac.Length > 0;

    /// <summary>
    /// Gets the header bytes (CLA|INS|P1|P2) from the MAC input.
    /// </summary>
    public byte[] GetHeader() => Bytes.Length >= 4 ? Bytes[..4] : Bytes;
}
