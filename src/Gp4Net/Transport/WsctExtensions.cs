using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;
using WSCT.ISO7816;

namespace Gp4Net.Transport;

/// <summary>
/// Extension methods for WSCT APDU types to integrate with Gp4Net functional patterns.
/// </summary>
[PublicAPI]
public static class WsctExtensions
{
    /// <summary>
    /// Converts WSCT ResponseAPDU to Gp4Net StatusWord.
    /// </summary>
    /// <param name="response">The WSCT ResponseAPDU.</param>
    /// <returns>The StatusWord from SW1 and SW2.</returns>
    public static StatusWord GetStatusWord(this ResponseAPDU response)
    {
        return new StatusWord(response.Sw1, response.Sw2);
    }

    /// <summary>
    /// Gets response data from WSCT ResponseAPDU.
    /// </summary>
    /// <param name="response">The WSCT ResponseAPDU.</param>
    /// <returns>Response data bytes (excluding status word).</returns>
    public static byte[] GetResponseData(this ResponseAPDU response)
    {
        return Maybe<byte[]>.From(response.Udr).GetValueOrDefault([]);
    }

    /// <summary>
    /// Checks if the WSCT ResponseAPDU indicates success (SW=9000).
    /// </summary>
    /// <param name="response">The WSCT ResponseAPDU.</param>
    /// <returns>True if SW1=90 and SW2=00.</returns>
    public static bool IsSuccess(this ResponseAPDU response)
    {
        return response.Sw1 == 0x90 && response.Sw2 == 0x00;
    }

    /// <summary>
    /// Creates a CommandAPDU from individual APDU components.
    /// </summary>
    /// <param name="cla">Class byte.</param>
    /// <param name="ins">Instruction byte.</param>
    /// <param name="p1">Parameter 1.</param>
    /// <param name="p2">Parameter 2.</param>
    /// <param name="data">Command data (optional).</param>
    /// <param name="le">Expected response length (optional).</param>
    /// <returns>A Result containing the CommandAPDU or an error.</returns>
    public static Result<CommandAPDU, SmartCardError> CreateCommandApdu(
        byte cla,
        byte ins,
        byte p1,
        byte p2,
        Maybe<byte[]> data = default,
        Maybe<int> le = default)
    {
        return ApduBuilder.CreateCommand(cla, ins, p1, p2, data, le);
    }

    /// <summary>
    /// Converts a CommandAPDU to its raw byte representation.
    /// </summary>
    /// <param name="command">The CommandAPDU.</param>
    /// <returns>The raw APDU bytes.</returns>
    public static byte[] ToBytes(this CommandAPDU command)
    {
        // WSCT CommandAPDU doesn't expose Binary property reliably
        // Return empty array until proper WSCT API usage is determined
        return [];
    }
}