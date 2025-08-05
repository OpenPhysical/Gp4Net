using WSCT.Core.APDU;

namespace Gp4Net.Tool.Services.CardCommunication;

/// <summary>
/// Factory interface for creating WSCT objects to enable unit testing.
/// </summary>
public interface IWsctFactory
{
    /// <summary>
    /// Creates a new card context wrapper.
    /// </summary>
    /// <returns>A new card context wrapper instance.</returns>
    ICardContextWrapper CreateCardContext();

    /// <summary>
    /// Creates a new command APDU.
    /// </summary>
    /// <param name="command">The command bytes.</param>
    /// <returns>A new command APDU instance.</returns>
    ICardCommand CreateCommandApdu(byte[] command);

    /// <summary>
    /// Creates a new response APDU.
    /// </summary>
    /// <returns>A new response APDU instance.</returns>
    ICardResponse CreateResponseApdu();
}