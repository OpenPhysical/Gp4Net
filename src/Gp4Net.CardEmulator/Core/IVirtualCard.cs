using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.CardEmulator.Functional;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Core;

/// <summary>
/// Interface for a virtual smart card that can process APDU commands.
/// </summary>
[PublicAPI]
public interface IVirtualCard
{
    /// <summary>
    /// Gets the Answer to Reset (ATR) of the virtual card.
    /// </summary>
    byte[] GetAtr();

    /// <summary>
    /// Processes an APDU command and returns the response.
    /// </summary>
    /// <param name="command">The APDU command bytes.</param>
    /// <returns>The APDU response including status word.</returns>
    ApduResponse ProcessCommand(byte[] command);

    /// <summary>
    /// Resets the virtual card to its initial state.
    /// </summary>
    /// <returns>A new card instance in reset state, or an error.</returns>
    Result<IVirtualCard, SmartCardError> Reset();

    /// <summary>
    /// Gets a value indicating whether the card is currently selected.
    /// </summary>
    bool IsSelected { get; }

    /// <summary>
    /// Gets a value indicating whether a secure channel is established.
    /// </summary>
    bool IsSecureChannelEstablished { get; }

    /// <summary>
    /// Gets the card configuration (for testing purposes).
    /// </summary>
    CardConfiguration Configuration { get; }
}

/// <summary>
/// Functional interface for a virtual smart card that can process APDU commands.
/// All operations are functional and return new instances with updated state.
/// </summary>
[PublicAPI]
public interface IFunctionalVirtualCard
{
    /// <summary>
    /// Gets the Answer to Reset (ATR) of the virtual card.
    /// </summary>
    byte[] GetAtr();

    /// <summary>
    /// Processes an APDU command and returns the response with updated card state.
    /// </summary>
    /// <param name="command">The APDU command bytes.</param>
    /// <returns>The APDU response and updated card instance, or an error.</returns>
    Result<
        (ApduResponse Response, IFunctionalVirtualCard UpdatedCard),
        SmartCardError
    > ProcessCommand(byte[] command);

    /// <summary>
    /// Resets the virtual card to its initial state.
    /// </summary>
    /// <returns>A new card instance in reset state, or an error.</returns>
    Result<IFunctionalVirtualCard, SmartCardError> Reset();

    /// <summary>
    /// Gets a value indicating whether the card is currently selected.
    /// </summary>
    bool IsSelected { get; }

    /// <summary>
    /// Gets a value indicating whether a secure channel is established.
    /// </summary>
    bool IsSecureChannelEstablished { get; }
}
