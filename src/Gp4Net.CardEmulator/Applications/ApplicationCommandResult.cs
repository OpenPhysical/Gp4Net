using Gp4Net.CardEmulator.Functional;

namespace Gp4Net.CardEmulator.Applications;

/// <summary>
/// Result of processing an APDU within a virtual application.
/// Encapsulates the updated application instance, updated card state, and response APDU.
/// </summary>
public sealed record ApplicationCommandResult(
    IApplication UpdatedApplication,
    CardState UpdatedState,
    ApduResponse Response
);
