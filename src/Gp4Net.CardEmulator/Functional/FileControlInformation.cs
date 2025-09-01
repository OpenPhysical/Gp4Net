namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// SELECT command P2 parameter values for FCI.
/// </summary>
internal enum FileControlInformation : byte
{
    ReturnFci = 0x00,
    ReturnFcp = 0x04,
    ReturnFmd = 0x08,
    NoResponse = 0x0C,
}
