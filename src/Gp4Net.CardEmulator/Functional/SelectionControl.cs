namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// SELECT command P1 parameter values.
/// </summary>
internal enum SelectionControl : byte
{
    SelectByName = 0x04,
    SelectFirstOccurrence = 0x00,
    SelectNextOccurrence = 0x02,
}
