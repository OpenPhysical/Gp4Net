using System.Collections.Immutable;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Data extracted from a SELECT command.
/// </summary>
internal record SelectCommandData(
    ImmutableArray<byte> Aid,
    SelectionControl SelectionControl,
    FileControlInformation Fci,
    bool FileOccurrence
);
