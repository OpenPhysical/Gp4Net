using System.Collections.Immutable;

namespace Gp4Net.CardEmulator.Core;

public partial class VirtualCard
{
    /// <summary>
    /// Represents the context for tracking LOAD command data accumulation.
    /// </summary>
    private record LoadContext(ImmutableList<byte> AccumulatedData, byte LastBlockNumber);
}
