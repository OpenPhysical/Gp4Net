using System.Collections.Immutable;

namespace Gp4Net.Domain.CapFile;

/// <summary>
/// Represents the context for tracking LOAD command data block accumulation.
/// Used internally by the CAP file service to maintain state during multi-block LOAD operations
/// as defined in GlobalPlatform Card Specification v2.3.1 Section 11.6.
/// </summary>
/// <param name="AccumulatedData">The accumulated CAP file data bytes from all received blocks.</param>
/// <param name="LastBlockNumber">The sequence number of the last processed block (0xFF indicates no previous block).</param>
internal sealed record LoadContext(ImmutableList<byte> AccumulatedData, byte LastBlockNumber);
