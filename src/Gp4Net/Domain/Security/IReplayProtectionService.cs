using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Service for preventing replay attacks by tracking sequence counters.
/// </summary>
[PublicAPI]
public interface IReplayProtectionService
{
    /// <summary>
    /// Validates that a sequence counter has not been seen before.
    /// </summary>
    /// <param name="keyVersion">The key version associated with the counter.</param>
    /// <param name="sequenceCounter">The sequence counter to validate (3 bytes).</param>
    /// <returns>Success if the counter is valid (not replayed), failure otherwise.</returns>
    UnitResult<SmartCardError> ValidateSequenceCounter(byte keyVersion, byte[] sequenceCounter);

    /// <summary>
    /// Records a sequence counter as seen to prevent future replay.
    /// </summary>
    /// <param name="keyVersion">The key version associated with the counter.</param>
    /// <param name="sequenceCounter">The sequence counter to record (3 bytes).</param>
    /// <returns>Success if recorded, failure if already seen.</returns>
    UnitResult<SmartCardError> RecordSequenceCounter(byte keyVersion, byte[] sequenceCounter);

    /// <summary>
    /// Clears recorded counters for a specific key version.
    /// This should be called when a keyset is replaced.
    /// </summary>
    /// <param name="keyVersion">The key version to clear.</param>
    /// <returns>Success if cleared.</returns>
    UnitResult<SmartCardError> ClearKeyVersion(byte keyVersion);
}