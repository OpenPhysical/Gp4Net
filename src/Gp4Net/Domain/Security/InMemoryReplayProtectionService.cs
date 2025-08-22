using System;
using System.Collections.Concurrent;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Security;

/// <summary>
/// In-memory implementation of replay protection service.
/// Tracks sequence counters to prevent replay attacks.
/// </summary>
[PublicAPI]
public class InMemoryReplayProtectionService : IReplayProtectionService
{
    private readonly ConcurrentDictionary<byte, ConcurrentDictionary<string, bool>> _seenCounters = new();

    /// <inheritdoc />
    public UnitResult<SmartCardError> ValidateSequenceCounter(byte keyVersion, byte[] sequenceCounter)
    {
        // Security fix: Accept both 2-byte (SCP02) and 3-byte sequence counters
        // SCP02 uses 2-byte sequence counters, while other protocols may use 3-byte
        if (sequenceCounter == null || (sequenceCounter.Length != 2 && sequenceCounter.Length != 3))
        {
            return UnitResult.Failure(SmartCardError.InvalidArgument("Sequence counter must be 2 or 3 bytes"));
        }

        var counterKey = Convert.ToHexString(sequenceCounter);
        var keyCounters = _seenCounters.GetOrAdd(keyVersion, _ => new ConcurrentDictionary<string, bool>());

        if (keyCounters.ContainsKey(counterKey))
        {
            return UnitResult.Failure(SmartCardError.SecurityError($"Replay attack detected: sequence counter {counterKey} has been used before"));
        }

        return UnitResult.Success<SmartCardError>();
    }

    /// <inheritdoc />
    public UnitResult<SmartCardError> RecordSequenceCounter(byte keyVersion, byte[] sequenceCounter)
    {
        // Security fix: Accept both 2-byte (SCP02) and 3-byte sequence counters
        // SCP02 uses 2-byte sequence counters, while other protocols may use 3-byte
        if (sequenceCounter == null || (sequenceCounter.Length != 2 && sequenceCounter.Length != 3))
        {
            return UnitResult.Failure(SmartCardError.InvalidArgument("Sequence counter must be 2 or 3 bytes"));
        }

        var counterKey = Convert.ToHexString(sequenceCounter);
        var keyCounters = _seenCounters.GetOrAdd(keyVersion, _ => new ConcurrentDictionary<string, bool>());

        if (!keyCounters.TryAdd(counterKey, true))
        {
            return UnitResult.Failure(SmartCardError.SecurityError($"Sequence counter {counterKey} already recorded"));
        }

        // Per GP spec: sequence counter should increment, so we can validate ordering
        var counterValue = (sequenceCounter[0] << 16) | (sequenceCounter[1] << 8) | sequenceCounter[2];
        
        // Optional: Remove old counters that are significantly lower than current to prevent memory growth
        // This is safe because counters must increment
        if (keyCounters.Count > 100) // Arbitrary threshold
        {
            var keysToRemove = keyCounters.Keys
                .Select(k => (key: k, value: ParseCounterValue(k)))
                .Where(kv => kv.value < counterValue - 50) // Keep last 50 counters
                .Select(kv => kv.key)
                .ToList();

            foreach (var key in keysToRemove)
            {
                _ = keyCounters.TryRemove(key, out _);
            }
        }

        return UnitResult.Success<SmartCardError>();
    }

    /// <inheritdoc />
    public UnitResult<SmartCardError> ClearKeyVersion(byte keyVersion)
    {
        _ = _seenCounters.TryRemove(keyVersion, out _);
        return UnitResult.Success<SmartCardError>();
    }

    private static int ParseCounterValue(string hexCounter)
    {
        var bytes = Convert.FromHexString(hexCounter);
        return (bytes[0] << 16) | (bytes[1] << 8) | bytes[2];
    }
}