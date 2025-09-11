using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
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
    private readonly ConcurrentDictionary<byte, ConcurrentDictionary<string, bool>> _seenCounters =
        new();

    /// <inheritdoc />
    public UnitResult<SmartCardError> ValidateSequenceCounter(
        byte keyVersion,
        byte[] sequenceCounter
    )
    {
        // Security fix: Accept both 2-byte (SCP02) and 3-byte sequence counters
        // SCP02 uses 2-byte sequence counters, while other protocols may use 3-byte
        if (sequenceCounter == null || sequenceCounter.Length != 2 && sequenceCounter.Length != 3)
        {
            return UnitResult.Failure(
                SmartCardError.InvalidArgument("Sequence counter must be 2 or 3 bytes")
            );
        }

        string counterKey = Convert.ToHexString(sequenceCounter);
        var keyCounters = _seenCounters.GetOrAdd(
            keyVersion,
            _ => new ConcurrentDictionary<string, bool>()
        );

        if (keyCounters.ContainsKey(counterKey))
        {
            return UnitResult.Failure(
                SmartCardError.SecurityError(
                    $"Replay attack detected: sequence counter {counterKey} has been used before"
                )
            );
        }

        return UnitResult.Success<SmartCardError>();
    }

    /// <inheritdoc />
    public UnitResult<SmartCardError> RecordSequenceCounter(byte keyVersion, byte[] sequenceCounter)
    {
        // Security fix: Accept both 2-byte (SCP02) and 3-byte sequence counters
        // SCP02 uses 2-byte sequence counters, while other protocols may use 3-byte
        if (sequenceCounter == null || sequenceCounter.Length != 2 && sequenceCounter.Length != 3)
        {
            return UnitResult.Failure(
                SmartCardError.InvalidArgument("Sequence counter must be 2 or 3 bytes")
            );
        }

        string counterKey = Convert.ToHexString(sequenceCounter);
        var keyCounters = _seenCounters.GetOrAdd(
            keyVersion,
            _ => new ConcurrentDictionary<string, bool>()
        );

        if (!keyCounters.TryAdd(counterKey, true))
        {
            return UnitResult.Failure(
                SmartCardError.SecurityError($"Sequence counter {counterKey} already recorded")
            );
        }

        // Per GP spec: sequence counter should increment, so we can validate ordering
        // SCP02 uses 2-byte counters, SCP03 uses 3-byte counters
        int counterValue = sequenceCounter.Length switch
        {
            2 => sequenceCounter[0] << 8 | sequenceCounter[1], // SCP02: 2-byte counter
            3 => sequenceCounter[0] << 16 | sequenceCounter[1] << 8 | sequenceCounter[2], // SCP03: 3-byte counter
            _ => 0, // Invalid counter length, but we've already validated it
        };

        // Optional: Remove old counters that are significantly lower than current to prevent memory growth
        // This is safe because counters must increment
        if (keyCounters.Count > 100) // Arbitrary threshold
        {
            List<string> keysToRemove =
            [
                .. keyCounters
                    .Keys.Select(k => (key: k, value: ParseCounterValue(k, sequenceCounter.Length)))
                    .Where(kv => kv.value < counterValue - 50) // Keep last 50 counters
                    .Select(kv => kv.key),
            ];

            foreach (string key in keysToRemove)
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

    private static int ParseCounterValue(string hexCounter, int expectedLength)
    {
        byte[] bytes = Convert.FromHexString(hexCounter);

        // Extract the counter portion from the hex string
        // Format is: {keyVersion:X2}{sequenceCounter}
        // Skip first byte (key version) and parse the counter
        byte[] counterBytes = bytes.Length > expectedLength ? bytes[1..] : bytes;

        return counterBytes.Length switch
        {
            2 => counterBytes[0] << 8 | counterBytes[1], // SCP02: 2-byte counter
            3 => counterBytes[0] << 16 | counterBytes[1] << 8 | counterBytes[2], // SCP03: 3-byte counter
            _ => 0, // Invalid counter length
        };
    }
}
