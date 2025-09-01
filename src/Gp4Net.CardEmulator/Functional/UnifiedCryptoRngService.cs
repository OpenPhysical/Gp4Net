using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Bridge service that adapts UnifiedCryptoService.Rng to the IRngService interface.
/// Uses the globally configured UnifiedCryptoService RNG mode (secure or deterministic).
/// This bridge will be eliminated once all IRngService references are removed from the codebase.
/// </summary>
[PublicAPI]
internal sealed class UnifiedCryptoRngService : IRngService
{
    /// <inheritdoc />
    public Result<byte[], SmartCardError> GetBytes(int length) =>
        CryptoService.Rng.GenerateBytes(length);

    /// <inheritdoc />
    public bool HasEnoughEntropy(int requiredBytes) => 
        CryptoService.Rng.HasEnoughEntropy(requiredBytes);

    /// <inheritdoc />
    public Maybe<int> RemainingEntropy => 
        CryptoService.Rng.RemainingEntropy;
}