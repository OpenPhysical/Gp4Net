using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Bridge service for transitioning from IRngService to UnifiedCryptoService.
/// Delegates all operations to UnifiedCryptoService.Rng static methods.
/// This class will be eliminated once all IRngService references are removed.
/// </summary>
[PublicAPI]
public sealed class SecureRngService : IRngService
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