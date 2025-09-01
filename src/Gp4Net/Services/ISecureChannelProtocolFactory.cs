using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Services;

/// <summary>
/// Factory interface for creating secure channel protocol operations.
/// Provides functional protocol operation builders for SCP02 and SCP03.
/// </summary>
[PublicAPI]
public interface ISecureChannelProtocolFactory
{
    /// <summary>
    /// Creates a secure channel establishment function for the specified keyset.
    /// </summary>
    /// <param name="keySet">The keyset to use for secure channel establishment.</param>
    /// <returns>A function that establishes a secure channel or error.</returns>
    Result<
        Func<SecurityLevel, CancellationToken, Task<Result<SecureChannelState, SmartCardError>>>,
        SmartCardError
    > CreateEstablishmentFunction(IKeySet keySet);
}
