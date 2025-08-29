using System.Collections.Immutable;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.CardInfo;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Security;
using StatusSubset = Gp4Net.Domain.Commands.GetStatusCommand.StatusSubset;

namespace Gp4Net.Services;

/// <summary>
/// Functional interface for GlobalPlatform operations.
/// </summary>
public interface IGlobalPlatformService
{
    /// <summary>
    /// Gets the current smart card service with proper secure channel context.
    /// </summary>
    ISmartCardService CardService { get; }

    /// <summary>
    /// Selects the Issuer Security Domain (ISD).
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The select response.</returns>
    Task<Result<SelectResponse, SmartCardError>> SelectIsdAsync(
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Establishes a secure channel with the card using a resolved keyset.
    /// </summary>
    /// <param name="keySet">The key set to use.</param>
    /// <param name="securityLevel">The security level to establish.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The secure channel state.</returns>
    Task<Result<SecureChannelState, SmartCardError>> EstablishSecureChannelAsync(
        KeySet keySet,
        SecurityLevel securityLevel = SecurityLevel.CMac,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Establishes a secure channel with the card using a named keyset specification.
    /// </summary>
    /// <param name="keysetName">The keyset name (e.g., 'gp_test_keys').</param>
    /// <param name="securityLevel">The security level to establish.</param>
    /// <param name="keyVersion">The key version to use.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The secure channel state.</returns>
    Task<Result<SecureChannelState, SmartCardError>> EstablishSecureChannelAsync(
        string keysetName,
        SecurityLevel securityLevel = SecurityLevel.CMac,
        byte keyVersion = 0x01,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Establishes a secure channel with the card using explicit keys.
    /// </summary>
    /// <param name="encKey">Encryption key (hex string).</param>
    /// <param name="macKey">MAC key (hex string).</param>
    /// <param name="dekKey">DEK key (hex string).</param>
    /// <param name="keyVersion">The key version to use.</param>
    /// <param name="securityLevel">The security level to establish.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The secure channel state.</returns>
    Task<Result<SecureChannelState, SmartCardError>> EstablishSecureChannelAsync(
        string encKey,
        string macKey,
        string dekKey,
        byte keyVersion,
        SecurityLevel securityLevel = SecurityLevel.CMac,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the status of applications on the card.
    /// </summary>
    /// <param name="subset">The status subset to retrieve.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The list of application statuses.</returns>
    Task<Result<ImmutableList<ApplicationInfo>, SmartCardError>> GetStatusAsync(
        StatusSubset subset = StatusSubset.IssuerSecurityDomain,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Installs a CAP file on the card.
    /// </summary>
    /// <param name="capFileData">The CAP file data.</param>
    /// <param name="options">Installation options.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The installation result.</returns>
    Task<Result<InstallationResult, SmartCardError>> InstallCapFileAsync(
        byte[] capFileData,
        Maybe<InstallOptions> options = default,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes an application from the card.
    /// </summary>
    /// <param name="aid">The application AID to delete.</param>
    /// <param name="deleteRelated">Whether to delete related objects.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Success or failure result.</returns>
    Task<Result<bool, SmartCardError>> DeleteApplicationAsync(
        byte[] aid,
        bool deleteRelated = false,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs a PUT KEY operation to change card keys.
    /// </summary>
    /// <param name="keySet">The new key set to install.</param>
    /// <param name="keyVersion">The key version number.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Success or failure result.</returns>
    Task<Result<bool, SmartCardError>> PutKeysAsync(
        KeySet keySet,
        byte keyVersion,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the Card Production Life Cycle (CPLC) data from the card.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The CPLC data.</returns>
    Task<Result<CplcData, SmartCardError>> GetCplcAsync(
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets data from the card using GET DATA command.
    /// </summary>
    /// <param name="tag">The data tag to retrieve.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The data value.</returns>
    Task<Result<byte[], SmartCardError>> GetDataAsync(
        ushort tag,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Sets the lifecycle state of an application.
    /// </summary>
    /// <param name="aid">The application AID.</param>
    /// <param name="state">The lifecycle state to set.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Success or failure result.</returns>
    Task<Result<bool, SmartCardError>> SetLifecycleStateAsync(
        byte[] aid,
        LifecycleState state,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets comprehensive card information including CPLC and reader details.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Structured card information for display.</returns>
    Task<Result<CardInformation, SmartCardError>> GetCardInfoAsync(
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Options for installing a CAP file.
/// </summary>
public record InstallOptions(
    bool InstallApplets = true,
    bool MakeSelectable = true,
    Maybe<byte[]> InstallParameters = default);

/// <summary>
/// Comprehensive card information for display purposes.
/// Pure data structure with no formatting logic.
/// </summary>
public record CardInformation(
    Maybe<CplcData> Cplc,
    Maybe<SelectResponse> IsdInfo,
    string ReaderName,
    Maybe<string> Atr = default,
    Maybe<byte[]> HistoricalBytes = default);