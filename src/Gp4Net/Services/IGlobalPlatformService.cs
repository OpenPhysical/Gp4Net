using System.Collections.Immutable;
using System.Threading;
using System.Threading.Tasks;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.CardInfo;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;

namespace Gp4Net.Services
{
    /// <summary>
    /// Functional interface for GlobalPlatform operations.
    /// </summary>
    public interface IGlobalPlatformService
    {
        /// <summary>
        /// Selects the Issuer Security Domain (ISD).
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The select response.</returns>
        Task<Result<SelectResponse, SmartCardError>> SelectIsdAsync(
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Establishes a secure channel with the card.
        /// </summary>
        /// <param name="keySet">The key set to use.</param>
        /// <param name="securityLevel">The security level to establish.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The secure channel session.</returns>
        Task<Result<SecureChannelSession, SmartCardError>> EstablishSecureChannelAsync(
            KeySet keySet,
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
            InstallOptions? options = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Deletes an application from the card.
        /// </summary>
        /// <param name="aid">The application AID to delete.</param>
        /// <param name="deleteRelated">Whether to delete related objects.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Success or failure result.</returns>
        Task<Result<Unit, SmartCardError>> DeleteApplicationAsync(
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
        Task<Result<Unit, SmartCardError>> PutKeysAsync(
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
        Task<Result<Unit, SmartCardError>> SetLifecycleStateAsync(
            byte[] aid,
            LifecycleState state,
            CancellationToken cancellationToken = default);
    }
}