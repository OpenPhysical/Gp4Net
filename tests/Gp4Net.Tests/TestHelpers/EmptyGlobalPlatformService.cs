using System;
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
using Gp4Net.Services;

namespace Gp4Net.Tests.TestHelpers;

/// <summary>
/// Empty implementation of IGlobalPlatformService for tests that don't require GP functionality.
/// All methods return appropriate empty/default values using functional patterns.
/// </summary>
public class EmptyGlobalPlatformService : IGlobalPlatformService
{
    public ISmartCardService CardService { get; }

    public EmptyGlobalPlatformService()
    {
        // Create a minimal empty card service for testing
        var virtualCardService = new VirtualCardService();
        CardService = new TestCardService(virtualCardService);
    }

    public Task<Result<SelectResponse, SmartCardError>> SelectIsdAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Failure<SelectResponse, SmartCardError>(
            SmartCardError.NotImplementedError("EmptyGlobalPlatformService does not implement ISD selection")));
    }

    public Task<Result<ImmutableList<ApplicationInfo>, SmartCardError>> GetStatusAsync(
        GetStatusCommand.StatusSubset subset = GetStatusCommand.StatusSubset.IssuerSecurityDomain, 
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Success<ImmutableList<ApplicationInfo>, SmartCardError>(
            ImmutableList<ApplicationInfo>.Empty));
    }

    public Task<Result<byte[], SmartCardError>> GetDataAsync(
        ushort tag, 
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Success<byte[], SmartCardError>([]));
    }

    public Task<Result<SecureChannelState, SmartCardError>> EstablishSecureChannelAsync(
        KeySet keySet, 
        SecurityLevel securityLevel = SecurityLevel.CMac, 
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Failure<SecureChannelState, SmartCardError>(
            SmartCardError.NotImplementedError("EmptyGlobalPlatformService does not implement secure channel")));
    }

    public Task<Result<InstallationResult, SmartCardError>> InstallCapFileAsync(
        byte[] capFileData, 
        Maybe<InstallOptions> options = default, 
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Failure<InstallationResult, SmartCardError>(
            SmartCardError.NotImplementedError("EmptyGlobalPlatformService does not implement CAP installation")));
    }

    public Task<Result<bool, SmartCardError>> DeleteApplicationAsync(
        byte[] aid, 
        bool deleteRelated = false, 
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Success<bool, SmartCardError>(false));
    }

    public Task<Result<bool, SmartCardError>> PutKeysAsync(
        KeySet keySet, 
        byte keyVersion, 
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Success<bool, SmartCardError>(false));
    }

    public Task<Result<CplcData, SmartCardError>> GetCplcAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Failure<CplcData, SmartCardError>(
            SmartCardError.NotImplementedError("EmptyGlobalPlatformService does not implement CPLC retrieval")));
    }

    public Task<Result<bool, SmartCardError>> SetLifecycleStateAsync(
        byte[] aid, 
        LifecycleState state, 
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Success<bool, SmartCardError>(false));
    }

    public void Dispose()
    {
        CardService?.Dispose();
    }
}