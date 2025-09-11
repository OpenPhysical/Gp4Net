using JetBrains.Annotations;
using WSCT.ISO7816;

namespace Gp4Net.Domain.Commands;

/// <summary>
/// Defines a fluent interface for building APDU commands.
/// </summary>
/// <typeparam name="TCommand">The command type being built.</typeparam>
[PublicAPI]
public interface ICommandBuilder<out TCommand>
{
    /// <summary>
    /// Builds the command and returns a WSCT CommandAPDU.
    /// </summary>
    /// <returns>The constructed CommandAPDU.</returns>
    CommandAPDU BuildCommand();

    /// <summary>
    /// Builds the command instance (for backwards compatibility).
    /// </summary>
    /// <returns>The constructed command.</returns>
    TCommand Build();
}

/// <summary>
/// Factory for creating command builders.
/// </summary>
[PublicAPI]
public interface ICommandBuilderFactory
{
    /// <summary>
    /// Creates a SELECT command builder.
    /// </summary>
    /// <returns>The SELECT command builder.</returns>
    ISelectCommandBuilder CreateSelectBuilder();

    /// <summary>
    /// Creates an INITIALIZE UPDATE command builder.
    /// </summary>
    /// <returns>The INITIALIZE UPDATE command builder.</returns>
    IInitializeUpdateCommandBuilder CreateInitializeUpdateBuilder();

    /// <summary>
    /// Creates an EXTERNAL AUTHENTICATE command builder.
    /// </summary>
    /// <returns>The EXTERNAL AUTHENTICATE command builder.</returns>
    IExternalAuthenticateCommandBuilder CreateExternalAuthenticateBuilder();

    /// <summary>
    /// Creates a GET STATUS command builder.
    /// </summary>
    /// <returns>The GET STATUS command builder.</returns>
    IGetStatusCommandBuilder CreateGetStatusBuilder();

    /// <summary>
    /// Creates an INSTALL command builder.
    /// </summary>
    /// <returns>The INSTALL command builder.</returns>
    IInstallCommandBuilder CreateInstallBuilder();

    /// <summary>
    /// Creates a LOAD command builder.
    /// </summary>
    /// <returns>The LOAD command builder.</returns>
    ILoadCommandBuilder CreateLoadBuilder();

    /// <summary>
    /// Creates a DELETE command builder.
    /// </summary>
    /// <returns>The DELETE command builder.</returns>
    IDeleteCommandBuilder CreateDeleteBuilder();

    /// <summary>
    /// Creates a PUT KEY command builder.
    /// </summary>
    /// <returns>The PUT KEY command builder.</returns>
    IPutKeyCommandBuilder CreatePutKeyBuilder();
}

/// <summary>
/// Builder interface for SELECT commands.
/// </summary>
[PublicAPI]
public interface ISelectCommandBuilder : ICommandBuilder<SelectCommand>
{
    /// <summary>
    /// Sets the AID to select.
    /// </summary>
    /// <param name="aid">The application identifier.</param>
    /// <returns>This builder for chaining.</returns>
    ISelectCommandBuilder WithAid(byte[] aid);

    /// <summary>
    /// Sets the selection control.
    /// </summary>
    /// <param name="control">The selection control.</param>
    /// <returns>This builder for chaining.</returns>
    ISelectCommandBuilder WithControl(SelectCommand.SelectionControl control);

    /// <summary>
    /// Sets the file control information.
    /// </summary>
    /// <param name="controlInfo">The file control information.</param>
    /// <returns>This builder for chaining.</returns>
    ISelectCommandBuilder WithControlInfo(SelectCommand.FileControlInfo controlInfo);

    /// <summary>
    /// Configures to return FCI template.
    /// </summary>
    /// <returns>This builder for chaining.</returns>
    ISelectCommandBuilder ReturnFci();

    /// <summary>
    /// Configures to return no response data.
    /// </summary>
    /// <returns>This builder for chaining.</returns>
    ISelectCommandBuilder ReturnNoData();
}

/// <summary>
/// Builder interface for INITIALIZE UPDATE commands.
/// </summary>
[PublicAPI]
public interface IInitializeUpdateCommandBuilder : ICommandBuilder<InitializeUpdateCommand>
{
    /// <summary>
    /// Sets the key version.
    /// </summary>
    /// <param name="keyVersion">The key version.</param>
    /// <returns>This builder for chaining.</returns>
    IInitializeUpdateCommandBuilder WithKeyVersion(byte keyVersion);

    /// <summary>
    /// Sets the key identifier.
    /// </summary>
    /// <param name="keyIdentifier">The key identifier.</param>
    /// <returns>This builder for chaining.</returns>
    IInitializeUpdateCommandBuilder WithKeyIdentifier(byte keyIdentifier);

    /// <summary>
    /// Sets the host challenge.
    /// </summary>
    /// <param name="hostChallenge">The host challenge (8 bytes).</param>
    /// <returns>This builder for chaining.</returns>
    IInitializeUpdateCommandBuilder WithHostChallenge(byte[] hostChallenge);

    /// <summary>
    /// Generates a random host challenge.
    /// </summary>
    /// <returns>This builder for chaining.</returns>
    IInitializeUpdateCommandBuilder WithRandomHostChallenge();
}

/// <summary>
/// Builder interface for EXTERNAL AUTHENTICATE commands.
/// </summary>
[PublicAPI]
public interface IExternalAuthenticateCommandBuilder : ICommandBuilder<ExternalAuthenticateCommand>
{
    /// <summary>
    /// Sets the security level.
    /// </summary>
    /// <param name="securityLevel">The security level.</param>
    /// <returns>This builder for chaining.</returns>
    IExternalAuthenticateCommandBuilder WithSecurityLevel(SecurityLevel securityLevel);

    /// <summary>
    /// Sets the host cryptogram.
    /// </summary>
    /// <param name="hostCryptogram">The host cryptogram (8 bytes).</param>
    /// <returns>This builder for chaining.</returns>
    IExternalAuthenticateCommandBuilder WithHostCryptogram(byte[] hostCryptogram);

    /// <summary>
    /// Sets the MAC.
    /// </summary>
    /// <param name="mac">The MAC (8 bytes, optional).</param>
    /// <returns>This builder for chaining.</returns>
    IExternalAuthenticateCommandBuilder WithMac(byte[] mac);
}

/// <summary>
/// Builder interface for GET STATUS commands.
/// </summary>
[PublicAPI]
public interface IGetStatusCommandBuilder : ICommandBuilder<GetStatusCommand>
{
    /// <summary>
    /// Sets the status subset to query.
    /// </summary>
    /// <param name="subset">The status subset.</param>
    /// <returns>This builder for chaining.</returns>
    IGetStatusCommandBuilder WithSubset(GetStatusCommand.StatusSubset subset);

    /// <summary>
    /// Sets the response format.
    /// </summary>
    /// <param name="format">The response format.</param>
    /// <returns>This builder for chaining.</returns>
    IGetStatusCommandBuilder WithFormat(GetStatusCommand.ResponseFormat format);

    /// <summary>
    /// Sets search criteria.
    /// </summary>
    /// <param name="searchCriteria">The search criteria (AID).</param>
    /// <returns>This builder for chaining.</returns>
    IGetStatusCommandBuilder WithSearchCriteria(byte[] searchCriteria);

    /// <summary>
    /// Configures to query the ISD.
    /// </summary>
    /// <returns>This builder for chaining.</returns>
    IGetStatusCommandBuilder QueryIsd();

    /// <summary>
    /// Configures to query applications and supplementary domains.
    /// </summary>
    /// <returns>This builder for chaining.</returns>
    IGetStatusCommandBuilder QueryApplications();

    /// <summary>
    /// Configures to query load files.
    /// </summary>
    /// <returns>This builder for chaining.</returns>
    IGetStatusCommandBuilder QueryLoadFiles();
}

/// <summary>
/// Builder interface for INSTALL commands.
/// </summary>
[PublicAPI]
public interface IInstallCommandBuilder : ICommandBuilder<InstallCommand>
{
    /// <summary>
    /// Configures for INSTALL [for load].
    /// </summary>
    /// <returns>This builder for chaining.</returns>
    IInstallCommandBuilder ForLoad();

    /// <summary>
    /// Configures for INSTALL [for install].
    /// </summary>
    /// <returns>This builder for chaining.</returns>
    IInstallCommandBuilder ForInstall();

    /// <summary>
    /// Configures for INSTALL [for make selectable].
    /// </summary>
    /// <returns>This builder for chaining.</returns>
    IInstallCommandBuilder ForMakeSelectable();

    /// <summary>
    /// Sets the package AID.
    /// </summary>
    /// <param name="packageAid">The package AID.</param>
    /// <returns>This builder for chaining.</returns>
    IInstallCommandBuilder WithPackageAid(byte[] packageAid);

    /// <summary>
    /// Sets the security domain AID.
    /// </summary>
    /// <param name="securityDomainAid">The security domain AID.</param>
    /// <returns>This builder for chaining.</returns>
    IInstallCommandBuilder WithSecurityDomainAid(byte[] securityDomainAid);
}

/// <summary>
/// Builder interface for LOAD commands.
/// </summary>
[PublicAPI]
public interface ILoadCommandBuilder : ICommandBuilder<LoadCommand>
{
    /// <summary>
    /// Sets the block number.
    /// </summary>
    /// <param name="blockNumber">The block number.</param>
    /// <returns>This builder for chaining.</returns>
    ILoadCommandBuilder WithBlockNumber(byte blockNumber);

    /// <summary>
    /// Sets the data to load.
    /// </summary>
    /// <param name="data">The data.</param>
    /// <returns>This builder for chaining.</returns>
    ILoadCommandBuilder WithData(byte[] data);

    /// <summary>
    /// Marks this as the final block.
    /// </summary>
    /// <returns>This builder for chaining.</returns>
    ILoadCommandBuilder AsFinalBlock();

    /// <summary>
    /// Sets the total CAP size (for first block).
    /// </summary>
    /// <param name="totalSize">The total CAP size.</param>
    /// <returns>This builder for chaining.</returns>
    ILoadCommandBuilder WithTotalCapSize(uint totalSize);
}

/// <summary>
/// Builder interface for DELETE commands.
/// </summary>
[PublicAPI]
public interface IDeleteCommandBuilder : ICommandBuilder<DeleteCommand>
{
    /// <summary>
    /// Adds an AID to delete.
    /// </summary>
    /// <param name="aid">The AID to delete.</param>
    /// <returns>This builder for chaining.</returns>
    IDeleteCommandBuilder WithAid(byte[] aid);

    /// <summary>
    /// Configures to delete related objects.
    /// </summary>
    /// <returns>This builder for chaining.</returns>
    IDeleteCommandBuilder WithRelatedObjects();

    /// <summary>
    /// Configures for key deletion.
    /// </summary>
    /// <returns>This builder for chaining.</returns>
    IDeleteCommandBuilder ForKeys();
}

/// <summary>
/// Builder interface for PUT KEY commands.
/// </summary>
[PublicAPI]
public interface IPutKeyCommandBuilder : ICommandBuilder<PutKeyCommand>
{
    /// <summary>
    /// Sets the key usage qualifier.
    /// </summary>
    /// <param name="qualifier">The usage qualifier.</param>
    /// <returns>This builder for chaining.</returns>
    IPutKeyCommandBuilder WithUsageQualifier(PutKeyCommand.KeyUsageQualifier qualifier);

    /// <summary>
    /// Sets the KEK identifier.
    /// </summary>
    /// <param name="kekIdentifier">The KEK identifier.</param>
    /// <returns>This builder for chaining.</returns>
    IPutKeyCommandBuilder WithKekIdentifier(PutKeyCommand.KeyEncryptionKeyIdentifier kekIdentifier);

    /// <summary>
    /// Adds a key data block.
    /// </summary>
    /// <param name="keyDataBlock">The key data block.</param>
    /// <returns>This builder for chaining.</returns>
    IPutKeyCommandBuilder WithKeyDataBlock(KeyDataBlock keyDataBlock);

    /// <summary>
    /// Configures for multiple keys.
    /// </summary>
    /// <returns>This builder for chaining.</returns>
    IPutKeyCommandBuilder ForMultipleKeys();
}
