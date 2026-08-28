using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Commands;

namespace Gp4Net.Domain.CapFile;

/// <summary>
/// Identifies how the Load Token is supplied for a delegated LOAD operation.
/// See GlobalPlatform Card Specification v2.3.1, Appendix C.4.1.
/// </summary>
public abstract class DelegatedLoadTokenSource
{
    private DelegatedLoadTokenSource() { }

    public sealed class Precomputed : DelegatedLoadTokenSource
    {
        internal byte[] Value { get; }
        public Precomputed(byte[] value) => Value = (byte[])(value ?? []).Clone();
    }

    public sealed class AesKey : DelegatedLoadTokenSource
    {
        internal byte[] Value { get; }
        public AesKey(byte[] value) => Value = (byte[])(value ?? []).Clone();
    }
}

/// <summary>
/// Immutable options for an AES-CMAC delegated LOAD operation.
/// See GlobalPlatform Card Specification v2.3.1, sections 11.5.2.1 and 11.6,
/// and Appendices C.4.1 and C.5.1.
/// </summary>
public sealed class DelegatedLoadOptions
{
    private readonly byte[] _securityDomainAid;
    private readonly byte[] _loadParameters;
    private readonly byte[]? _dapSecurityDomainAid;
    private readonly byte[]? _dapKey;

    public byte[] SecurityDomainAid => (byte[])_securityDomainAid.Clone();
    public DelegatedLoadTokenSource TokenSource { get; }
    public byte[] LoadParameters => (byte[])_loadParameters.Clone();
    public Maybe<byte[]> DapSecurityDomainAid => _dapSecurityDomainAid is null
        ? Maybe<byte[]>.None
        : Maybe<byte[]>.From((byte[])_dapSecurityDomainAid.Clone());
    public Maybe<byte[]> DapKey => _dapKey is null
        ? Maybe<byte[]>.None
        : Maybe<byte[]>.From((byte[])_dapKey.Clone());

    private DelegatedLoadOptions(
        byte[] securityDomainAid,
        DelegatedLoadTokenSource tokenSource,
        byte[] loadParameters,
        byte[]? dapSecurityDomainAid,
        byte[]? dapKey)
    {
        _securityDomainAid = (byte[])securityDomainAid.Clone();
        TokenSource = tokenSource;
        _loadParameters = (byte[])loadParameters.Clone();
        _dapSecurityDomainAid = dapSecurityDomainAid is null ? null : (byte[])dapSecurityDomainAid.Clone();
        _dapKey = dapKey is null ? null : (byte[])dapKey.Clone();
    }

    public static Result<DelegatedLoadOptions, SmartCardError> Create(
        byte[] securityDomainAid,
        DelegatedLoadTokenSource tokenSource,
        byte[]? loadParameters = null,
        byte[]? dapSecurityDomainAid = null,
        byte[]? dapKey = null)
    {
        if (securityDomainAid is null || securityDomainAid.Length is < 5 or > 16)
            return SmartCardError.InvalidArgument("Security Domain AID must contain 5-16 bytes.");
        if (tokenSource is null)
            return SmartCardError.InvalidArgument("A delegated Load Token source is required.");
        byte[] tokenMaterial = tokenSource switch
        {
            DelegatedLoadTokenSource.Precomputed value => value.Value,
            DelegatedLoadTokenSource.AesKey value => value.Value,
            _ => []
        };
        if (tokenSource is DelegatedLoadTokenSource.Precomputed && tokenMaterial.Length != 16)
            return SmartCardError.InvalidArgument("A precomputed AES Load Token must contain 16 bytes.");
        if (tokenSource is DelegatedLoadTokenSource.AesKey && tokenMaterial.Length is not (16 or 24 or 32))
            return SmartCardError.InvalidArgument("An AES Load Token key must contain 16, 24, or 32 bytes.");
        if ((dapSecurityDomainAid is null) != (dapKey is null))
            return SmartCardError.InvalidArgument("DAP Security Domain AID and DAP key must be supplied together.");
        if (dapSecurityDomainAid is not null && dapSecurityDomainAid.Length is < 5 or > 16)
            return SmartCardError.InvalidArgument("DAP Security Domain AID must contain 5-16 bytes.");
        if (dapKey is not null && dapKey.Length is not (16 or 24 or 32))
            return SmartCardError.InvalidArgument("An AES DAP key must contain 16, 24, or 32 bytes.");
        if ((loadParameters?.Length ?? 0) > 0xFFFF)
            return SmartCardError.InvalidArgument("Load Parameters cannot exceed 65535 bytes.");

        return new DelegatedLoadOptions(
            securityDomainAid, tokenSource, loadParameters ?? [], dapSecurityDomainAid, dapKey);
    }
}

/// <summary>
/// Builds the authenticated values used by AES delegated LOAD and DAP verification.
/// See GlobalPlatform Card Specification v2.3.1, sections B.2.2, C.3, and C.4.1.
/// </summary>
public static class DelegatedLoadCryptography
{
    /// <summary>
    /// Calculates the SHA-256 Load File Data Block Hash over the expanded load-file bytes.
    /// The input excludes the outer <c>C4</c> TLV, as specified by GlobalPlatform Card
    /// Specification v2.3.1, section C.2.
    /// </summary>
    public static Result<byte[], SmartCardError> ComputeLoadFileDataBlockHash(byte[] expandedLoadFile) =>
        expandedLoadFile is null
            ? SmartCardError.InvalidArgument("Expanded Load File Data Block is required.")
            : CryptoOperations.Hash.Sha256(expandedLoadFile);

    public static Result<byte[], SmartCardError> BuildLoadTokenInput(
        byte p1,
        byte p2,
        byte[] loadFileAid,
        byte[] securityDomainAid,
        byte[] hash,
        byte[] loadParameters)
    {
        if (loadFileAid is null || loadFileAid.Length is < 5 or > 16)
            return SmartCardError.InvalidArgument("Load File AID must contain 5-16 bytes.");
        if (securityDomainAid is null || securityDomainAid.Length is < 5 or > 16)
            return SmartCardError.InvalidArgument("Security Domain AID must contain 5-16 bytes.");
        if (hash is null || hash.Length != 32)
            return SmartCardError.InvalidArgument("AES delegated LOAD requires a 32-byte SHA-256 LFDBH.");
        loadParameters ??= [];

        var fields = new List<byte>
        {
            (byte)loadFileAid.Length
        };
        fields.AddRange(loadFileAid);
        fields.Add((byte)securityDomainAid.Length);
        fields.AddRange(securityDomainAid);
        fields.Add((byte)hash.Length);
        fields.AddRange(hash);
        fields.AddRange(EncodeBerLength(loadParameters.Length));
        fields.AddRange(loadParameters);

        // Appendix C.4.1 authenticates P1, P2, the pre-token Lc, and all
        // INSTALL [for load] fields through Load Parameters.
        var input = new List<byte> { p1, p2 };
        input.AddRange(EncodeInstallLc(fields.Count));
        input.AddRange(fields);
        return input.ToArray();
    }

    public static Result<byte[], SmartCardError> ComputeLoadToken(
        byte[] key, byte p1, byte p2, byte[] loadFileAid, byte[] securityDomainAid,
        byte[] hash, byte[] loadParameters) =>
        BuildLoadTokenInput(p1, p2, loadFileAid, securityDomainAid, hash, loadParameters)
            .Bind(input => CryptoOperations.Keys.ComputeAesCmac(key, input));

    public static Result<byte[], SmartCardError> CreateDapBlock(
        byte[] securityDomainAid, byte[] key, byte[] hash)
    {
        if (securityDomainAid is null || securityDomainAid.Length is < 5 or > 16)
            return SmartCardError.InvalidArgument("DAP Security Domain AID must contain 5-16 bytes.");
        return CryptoOperations.Keys.ComputeAesCmac(key, hash).Map(signature =>
        {
            // GP 2.3.1 section 11.6.2.3 and Table 11-58 encode each DAP as
            // E2 { 4F DAP-SD-AID, C3 Load-File-Data-Block-Signature }.
            var body = new List<byte> { 0x4F, (byte)securityDomainAid.Length };
            body.AddRange(securityDomainAid);
            body.Add(0xC3);
            body.Add(0x10);
            body.AddRange(signature);
            var result = new List<byte> { 0xE2 };
            result.AddRange(EncodeBerLength(body.Count));
            result.AddRange(body);
            return result.ToArray();
        });
    }

    public static byte[] EncodeBerLength(int length) => length switch
    {
        < 0 => throw new ArgumentOutOfRangeException(nameof(length)),
        <= 0x7F => [(byte)length],
        <= 0xFF => [0x81, (byte)length],
        <= 0xFFFF => [0x82, (byte)(length >> 8), (byte)length],
        _ => throw new ArgumentOutOfRangeException(nameof(length))
    };

    private static byte[] EncodeInstallLc(int length) => length <= 0xFF
        ? [(byte)length]
        : [0x00, (byte)(length >> 8), (byte)length];
}

/// <summary>
/// Contains the INSTALL [for load] command, LOAD commands, LFDBH, and Load Token
/// for one delegated LOAD operation. See GlobalPlatform Card Specification v2.3.1,
/// sections 11.5.2.1 and 11.6 and Appendix C.4.1.
/// </summary>
public sealed class DelegatedLoadArtifacts
{
    private readonly byte[] _hash;
    private readonly byte[] _token;
    public InstallCommand.InstallForLoadCommand InstallForLoad { get; }
    public IReadOnlyList<LoadCommand> LoadCommands { get; }
    public byte[] LoadFileDataBlockHash => (byte[])_hash.Clone();
    public byte[] LoadToken => (byte[])_token.Clone();

    private DelegatedLoadArtifacts(
        InstallCommand.InstallForLoadCommand installForLoad,
        IReadOnlyList<LoadCommand> loadCommands,
        byte[] hash,
        byte[] token)
    {
        InstallForLoad = installForLoad;
        LoadCommands = loadCommands;
        _hash = (byte[])hash.Clone();
        _token = (byte[])token.Clone();
    }

    public static Result<DelegatedLoadArtifacts, SmartCardError> Create(
        CapFileStructure capFile,
        DelegatedLoadOptions options,
        int maxBlockSize = Constants.Constants.GlobalPlatform.ApduLimits.DEFAULT_LOAD_BLOCK_SIZE)
    {
        if (capFile is null)
            return SmartCardError.InvalidArgument("CAP file is required.");
        if (options is null)
            return SmartCardError.InvalidArgument("Delegated LOAD options are required.");

        return Result.Try(
                capFile.ToBinaryFormat,
                ex => SmartCardError.InvalidData($"Unable to build Load File Data Block: {ex.Message}"))
            .Bind(expanded => DelegatedLoadCryptography.ComputeLoadFileDataBlockHash(expanded)
                .Bind(hash => ResolveToken(options, capFile.PackageAid, hash)
                    .Bind(token => BuildEncodedLoadFile(options, expanded, hash)
                        .Bind(encoded => LoadCommand.CreateFromEncodedLoadFile(encoded, maxBlockSize)
                            .Bind(loadCommands => InstallCommand.InstallForLoadCommand.Create(
                                    capFile.PackageAid,
                                    Maybe<byte[]>.From(options.LoadParameters),
                                    Maybe<byte[]>.From(options.SecurityDomainAid),
                                    Maybe<byte[]>.From(hash),
                                    Maybe<byte[]>.From(token))
                                .Map(install => new DelegatedLoadArtifacts(
                                    install, (IReadOnlyList<LoadCommand>)loadCommands, hash, token)))))));
    }

    private static Result<byte[], SmartCardError> ResolveToken(
        DelegatedLoadOptions options, byte[] packageAid, byte[] hash) => options.TokenSource switch
        {
            DelegatedLoadTokenSource.Precomputed token => Result.Success<byte[], SmartCardError>((byte[])token.Value.Clone()),
            DelegatedLoadTokenSource.AesKey key => DelegatedLoadCryptography.ComputeLoadToken(
                key.Value, 0x02, 0x00, packageAid, options.SecurityDomainAid, hash, options.LoadParameters),
            _ => Result.Failure<byte[], SmartCardError>(SmartCardError.AlgorithmNotSupported())
        };

    private static Result<byte[], SmartCardError> BuildEncodedLoadFile(
        DelegatedLoadOptions options, byte[] expanded, byte[] hash)
    {
        Result<byte[], SmartCardError> dap = options.DapKey.HasValue
            ? DelegatedLoadCryptography.CreateDapBlock(
                options.DapSecurityDomainAid.Value, options.DapKey.Value, hash)
            : Result.Success<byte[], SmartCardError>([]);
        return dap.Map(dapBlock =>
        {
            // Table 11-58 requires all DAP blocks to precede the single C4
            // Load File Data Block in the LOAD command stream.
            var result = new List<byte>(dapBlock.Length + expanded.Length + 4);
            result.AddRange(dapBlock);
            result.Add(0xC4);
            result.AddRange(DelegatedLoadCryptography.EncodeBerLength(expanded.Length));
            result.AddRange(expanded);
            return result.ToArray();
        });
    }
}

/// <summary>
/// Contains the commands and LFDBH for an ordinary LOAD authenticated by an
/// AES-CMAC DAP block. See GlobalPlatform Card Specification v2.3.1,
/// sections 11.6.2.3, B.2.2, and C.3, and Table 11-58.
/// </summary>
public sealed class DapLoadArtifacts
{
    private readonly byte[] _hash;
    public InstallCommand.InstallForLoadCommand InstallForLoad { get; }
    public IReadOnlyList<LoadCommand> LoadCommands { get; }
    public byte[] LoadFileDataBlockHash => (byte[])_hash.Clone();

    private DapLoadArtifacts(
        InstallCommand.InstallForLoadCommand installForLoad,
        IReadOnlyList<LoadCommand> loadCommands,
        byte[] hash)
    {
        InstallForLoad = installForLoad;
        LoadCommands = loadCommands;
        _hash = (byte[])hash.Clone();
    }

    public static Result<DapLoadArtifacts, SmartCardError> Create(
        CapFileStructure capFile,
        byte[] dapSecurityDomainAid,
        byte[] dapKey,
        Maybe<byte[]> targetSecurityDomainAid = default,
        Maybe<byte[]> loadParameters = default,
        int maxBlockSize = Constants.Constants.GlobalPlatform.ApduLimits.DEFAULT_LOAD_BLOCK_SIZE)
    {
        if (capFile is null)
            return SmartCardError.InvalidArgument("CAP file is required.");
        if (dapKey is null || dapKey.Length is not (16 or 24 or 32))
            return SmartCardError.InvalidArgument("AES DAP key must contain 16, 24, or 32 bytes.");

        byte[] expanded = capFile.ToBinaryFormat();
        return DelegatedLoadCryptography.ComputeLoadFileDataBlockHash(expanded)
            .Bind(hash => DelegatedLoadCryptography.CreateDapBlock(dapSecurityDomainAid, dapKey, hash)
                .Bind(dap =>
                {
                    byte[] encoded = [.. dap, 0xC4,
                        .. DelegatedLoadCryptography.EncodeBerLength(expanded.Length), .. expanded];
                    return LoadCommand.CreateFromEncodedLoadFile(encoded, maxBlockSize)
                        .Bind(commands => InstallCommand.InstallForLoadCommand.Create(
                            capFile.PackageAid,
                            loadParameters,
                            targetSecurityDomainAid,
                            Maybe<byte[]>.From(hash),
                            Maybe<byte[]>.None)
                        .Map(install => new DapLoadArtifacts(install, commands.ToArray(), hash)));
                }));
    }
}
