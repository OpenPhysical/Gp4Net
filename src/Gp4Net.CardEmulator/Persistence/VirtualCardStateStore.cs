using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using static Gp4Net.Constants.Constants.GlobalPlatform;
using StoredExecutableModule = Gp4Net.CardEmulator.Functional.ExecutableModule;

namespace Gp4Net.CardEmulator.Persistence;

/// <summary>Versioned, authenticated persistence for virtual-card nonvolatile state.</summary>
public static class VirtualCardStateStore
{
    private const int FORMAT_VERSION = 1;
    private const string ALGORITHM = "aes-256-gcm";

    public static UnitResult<SmartCardError> Save(VirtualCard card, string path, byte[] rootKey) =>
        ValidateRootKey(rootKey)
            .Bind(() => CreateEnvelope(card, rootKey))
            .Bind(envelope => WriteAtomically(path, JsonSerializer.Serialize(envelope)));

    public static Result<CardState, SmartCardError> Load(
        string path,
        CardConfiguration configuration,
        byte[] rootKey
    ) =>
        ValidateRootKey(rootKey)
            .Bind(() => ReadEnvelope(path))
            .Bind(envelope => ValidateEnvelope(envelope, configuration))
            .Bind(envelope => DecryptSnapshot(envelope, rootKey))
            .Bind(snapshot => Restore(snapshot, configuration));

    private static Result<PersistenceEnvelope, SmartCardError> CreateEnvelope(
        VirtualCard card,
        byte[] rootKey
    )
    {
        CardSnapshot snapshot = CardSnapshot.From(card.CurrentState);
        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(snapshot);
        byte[] fingerprint = ComputeProfileFingerprint(card.Configuration);
        byte[] key = DeriveStorageKey(rootKey, snapshot.Uuid, fingerprint);

        using var encryption = new CardStateEncryption();
        return CardUuid
            .FromGuid(snapshot.Uuid)
            .Bind(uuid => encryption.Encrypt(key, plaintext, uuid))
            .Map(payload => new PersistenceEnvelope(
                FORMAT_VERSION,
                ALGORITHM,
                snapshot.Uuid,
                Convert.ToHexString(fingerprint),
                payload.Iv,
                payload.Ciphertext,
                payload.AuthTag
            ));
    }

    private static Result<PersistenceEnvelope, SmartCardError> ReadEnvelope(string path) =>
        Result
            .Try(
                () => JsonSerializer.Deserialize<PersistenceEnvelope>(File.ReadAllText(path)),
                ex => SmartCardError.InvalidData($"Unable to read virtual-card state: {ex.Message}")
            )
            .Bind(envelope =>
                envelope is { }
                    ? Result.Success<PersistenceEnvelope, SmartCardError>(envelope)
                    : Result.Failure<PersistenceEnvelope, SmartCardError>(
                        SmartCardError.InvalidData("Virtual-card state is empty")
                    )
            );

    private static Result<PersistenceEnvelope, SmartCardError> ValidateEnvelope(
        PersistenceEnvelope envelope,
        CardConfiguration configuration
    )
    {
        if (envelope.Version != FORMAT_VERSION || envelope.Algorithm != ALGORITHM)
            return SmartCardError.InvalidData("Unsupported virtual-card state format");

        string expected = Convert.ToHexString(ComputeProfileFingerprint(configuration));
        return string.Equals(expected, envelope.ProfileFingerprint, StringComparison.Ordinal)
            ? Result.Success<PersistenceEnvelope, SmartCardError>(envelope)
            : Result.Failure<PersistenceEnvelope, SmartCardError>(
                SmartCardError.InvalidData("Virtual-card state belongs to a different profile")
            );
    }

    private static Result<CardSnapshot, SmartCardError> DecryptSnapshot(
        PersistenceEnvelope envelope,
        byte[] rootKey
    )
    {
        return Result
            .Try(
                () => Convert.FromHexString(envelope.ProfileFingerprint),
                ex => SmartCardError.InvalidData($"Invalid profile fingerprint: {ex.Message}")
            )
            .Bind(fingerprint => DecryptSnapshot(envelope, rootKey, fingerprint));
    }

    private static Result<CardSnapshot, SmartCardError> DecryptSnapshot(
        PersistenceEnvelope envelope,
        byte[] rootKey,
        byte[] fingerprint
    )
    {
        byte[] key = DeriveStorageKey(rootKey, envelope.Uuid, fingerprint);
        using var encryption = new CardStateEncryption();
        var payload = new EncryptedPayload(
            envelope.Algorithm,
            envelope.Iv,
            envelope.Ciphertext,
            envelope.AuthenticationTag
        );

        return CardUuid
            .FromGuid(envelope.Uuid)
            .Bind(uuid => encryption.Decrypt(key, payload, uuid))
            .Bind(bytes =>
                Result.Try(
                    () => JsonSerializer.Deserialize<CardSnapshot>(bytes),
                    ex => SmartCardError.InvalidData($"Invalid virtual-card snapshot: {ex.Message}")
                )
            )
            .Bind(snapshot =>
                snapshot is { }
                    ? Result.Success<CardSnapshot, SmartCardError>(snapshot)
                    : Result.Failure<CardSnapshot, SmartCardError>(
                        SmartCardError.InvalidData("Virtual-card snapshot is empty")
                    )
            );
    }

    private static Result<CardState, SmartCardError> Restore(
        CardSnapshot snapshot,
        CardConfiguration configuration
    ) =>
        CardUuid
            .FromGuid(snapshot.Uuid)
            .Bind(uuid =>
            {
                var keysBuilder = ImmutableDictionary.CreateBuilder<byte, IKeySet>();
                foreach (KeySnapshot keySnapshot in snapshot.Keys)
                {
                    Result<IKeySet, SmartCardError> keyResult = ToKeySet(keySnapshot);
                    if (keyResult.IsFailure)
                        return Result.Failure<CardState, SmartCardError>(keyResult.Error);

                    keysBuilder[keyResult.Value.KeyVersion] = keyResult.Value;
                }

                var components = snapshot.KeyComponents.ToImmutableDictionary(
                    component => new KeyReference(component.Version, component.Identifier),
                    component => new StoredKeyComponent(
                        component.Type,
                        component.Value.ToImmutableArray(),
                        component.CheckValue.ToImmutableArray()
                    )
                );
                CardState state = CardState.CreateWithUuid(uuid) with
                {
                    ScpVersion = snapshot.ScpVersion,
                    ScpImplementation = (ScpImplementation)snapshot.ScpImplementation,
                    DataObjects = snapshot.DataObjects.ToImmutableDictionary(
                        item => item.Tag,
                        item => item.Value
                    ),
                    Applications = snapshot.Applications.ToImmutableDictionary(
                        app => Convert.ToHexString(app.Aid),
                        app => new InstalledApplication(
                            app.Aid,
                            app.ExecutableModuleAid,
                            app.Lifecycle,
                            (Constants.Constants.GlobalPlatform.Privilege)app.Privileges,
                            ImmutableDictionary<string, byte[]>.Empty
                        )
                    ),
                    LoadFiles = snapshot
                        .LoadFiles.Select(load => new LoadFile(
                            load.Aid,
                            load.SecurityDomainAid,
                            load.Lifecycle,
                            load.Modules.Select(module => new StoredExecutableModule(
                                    module,
                                    load.Lifecycle
                                ))
                                .ToImmutableList()
                        ))
                        .ToImmutableList(),
                    InstalledKeys = keysBuilder.ToImmutable(),
                    InstalledKeyComponents = components,
                    DefaultKeyVersion = snapshot.DefaultKeyVersion,
                    SequenceCounters = snapshot.SequenceCounters.ToImmutableDictionary(
                        counter => counter.Version,
                        counter => counter.Value
                    ),
                    CardLifecycleState = (CardLifecycleState)snapshot.CardLifecycle,
                };

                return CardStateTransitions.InitializeApplicationRegistryWithDataObjects(
                    state,
                    configuration.IsdAid.ToImmutableArray(),
                    state.DataObjects
                );
            });

    private static Result<IKeySet, SmartCardError> ToKeySet(KeySnapshot key) =>
        key.Protocol switch
        {
            0x02
                => Scp02KeySet
                    .Create(key.Enc, key.Mac, key.Dek, key.Version, key.Identifier)
                    .Map(value => (IKeySet)value),
            0x03
                => Scp03KeySet
                    .Create(key.Enc, key.Mac, key.Dek, key.Version, key.Identifier)
                    .Map(value => (IKeySet)value),
            _
                => Result.Failure<IKeySet, SmartCardError>(
                    SmartCardError.InvalidData(
                        $"Unsupported persisted SCP version {key.Protocol:X2}"
                    )
                ),
        };

    private static byte[] ComputeProfileFingerprint(CardConfiguration configuration)
    {
        byte[] material = configuration
            .Atr.Concat(configuration.IsdAid)
            .Concat([configuration.DefaultScpVersion, (byte)configuration.DefaultScpImplementation])
            .Concat(Encoding.UTF8.GetBytes(configuration.CardType))
            .ToArray();
        return CryptoOperations.Hash.Sha256(material).Value;
    }

    private static byte[] DeriveStorageKey(byte[] rootKey, Guid uuid, byte[] fingerprint)
    {
        byte[] material = rootKey
            .Concat(uuid.ToByteArray())
            .Concat(fingerprint)
            .Concat(Encoding.UTF8.GetBytes("gp4net-virtual-card-state/v1"))
            .ToArray();
        return CryptoOperations.Hash.Sha256(material).Value;
    }

    private static UnitResult<SmartCardError> ValidateRootKey(byte[] rootKey) =>
        rootKey.Length == 32
            ? UnitResult.Success<SmartCardError>()
            : UnitResult.Failure(
                SmartCardError.InvalidArgument("Virtual-card state key must contain 32 bytes")
            );

    private static UnitResult<SmartCardError> WriteAtomically(string path, string content) =>
        Result.Try(
            () =>
            {
                string fullPath = Path.GetFullPath(path);
                string directory = Path.GetDirectoryName(fullPath) ?? ".";
                Directory.CreateDirectory(directory);
                string temporaryPath = Path.Combine(
                    directory,
                    $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp"
                );
                File.WriteAllText(temporaryPath, content);
                File.Move(temporaryPath, fullPath, true);
            },
            ex =>
                SmartCardError.CommunicationError(
                    $"Unable to save virtual-card state: {ex.Message}"
                )
        );

    private sealed record PersistenceEnvelope(
        int Version,
        string Algorithm,
        Guid Uuid,
        string ProfileFingerprint,
        byte[] Iv,
        byte[] Ciphertext,
        byte[] AuthenticationTag
    );

    private sealed record DataObjectSnapshot(ushort Tag, byte[] Value);

    private sealed record CounterSnapshot(byte Version, byte[] Value);

    private sealed record ApplicationSnapshot(
        byte[] Aid,
        byte[] ExecutableModuleAid,
        byte Lifecycle,
        int Privileges
    );

    private sealed record LoadFileSnapshot(
        byte[] Aid,
        byte[] SecurityDomainAid,
        byte Lifecycle,
        byte[][] Modules
    );

    private sealed record KeySnapshot(
        byte Protocol,
        byte Version,
        byte Identifier,
        byte[] Enc,
        byte[] Mac,
        byte[] Dek
    );

    private sealed record KeyComponentSnapshot(
        byte Version,
        byte Identifier,
        byte Type,
        byte[] Value,
        byte[] CheckValue
    );

    private sealed record CardSnapshot(
        Guid Uuid,
        byte ScpVersion,
        byte ScpImplementation,
        byte CardLifecycle,
        byte DefaultKeyVersion,
        DataObjectSnapshot[] DataObjects,
        ApplicationSnapshot[] Applications,
        LoadFileSnapshot[] LoadFiles,
        KeySnapshot[] Keys,
        KeyComponentSnapshot[] KeyComponents,
        CounterSnapshot[] SequenceCounters
    )
    {
        public static CardSnapshot From(CardState state) =>
            new(
                state.Uuid.ToGuid(),
                state.ScpVersion,
                (byte)state.ScpImplementation,
                (byte)state.CardLifecycleState,
                state.DefaultKeyVersion,
                state
                    .DataObjects.Select(item => new DataObjectSnapshot(item.Key, item.Value))
                    .ToArray(),
                state
                    .Applications.Values.Select(app => new ApplicationSnapshot(
                        app.Aid,
                        app.ExecutableModuleAid,
                        app.LifecycleState,
                        (int)app.Privileges
                    ))
                    .ToArray(),
                state
                    .LoadFiles.Select(load => new LoadFileSnapshot(
                        load.Aid,
                        load.AssociatedSecurityDomainAid,
                        load.LifecycleState,
                        load.ExecutableModules.Select(module => module.Aid).ToArray()
                    ))
                    .ToArray(),
                state
                    .InstalledKeys.Values.Select(key => new KeySnapshot(
                        key is Scp03KeySet ? (byte)0x03 : (byte)0x02,
                        key.KeyVersion,
                        key.KeyId,
                        key.EncKey,
                        key.MacKey,
                        key.DekKey
                    ))
                    .ToArray(),
                state
                    .InstalledKeyComponents.Select(item => new KeyComponentSnapshot(
                        item.Key.Version,
                        item.Key.Identifier,
                        item.Value.Type,
                        item.Value.Value.ToArray(),
                        item.Value.CheckValue.ToArray()
                    ))
                    .ToArray(),
                state
                    .SequenceCounters.Select(item => new CounterSnapshot(item.Key, item.Value))
                    .ToArray()
            );
    }
}
