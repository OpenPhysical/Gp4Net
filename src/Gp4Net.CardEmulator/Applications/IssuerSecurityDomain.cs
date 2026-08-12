using System;
using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Shared;
using JetBrains.Annotations;
using static Gp4Net.Constants.Constants.GlobalPlatform;
using ApduIns = Gp4Net.Constants.Apdu.Instructions;
using ApplicationApduResponse = Gp4Net.CardEmulator.Applications.ApduResponse;
using GpConstants = Gp4Net.Constants.Constants;
using GpIns = Gp4Net.Constants.Constants.GlobalPlatform.Ins;

namespace Gp4Net.CardEmulator.Applications;

/// <summary>
/// Issuer Security Domain - the default application on every GlobalPlatform card.
/// Handles card management commands per GP Card Specification Section 6.4.1.
/// Maintains functional programming principles with immutable state.
/// </summary>
[PublicAPI]
public sealed record IssuerSecurityDomain : IApplication
{
    // GP Card Specification v2.3.1, §6.6.2.
    private const Privilege InitialPrivileges =
        Privilege.SecurityDomain
        | Privilege.AuthorizedManagement
        | Privilege.GlobalRegistry
        | Privilege.GlobalLock
        | Privilege.GlobalDelete
        | Privilege.TokenVerification
        | Privilege.CardLock
        | Privilege.CardTerminate
        | Privilege.TrustedPath
        | Privilege.CvmManagement
        | Privilege.CardReset
        | Privilege.FinalApplication
        | Privilege.ReceiptGeneration;

    public ImmutableArray<byte> Aid { get; init; }
    public string Name { get; init; } = "ISD";
    public byte LifecycleState { get; init; }
    public CardLifecycleState CardLifecycleState => (CardLifecycleState)LifecycleState;
    public Privilege Privileges { get; init; }
    public ImmutableArray<byte> AssociatedSecurityDomainAid { get; init; }

    // ISD-specific state
    public ImmutableDictionary<byte, IKeySet> InstalledKeys { get; init; }
    public ImmutableDictionary<ushort, byte[]> DataObjects { get; init; }
    public byte DefaultKeyVersion { get; init; }
    public byte ScpVersion { get; init; }
    public byte ScpImplementation { get; init; }

    private IssuerSecurityDomain(
        ImmutableArray<byte> aid,
        CardLifecycleState lifecycleState,
        Privilege privileges,
        ImmutableDictionary<byte, IKeySet> installedKeys,
        ImmutableDictionary<ushort, byte[]> dataObjects,
        byte defaultKeyVersion,
        byte scpVersion,
        byte scpImplementation
    )
    {
        Aid = aid;
        LifecycleState = (byte)lifecycleState;
        Privileges = privileges;
        AssociatedSecurityDomainAid = aid; // ISD is its own security domain
        InstalledKeys = installedKeys;
        DataObjects = dataObjects;
        DefaultKeyVersion = defaultKeyVersion;
        ScpVersion = scpVersion;
        ScpImplementation = scpImplementation;
    }

    /// <summary>
    /// Creates new ISD with default configuration per GP specification.
    /// Reference: GP Card Specification v2.3.1 Section 6.4.1
    /// </summary>
    public static Result<IssuerSecurityDomain, SmartCardError> Create(
        ImmutableArray<byte> aid,
        byte scpVersion = 0x02,
        byte scpImplementation = 0x15
    )
    {
        if (aid.Length < 5 || aid.Length > 16)
        {
            return Result.Failure<IssuerSecurityDomain, SmartCardError>(
                Errors.InvalidLength("AID", 5, aid.Length)
            );
        }

        // Create default test keys
        var defaultKeys = ImmutableDictionary<byte, IKeySet>.Empty.Add(
            0xFF,
            CreateDefaultTestKeySet(scpVersion)
        );

        return Result.Success<IssuerSecurityDomain, SmartCardError>(
            new IssuerSecurityDomain(
                aid: aid,
                lifecycleState: CardLifecycleState.OpReady,
                privileges: InitialPrivileges,
                installedKeys: defaultKeys,
                dataObjects: CreateDefaultDataObjects(),
                defaultKeyVersion: 0xFF,
                scpVersion: scpVersion,
                scpImplementation: scpImplementation
            )
        );
    }

    /// <summary>
    /// Creates new ISD with specific data objects from card configuration.
    /// Reference: GP Card Specification v2.3.1 Section 6.4.1
    /// </summary>
    public static Result<IssuerSecurityDomain, SmartCardError> CreateWithDataObjects(
        ImmutableArray<byte> aid,
        ImmutableDictionary<ushort, byte[]> dataObjects,
        byte scpVersion = 0x02,
        byte scpImplementation = 0x15
    )
    {
        if (aid.Length < 5 || aid.Length > 16)
        {
            return Result.Failure<IssuerSecurityDomain, SmartCardError>(
                Errors.InvalidLength("AID", 5, aid.Length)
            );
        }

        // Create default test keys
        var defaultKeysBuilder = ImmutableDictionary.CreateBuilder<byte, IKeySet>();
        defaultKeysBuilder.Add(0xFF, CreateDefaultTestKeySet(scpVersion));
        var defaultKeys = defaultKeysBuilder.ToImmutable();

        return Result.Success<IssuerSecurityDomain, SmartCardError>(
            new IssuerSecurityDomain(
                aid: aid,
                lifecycleState: CardLifecycleState.OpReady,
                privileges: InitialPrivileges,
                installedKeys: defaultKeys,
                dataObjects: dataObjects,
                defaultKeyVersion: 0xFF,
                scpVersion: scpVersion,
                scpImplementation: scpImplementation
            )
        );
    }

    /// <summary>
    /// Processes APDU commands specific to ISD per GP specification.
    /// Routes to appropriate command handlers based on instruction.
    /// Reference: GP Card Specification v2.3.1 Section 11
    /// </summary>
    public Result<ApplicationCommandResult, SmartCardError> ProcessCommand(
        byte[] command,
        CardState cardState,
        CardConfiguration config,
        IRngContext rngContext
    )
    {
        if (command.Length < 4)
        {
            return Result.Success<ApplicationCommandResult, SmartCardError>(
                new ApplicationCommandResult(this, cardState, ApplicationApduResponse.WrongLength())
            );
        }

        byte instruction = command[1];

        return instruction switch
        {
            ApduIns.GET_DATA => ProcessGetData(command, cardState, config, rngContext),
            _
                => Result.Success<ApplicationCommandResult, SmartCardError>(
                    new ApplicationCommandResult(
                        this,
                        cardState,
                        ApplicationApduResponse.InstructionNotSupported()
                    )
                ),
        };
    }

    public bool SupportsInstruction(byte instruction)
    {
        return instruction switch
        {
            ApduIns.GET_DATA => true,
            _ => false,
        };
    }

    public Maybe<Privilege> GetRequiredPrivileges(byte instruction)
    {
        return instruction switch
        {
            // GET DATA requires no special privileges
            ApduIns.GET_DATA
                => Maybe<Privilege>.None,

            _ => Maybe<Privilege>.None,
        };
    }

    public Result<IApplication, SmartCardError> WithLifecycleState(byte newState)
    {
        if (!GlobalPlatformLifecycle.IsCardState(newState))
        {
            return Result.Failure<IApplication, SmartCardError>(
                SmartCardError.InvalidData($"Invalid card lifecycle state: 0x{newState:X2}")
            );
        }

        var target = (CardLifecycleState)newState;
        return GlobalPlatformLifecycle.CanTransitionCard(CardLifecycleState, target)
            ? Result.Success<IApplication, SmartCardError>(this with { LifecycleState = newState })
            : Result.Failure<IApplication, SmartCardError>(SmartCardError.ConditionsNotSatisfied());
    }

    public IApplication WithPrivileges(Privilege newPrivileges)
    {
        return this with { Privileges = newPrivileges };
    }

    #region Command Processors

    private Result<ApplicationCommandResult, SmartCardError> ProcessGetData(
        byte[] command,
        CardState cardState,
        CardConfiguration config,
        IRngContext rngContext
    )
    {
        if (command.Length < 5)
        {
            return Result.Success<ApplicationCommandResult, SmartCardError>(
                new ApplicationCommandResult(this, cardState, ApplicationApduResponse.WrongLength())
            );
        }

        // P1P2 contains tag
        ushort tag = (ushort)((command[2] << 8) | command[3]);

        // Check if we have this data object using functional pattern
        return DataObjects.TryGetValue(tag, out var data)
            ? Result.Success<ApplicationCommandResult, SmartCardError>(
                new ApplicationCommandResult(this, cardState, ApplicationApduResponse.Success(data))
            )
            : Result.Success<ApplicationCommandResult, SmartCardError>(
                new ApplicationCommandResult(
                    this,
                    cardState,
                    ApplicationApduResponse.Error(
                        GpConstants.StatusWords.Legacy.ReferencedDataNotFound
                    )
                )
            );
    }

    #endregion

    #region Helper Methods

    private static IKeySet CreateDefaultTestKeySet(byte scpVersion)
    {
        var testKey = new byte[]
        {
            0x40,
            0x41,
            0x42,
            0x43,
            0x44,
            0x45,
            0x46,
            0x47,
            0x48,
            0x49,
            0x4A,
            0x4B,
            0x4C,
            0x4D,
            0x4E,
            0x4F,
        };

        return scpVersion switch
        {
            0x02 => Scp02KeySet.Create(testKey, testKey, testKey).Value,
            0x03 => Scp03KeySet.Create(testKey, testKey, testKey).Value,
            _ => Scp02KeySet.Create(testKey, testKey, testKey).Value,
        };
    }

    private static ImmutableDictionary<ushort, byte[]> CreateDefaultDataObjects()
    {
        return ImmutableDictionary<ushort, byte[]>
            .Empty
            // CPLC is an industry data object, not defined by GP Card Specification v2.3.1.
            .Add(0x9F7F, [0x9F, 0x7F, 0x2A, .. new byte[42]])
            // Card Data
            .Add(0x0066, [0x00, 0x66, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #endregion
}
