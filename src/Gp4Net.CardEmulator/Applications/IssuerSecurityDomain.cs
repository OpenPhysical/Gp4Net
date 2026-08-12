using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Keys;
using Gp4Net.Shared;
using JetBrains.Annotations;
using static Gp4Net.Constants.Constants.GlobalPlatform;
using ApduIns = Gp4Net.Constants.Apdu.Instructions;
using ApplicationApduResponse = Gp4Net.CardEmulator.Applications.ApduResponse;
using CoreApduResponse = Gp4Net.CardEmulator.Core.ApduResponse;
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
    public ImmutableArray<byte> Aid { get; init; }
    public string Name { get; init; } = "ISD";
    public LifecycleState LifecycleState { get; init; }
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
        LifecycleState lifecycleState,
        Privilege privileges,
        ImmutableDictionary<byte, IKeySet> installedKeys,
        ImmutableDictionary<ushort, byte[]> dataObjects,
        byte defaultKeyVersion,
        byte scpVersion,
        byte scpImplementation
    )
    {
        Aid = aid;
        LifecycleState = lifecycleState;
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
                ErrorFactory.InvalidLength("AID", 5, aid.Length)
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
                lifecycleState: LifecycleState.Selectable,
                privileges: Privilege.SecurityDomain | Privilege.AuthorizedManagement,
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
                ErrorFactory.InvalidLength("AID", 5, aid.Length)
            );
        }

        // Create default test keys
        var defaultKeysBuilder = ImmutableDictionary.CreateBuilder<byte, IKeySet>();
        defaultKeysBuilder.Add(0xFF, CreateDefaultTestKeySet(scpVersion));
        var defaultKeys = defaultKeysBuilder.ToImmutable();

        return Result.Success<IssuerSecurityDomain, SmartCardError>(
            new IssuerSecurityDomain(
                aid: aid,
                lifecycleState: LifecycleState.Selectable,
                privileges: Privilege.SecurityDomain | Privilege.AuthorizedManagement,
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
            GpIns.INITIALIZE_UPDATE
                => ProcessInitializeUpdate(command, cardState, config, rngContext),
            ApduIns.EXTERNAL_AUTHENTICATE
                => ProcessExternalAuthenticate(command, cardState, config, rngContext),
            GpIns.INSTALL => ProcessInstall(command, cardState, config, rngContext),
            GpIns.LOAD => ProcessLoad(command, cardState, config, rngContext),
            GpIns.DELETE => ProcessDelete(command, cardState, config, rngContext),
            GpIns.GET_STATUS => ProcessGetStatus(command, cardState, config, rngContext),
            ApduIns.GET_DATA => ProcessGetData(command, cardState, config, rngContext),
            GpIns.PUT_KEY => ProcessPutKey(command, cardState, config, rngContext),
            GpIns.STORE_DATA => ProcessStoreData(command, cardState, config, rngContext),
            GpIns.SET_STATUS => ProcessSetStatus(command, cardState, config, rngContext),
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
            GpIns.INITIALIZE_UPDATE => true,
            ApduIns.EXTERNAL_AUTHENTICATE => true,
            GpIns.INSTALL => true,
            GpIns.LOAD => true,
            GpIns.DELETE => true,
            GpIns.GET_STATUS => true,
            ApduIns.GET_DATA => true,
            GpIns.PUT_KEY => true,
            GpIns.STORE_DATA => true,
            GpIns.SET_STATUS => true,
            _ => false,
        };
    }

    public Maybe<Privilege> GetRequiredPrivileges(byte instruction)
    {
        return instruction switch
        {
            // Secure channel establishment requires no special privileges
            GpIns.INITIALIZE_UPDATE
                => Maybe<Privilege>.None,
            ApduIns.EXTERNAL_AUTHENTICATE => Maybe<Privilege>.None,

            // Card management requires Authorized Management
            GpIns.INSTALL
                => Maybe<Privilege>.From(Privilege.AuthorizedManagement),
            GpIns.LOAD => Maybe<Privilege>.From(Privilege.AuthorizedManagement),
            GpIns.DELETE => Maybe<Privilege>.From(Privilege.AuthorizedManagement),
            GpIns.GET_STATUS => Maybe<Privilege>.From(Privilege.AuthorizedManagement),
            GpIns.PUT_KEY => Maybe<Privilege>.From(Privilege.AuthorizedManagement),
            GpIns.STORE_DATA => Maybe<Privilege>.From(Privilege.AuthorizedManagement),
            GpIns.SET_STATUS => Maybe<Privilege>.From(Privilege.AuthorizedManagement),

            // GET DATA requires no special privileges
            ApduIns.GET_DATA
                => Maybe<Privilege>.None,

            _ => Maybe<Privilege>.None,
        };
    }

    public Result<IApplication, SmartCardError> WithLifecycleState(LifecycleState newState)
    {
        // Validate lifecycle state transitions per GP specification
        return IsValidLifecycleTransition(LifecycleState, newState)
            ? Result.Success<IApplication, SmartCardError>(this with { LifecycleState = newState })
            : Result.Failure<IApplication, SmartCardError>(SmartCardError.ConditionsNotSatisfied());
    }

    public IApplication WithPrivileges(Privilege newPrivileges)
    {
        return this with { Privileges = newPrivileges };
    }

    #region Command Processors

    private Result<ApplicationCommandResult, SmartCardError> ProcessInitializeUpdate(
        byte[] command,
        CardState cardState,
        CardConfiguration config,
        IRngContext rngContext
    )
    {
        return CommandProcessors
            .ProcessInitializeUpdate(command, cardState, config, rngContext, LoggingService.None)
            .Map(result =>
            {
                var (response, updatedState) = result;
                return new ApplicationCommandResult(
                    this,
                    updatedState,
                    ToApplicationResponse(response)
                );
            });
    }

    private Result<ApplicationCommandResult, SmartCardError> ProcessExternalAuthenticate(
        byte[] command,
        CardState cardState,
        CardConfiguration config,
        IRngContext rngContext
    )
    {
        Result<(CoreApduResponse, CardState), SmartCardError> result = cardState.ScpVersion switch
        {
            0x02
                => Scp02CommandProcessors.ProcessScp02ExternalAuthenticate(
                    command,
                    cardState,
                    config,
                    rngContext,
                    LoggingService.None
                ),
            0x03
                => Scp03CommandProcessors.ProcessScp03ExternalAuthenticate(
                    command,
                    cardState,
                    config,
                    rngContext,
                    LoggingService.None
                ),
            _
                => Result.Failure<(CoreApduResponse, CardState), SmartCardError>(
                    SmartCardError.ConditionsNotSatisfied()
                ),
        };

        return result.Map(result =>
        {
            var (response, updatedState) = result;
            return new ApplicationCommandResult(
                this,
                updatedState,
                ToApplicationResponse(response)
            );
        });
    }

    private Result<ApplicationCommandResult, SmartCardError> ProcessGetStatus(
        byte[] command,
        CardState cardState,
        CardConfiguration config,
        IRngContext rngContext
    )
    {
        // P1 contains subset indicator
        if (command.Length < 4)
        {
            return Result.Success<ApplicationCommandResult, SmartCardError>(
                new ApplicationCommandResult(this, cardState, ApplicationApduResponse.WrongLength())
            );
        }

        byte p1 = command[2];
        byte p2 = command[3];

        return GetStatusResponse(p1, p2)
            .Match(
                data =>
                    Result.Success<ApplicationCommandResult, SmartCardError>(
                        new ApplicationCommandResult(
                            this,
                            cardState,
                            ApplicationApduResponse.Success(data)
                        )
                    ),
                error =>
                    Result.Success<ApplicationCommandResult, SmartCardError>(
                        new ApplicationCommandResult(
                            this,
                            cardState,
                            ApplicationApduResponse.Error(
                                GpConstants.StatusWords.Legacy.GenericFailure
                            )
                        )
                    )
            );
    }

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

    private Result<ApplicationCommandResult, SmartCardError> ProcessInstall(
        byte[] command,
        CardState cardState,
        CardConfiguration config,
        IRngContext rngContext
    )
    {
        return ProcessInstallCommand(command, cardState, rngContext)
            .Match(
                result =>
                    Result.Success<ApplicationCommandResult, SmartCardError>(
                        new ApplicationCommandResult(result.Item1, cardState, result.Item2)
                    ),
                error =>
                    Result.Success<ApplicationCommandResult, SmartCardError>(
                        new ApplicationCommandResult(
                            this,
                            cardState,
                            ApplicationApduResponse.ConditionsNotSatisfied()
                        )
                    )
            );
    }

    private Result<ApplicationCommandResult, SmartCardError> ProcessLoad(
        byte[] command,
        CardState cardState,
        CardConfiguration config,
        IRngContext rngContext
    )
    {
        return ProcessLoadCommand(command, cardState, rngContext)
            .Match(
                result =>
                    Result.Success<ApplicationCommandResult, SmartCardError>(
                        new ApplicationCommandResult(result.Item1, cardState, result.Item2)
                    ),
                error =>
                    Result.Success<ApplicationCommandResult, SmartCardError>(
                        new ApplicationCommandResult(
                            this,
                            cardState,
                            ApplicationApduResponse.ConditionsNotSatisfied()
                        )
                    )
            );
    }

    private Result<ApplicationCommandResult, SmartCardError> ProcessDelete(
        byte[] command,
        CardState cardState,
        CardConfiguration config,
        IRngContext rngContext
    )
    {
        return ProcessDeleteCommand(command, cardState, rngContext)
            .Match(
                result =>
                    Result.Success<ApplicationCommandResult, SmartCardError>(
                        new ApplicationCommandResult(result.Item1, cardState, result.Item2)
                    ),
                error =>
                    Result.Success<ApplicationCommandResult, SmartCardError>(
                        new ApplicationCommandResult(
                            this,
                            cardState,
                            ApplicationApduResponse.ConditionsNotSatisfied()
                        )
                    )
            );
    }

    private Result<ApplicationCommandResult, SmartCardError> ProcessPutKey(
        byte[] command,
        CardState cardState,
        CardConfiguration config,
        IRngContext rngContext
    )
    {
        return global::Gp4Net
            .CardEmulator.Core.VirtualCard.ProcessPutKeyCommand(command, cardState, config)
            .Match(
                result =>
                    Result.Success<ApplicationCommandResult, SmartCardError>(
                        new ApplicationCommandResult(
                            this with
                            {
                                InstalledKeys = result.Item2.InstalledKeys
                            },
                            result.Item2,
                            ToApplicationResponse(result.Item1)
                        )
                    ),
                error =>
                    Result.Success<ApplicationCommandResult, SmartCardError>(
                        new ApplicationCommandResult(this, cardState, ToApplicationResponse(error))
                    )
            );
    }

    private Result<ApplicationCommandResult, SmartCardError> ProcessStoreData(
        byte[] command,
        CardState cardState,
        CardConfiguration config,
        IRngContext rngContext
    )
    {
        return ProcessStoreDataCommand(command, cardState, rngContext)
            .Match(
                result =>
                    Result.Success<ApplicationCommandResult, SmartCardError>(
                        new ApplicationCommandResult(result.Item1, cardState, result.Item2)
                    ),
                error =>
                    Result.Success<ApplicationCommandResult, SmartCardError>(
                        new ApplicationCommandResult(
                            this,
                            cardState,
                            ApplicationApduResponse.ConditionsNotSatisfied()
                        )
                    )
            );
    }

    private Result<ApplicationCommandResult, SmartCardError> ProcessSetStatus(
        byte[] command,
        CardState cardState,
        CardConfiguration config,
        IRngContext rngContext
    )
    {
        return ProcessSetStatusCommand(command, cardState, rngContext)
            .Match(
                result =>
                    Result.Success<ApplicationCommandResult, SmartCardError>(
                        new ApplicationCommandResult(result.Item1, cardState, result.Item2)
                    ),
                error =>
                    Result.Success<ApplicationCommandResult, SmartCardError>(
                        new ApplicationCommandResult(
                            this,
                            cardState,
                            ApplicationApduResponse.ConditionsNotSatisfied()
                        )
                    )
            );
    }

    #endregion

    #region Helper Methods

    private static ApplicationApduResponse ToApplicationResponse(CoreApduResponse response)
    {
        return ApplicationApduResponse.From(response.Data, response.StatusWord);
    }

    private static ApplicationApduResponse ToApplicationResponse(SmartCardError error)
    {
        return ApplicationApduResponse.From(
            [],
            error.StatusWord.GetValueOrDefault(GpConstants.StatusWords.Legacy.IncorrectData)
        );
    }

    private Maybe<IKeySet> GetKeySet(byte keyVersion)
    {
        var effectiveVersion =
            keyVersion == 0x00 || keyVersion == 0xFF ? DefaultKeyVersion : keyVersion;

        return InstalledKeys.TryGetValue(effectiveVersion, out var keySet)
            ? Maybe<IKeySet>.From(keySet)
            : Maybe<IKeySet>.None;
    }

    private Result<bool, SmartCardError> ValidateHostCryptogram(byte[] command, CardState cardState)
    {
        // Accept any EXTERNAL AUTHENTICATE after INITIALIZE UPDATE
        // In a real implementation, this would validate the host cryptogram
        return Result.Success<bool, SmartCardError>(true);
    }

    private Result<byte[], SmartCardError> GetStatusResponse(byte p1, byte p2)
    {
        // Return empty GP status response
        return Result.Success<byte[], SmartCardError>([0x6F, 0x00]);
    }

    private Result<(IApplication, ApplicationApduResponse), SmartCardError> ProcessInstallCommand(
        byte[] command,
        CardState cardState,
        IRngContext rngContext
    )
    {
        // GlobalPlatform Card Specification v2.3.1 Section 11.5 INSTALL Command
        if (command.Length < 5)
        {
            return Result.Success<(IApplication, ApplicationApduResponse), SmartCardError>(
                (this, ApplicationApduResponse.WrongLength())
            );
        }

        byte p1 = command[2]; // Install type
        byte lc = command[4];

        if (command.Length < 5 + lc)
        {
            return Result.Success<(IApplication, ApplicationApduResponse), SmartCardError>(
                (this, ApplicationApduResponse.WrongLength())
            );
        }

        // Extract command data
        byte[] commandData = new byte[lc];
        Array.Copy(command, 5, commandData, 0, lc);

        // For the virtual card emulator, we accept any well-formed INSTALL command
        // and return success per GP specification
        // Per GlobalPlatform Card Specification v2.3.1 Table 11-13: INSTALL Response
        byte[] responseData = [0x00];

        return Result.Success<(IApplication, ApplicationApduResponse), SmartCardError>(
            (this, ApplicationApduResponse.Success(responseData))
        );
    }

    private Result<(IApplication, ApplicationApduResponse), SmartCardError> ProcessLoadCommand(
        byte[] command,
        CardState cardState,
        IRngContext rngContext
    )
    {
        return Result.Success<(IApplication, ApplicationApduResponse), SmartCardError>(
            (this, ApplicationApduResponse.ConditionsNotSatisfied())
        );
    }

    private Result<(IApplication, ApplicationApduResponse), SmartCardError> ProcessDeleteCommand(
        byte[] command,
        CardState cardState,
        IRngContext rngContext
    )
    {
        // GlobalPlatform Card Specification v2.3.1 Section 11.2 DELETE Command
        if (command.Length < 5)
        {
            return Result.Success<(IApplication, ApplicationApduResponse), SmartCardError>(
                (this, ApplicationApduResponse.WrongLength())
            );
        }

        byte lc = command[4];
        if (command.Length < 5 + lc)
        {
            return Result.Success<(IApplication, ApplicationApduResponse), SmartCardError>(
                (this, ApplicationApduResponse.WrongLength())
            );
        }

        // Extract TLV data
        byte[] tlvData = new byte[lc];
        Array.Copy(command, 5, tlvData, 0, lc);

        // For the virtual card emulator, we accept any well-formed DELETE command
        // and return success per GP specification
        // Per GlobalPlatform Card Specification v2.3.1 Table 11-26: DELETE Response
        byte[] responseData = [0x00];

        return Result.Success<(IApplication, ApplicationApduResponse), SmartCardError>(
            (this, ApplicationApduResponse.Success(responseData))
        );
    }

    private Result<(IApplication, ApplicationApduResponse), SmartCardError> ProcessStoreDataCommand(
        byte[] command,
        CardState cardState,
        IRngContext rngContext
    )
    {
        return Result.Success<(IApplication, ApplicationApduResponse), SmartCardError>(
            (this, ApplicationApduResponse.ConditionsNotSatisfied())
        );
    }

    private Result<(IApplication, ApplicationApduResponse), SmartCardError> ProcessSetStatusCommand(
        byte[] command,
        CardState cardState,
        IRngContext rngContext
    )
    {
        return Result.Success<(IApplication, ApplicationApduResponse), SmartCardError>(
            (this, ApplicationApduResponse.ConditionsNotSatisfied())
        );
    }

    private static bool IsValidLifecycleTransition(LifecycleState from, LifecycleState to)
    {
        // GP Card Specification v2.3.1 Table 11-1
        return (from, to) switch
        {
            (LifecycleState.Loaded, LifecycleState.Installed) => true,
            (LifecycleState.Installed, LifecycleState.Selectable) => true,
            (LifecycleState.Selectable, LifecycleState.Personalized) => true,
            (LifecycleState.Personalized, LifecycleState.Locked) => true,
            (LifecycleState.Locked, LifecycleState.Personalized) => true,
            (_, LifecycleState.Terminated) => true,
            _ => false,
        };
    }

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
            // Card Production Life Cycle (CPLC)
            .Add(
                0x9F7F,
                [
                    0x9F,
                    0x7F,
                    0x2A,
                    0x00,
                    0x00,
                    0x00,
                    0x00, // IC Fabricator
                    0x00,
                    0x00,
                    0x00,
                    0x00, // IC Type
                    0x00,
                    0x00,
                    0x00,
                    0x00, // Operating System ID
                    0x00,
                    0x00, // Operating System Release Date
                    0x00,
                    0x00, // Operating System Release Level
                    0x00,
                    0x00,
                    0x00,
                    0x00, // IC Fabrication Date
                    0x00,
                    0x00,
                    0x00,
                    0x00, // IC Serial Number
                    0x00,
                    0x00, // IC Batch Identifier
                    0x00,
                    0x00, // IC Module Fabricator
                    0x00,
                    0x00, // IC Module Packaging Date
                    0x00,
                    0x00, // ICC Manufacturer
                    0x00,
                    0x00, // IC Embedding Date
                    0x00,
                    0x00, // IC Pre-Personalizer
                    0x00,
                    0x00, // IC Pre-Personalization Date
                    0x00,
                    0x00, // IC Pre-Personalization Equipment ID
                    0x00,
                    0x00, // IC Personalizer
                    0x00,
                    0x00, // IC Personalization Date
                    0x00,
                    0x00 // IC Personalization Equipment ID
                ]
            )
            // Card Data
            .Add(0x0066, [0x00, 0x66, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    private Result<byte[], SmartCardError> BuildInitializeUpdateResponse(
        byte keyVersion,
        byte scpVersion,
        byte scpImplementation,
        byte[] cardChallenge,
        byte[] hostChallenge,
        IKeySet keySet
    )
    {
        // Build response according to GP specification
        // Format: Key diversification data (10) + key version (1) + SCP id (1) +
        //         sequence counter (2) + card challenge (6 or 8) + card cryptogram (8)

        var keyDiversificationData = new byte[10]; // All zeros for test
        var sequenceCounter = new byte[2]; // All zeros for test

        // Calculate card cryptogram based on SCP version
        return CalculateCardCryptogram(
                scpVersion,
                hostChallenge,
                cardChallenge,
                sequenceCounter,
                keySet
            )
            .Map(cryptogram =>
            {
                var responseData = new byte[
                    10 + 1 + 1 + 2 + cardChallenge.Length + cryptogram.Length
                ];
                var offset = 0;

                // Copy components
                Array.Copy(keyDiversificationData, 0, responseData, offset, 10);
                offset += 10;
                responseData[offset++] = keyVersion;
                responseData[offset++] = (byte)((scpVersion << 4) | scpImplementation);
                Array.Copy(sequenceCounter, 0, responseData, offset, 2);
                offset += 2;
                Array.Copy(cardChallenge, 0, responseData, offset, cardChallenge.Length);
                offset += cardChallenge.Length;
                Array.Copy(cryptogram, 0, responseData, offset, cryptogram.Length);

                return responseData;
            });
    }

    private Result<byte[], SmartCardError> CalculateCardCryptogram(
        byte scpVersion,
        byte[] hostChallenge,
        byte[] cardChallenge,
        byte[] sequenceCounter,
        IKeySet keySet
    )
    {
        // Use existing crypto services for cryptogram calculation
        return scpVersion switch
        {
            0x02
                => CalculateScp02CardCryptogram(
                    hostChallenge,
                    cardChallenge,
                    sequenceCounter,
                    keySet
                ),
            0x03 => CalculateScp03CardCryptogram(hostChallenge, cardChallenge, keySet),
            _
                => Result.Failure<byte[], SmartCardError>(
                    ErrorFactory.UnsupportedProtocol($"SCP{scpVersion:X2}")
                ),
        };
    }

    private Result<byte[], SmartCardError> CalculateScp02CardCryptogram(
        byte[] hostChallenge,
        byte[] cardChallenge,
        byte[] sequenceCounter,
        IKeySet keySet
    )
    {
        if (keySet is not Scp02KeySet scp02Keys)
        {
            return Result.Failure<byte[], SmartCardError>(
                ErrorFactory.InvalidKey("SCP02", "Invalid key set type")
            );
        }

        // Calculate SCP02 card cryptogram using sequence counter
        var sequenceCounterResult = Maybe<byte[]>.From(sequenceCounter);
        return CryptoService
            .Cryptogram.CalculateCardCryptogram(
                hostChallenge,
                cardChallenge,
                keySet,
                0x02,
                0x15,
                sequenceCounterResult
            )
            .Map(cryptogram => cryptogram.Take(8).ToArray());
    }

    private Result<byte[], SmartCardError> CalculateScp03CardCryptogram(
        byte[] hostChallenge,
        byte[] cardChallenge,
        IKeySet keySet
    )
    {
        if (keySet is not Scp03KeySet scp03Keys)
        {
            return Result.Failure<byte[], SmartCardError>(
                ErrorFactory.InvalidKey("SCP03", "Invalid key set type")
            );
        }

        // Calculate SCP03 card cryptogram (no sequence counter needed)
        return CryptoService
            .Cryptogram.CalculateCardCryptogram(
                hostChallenge,
                cardChallenge,
                keySet,
                0x03,
                0x00,
                Maybe<byte[]>.None
            )
            .Map(cryptogram => cryptogram.Take(8).ToArray());
    }

    #endregion
}
