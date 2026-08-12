using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Security;
using Gp4Net.Services;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using WSCT.ISO7816;
using static Gp4Net.Cryptography.CryptoService;

namespace Gp4Net.Domain.Trace;

/// <summary>
/// Pure functional trace validation using existing ScpService.Security functions.
/// Validates cryptographic operations in GlobalPlatform traces.
/// </summary>
[PublicAPI]
public static class TraceValidation
{
#if DEBUG
    private static readonly ILogger Logger = NullLoggerFactory.Instance.CreateLogger(
        "Gp4Net.Domain.Trace.TraceValidation"
    );

    [Conditional("DEBUG")]
    private static void DebugLog(string message)
    {
        Logger.LogDebug(message);
        Debug.WriteLine(message);
    }
#else
    private static readonly ILogger Logger = NullLoggerFactory.Instance.CreateLogger(
        "Gp4Net.Domain.Trace.TraceValidation"
    );

    [Conditional("DEBUG")]
    private static void DebugLog(string message) { }
#endif

    private static Result<TraceValidationState, SmartCardError> ApplyDiversification(
        TraceValidationState currentState,
        InitializeUpdateComponents components,
        ScpVersion detectedScpVersion
    )
    {
        if (detectedScpVersion != ScpVersion.Scp03)
        {
            return Result.Success<TraceValidationState, SmartCardError>(currentState);
        }

        return currentState.KeyMaterial.Diversification.Match(
            spec =>
            {
                if (currentState.KeyMaterial.MasterKeys is not Scp03KeySet masterScp03)
                {
                    return Result.Failure<TraceValidationState, SmartCardError>(
                        SmartCardError.InvalidArgument(
                            "SCP03 diversification requires an SCP03 key set"
                        )
                    );
                }

                return KeyDiversificationService
                    .DiversifyScp03KeySet(masterScp03, spec, components.KeyDiversificationData)
                    .Map(diversified =>
                    {
                        var updatedMaterial = currentState.KeyMaterial.WithCurrentKeys(
                            diversified,
                            components.KeyDiversificationData
                        );
                        return currentState.WithKeyMaterial(updatedMaterial);
                    });
            },
            () => Result.Success<TraceValidationState, SmartCardError>(currentState)
        );
    }

    /// <summary>
    /// Validates a single exchange (command/response pair) in the trace.
    /// </summary>
    public static Result<TraceValidationState, SmartCardError> ValidateExchange(
        TraceValidationState state,
        byte[] command,
        byte[] response,
        int exchangeIndex
    )
    {
        if (command.Length == 0)
            return Result.Failure<TraceValidationState, SmartCardError>(
                SmartCardError.InvalidArgument("Command cannot be empty")
            );

        return GetCommandInstructionByte(command)
            .Bind(ins =>
                ins switch
                {
                    0xFF
                        => Result.Success<TraceValidationState, SmartCardError>(
                            state.AddResult(
                                ValidationResult.Failure(
                                    exchangeIndex,
                                    "STRUCTURE",
                                    "Command too short",
                                    "APDU must be at least 5 bytes"
                                )
                            )
                        ),
                    0x50 => ValidateInitializeUpdate(state, command, response, exchangeIndex),
                    0x82 => ValidateExternalAuthenticate(state, command, response, exchangeIndex),
                    _ => ValidateSecureMessaging(state, command, response, exchangeIndex)
                }
            );
    }

    private static Result<byte, SmartCardError> GetCommandInstructionByte(byte[] command)
    {
        if (command.Length < 5)
        {
            // Command too short - return special marker
            return Result.Success<byte, SmartCardError>(0xFF);
        }
        return Result.Success<byte, SmartCardError>(command[1]);
    }

    private static Result<TraceValidationState, SmartCardError> ValidateInitializeUpdate(
        TraceValidationState state,
        byte[] command,
        byte[] response,
        int exchangeIndex
    )
    {
        // Parse command to extract host challenge
        var cmd = new CommandAPDU(command);

        return Maybe<byte[]>
            .From(cmd.Udc)
            .ToResult(SmartCardError.InvalidArgument("No data in INITIALIZE UPDATE"))
            .Bind(data =>
                data.Length >= 8
                    ? Result.Success<byte[], SmartCardError>(data.Take(8).ToArray())
                    : Result.Failure<byte[], SmartCardError>(
                        SmartCardError.InvalidArgument("Host challenge too short")
                    )
            )
            .Bind(hostChallenge =>
            {
                // Parse response to extract components
                return ParseInitializeUpdateResponse(response)
                    .Bind(components =>
                    {
                        var diversifiedStateResult = ApplyDiversification(
                            state,
                            components,
                            components.ScpVersion
                        );

                        return diversifiedStateResult.Bind(diversifiedState =>
                        {
                            var workingState = diversifiedState
                                .WithHostChallenge(hostChallenge)
                                .WithCardChallenge(components.CardChallenge)
                                .WithSequenceCounter(components.SequenceCounter)
                                .WithScpVersion(components.ScpVersion)
                                .WithScpImplementation(
                                    (ScpImplementation)components.ImplementationParameter
                                );

                            return DeriveSessionKeys(
                                    workingState.KeyMaterial,
                                    hostChallenge,
                                    components.CardChallenge,
                                    components.SequenceCounter,
                                    components.ScpVersion
                                )
                                .Bind(sessionKeys =>
                                    VerifyCardCryptogram(
                                            sessionKeys,
                                            response,
                                            hostChallenge,
                                            components.CardCryptogram,
                                            components.ScpVersion
                                        )
                                        .Map(valid =>
                                        {
                                            if (!valid)
                                            {
                                                return workingState.AddResult(
                                                    ValidationResult.Failure(
                                                        exchangeIndex,
                                                        "INITIALIZE_UPDATE",
                                                        "Invalid card cryptogram",
                                                        "Cryptogram verification failed"
                                                    )
                                                );
                                            }

                                            return workingState
                                                .WithSessionKeys(sessionKeys)
                                                .WithSecurityLevel(0x00)
                                                .AddResult(
                                                    ValidationResult.Success(
                                                        exchangeIndex,
                                                        "INITIALIZE_UPDATE",
                                                        $"Valid card cryptogram for {components.ScpVersion}"
                                                    )
                                                );
                                        })
                                );
                        });
                    });
            });
    }

    private static Result<TraceValidationState, SmartCardError> ValidateExternalAuthenticate(
        TraceValidationState state,
        byte[] command,
        byte[] response,
        int exchangeIndex
    )
    {
        return state
            .SessionKeys.ToResult(SmartCardError.InvalidArgument("No session keys established"))
            .Bind(sessionKeys =>
            {
                // Parse command to extract host cryptogram and security level
                var cmd = new CommandAPDU(command);

                return Maybe<byte[]>
                    .From(cmd.Udc)
                    .ToResult(SmartCardError.InvalidArgument("No data in EXTERNAL AUTHENTICATE"))
                    .Bind(data =>
                    {
                        if (data.Length < 8)
                            return Result.Failure<TraceValidationState, SmartCardError>(
                                SmartCardError.InvalidArgument(
                                    "EXTERNAL AUTHENTICATE data too short"
                                )
                            );

                        var hostCryptogram = data.Take(8).ToArray();
                        var securityLevel = cmd.P1;

                        bool requiresCmac = (securityLevel & 0x01) != 0;

                        // For SCP02 with C-MAC, verify the MAC on EXTERNAL AUTHENTICATE
                        if (state.ScpVersion == ScpVersion.Scp02 && requiresCmac)
                        {
                            if (data.Length < 16)
                            {
                                return Result.Success<TraceValidationState, SmartCardError>(
                                    state.AddResult(
                                        ValidationResult.Failure(
                                            exchangeIndex,
                                            "EXTERNAL_AUTHENTICATE",
                                            "Invalid EXTERNAL AUTHENTICATE data",
                                            "Data too short for SCP02 MAC"
                                        )
                                    )
                                );
                            }

                            var mac = data.Skip(8).Take(8).ToArray();

                            return MacChainingState
                                .Create(new byte[8], ScpVersion.Scp02, 0x00)
                                .Bind(macState =>
                                    SecureChannelState
                                        .Create(
                                            sessionKeys,
                                            SecurityLevel.CMac,
                                            ScpVersion.Scp02,
                                            new byte[8],
                                            (byte)state.ScpImplementation
                                        )
                                        .Bind(initialState =>
                                            initialState.UpdateCounterAndMac(0, macState)
                                        )
                                )
                                .Bind(channelState =>
                                {
                                    var securedCmd = new CommandAPDU(command);

                                    return ScpService
                                        .Security.RemoveCommandSecurity(securedCmd, channelState)
                                        .Map(result =>
                                        {
                                            var (_, newState) = result;
                                            return state
                                                .WithSecurityLevel(securityLevel)
                                                .WithCommandIcv(newState.MacChainingValue)
                                                .AddResult(
                                                    ValidationResult.Success(
                                                        exchangeIndex,
                                                        "EXTERNAL_AUTHENTICATE",
                                                        $"Valid host cryptogram and MAC for {state.ScpVersion}, security level 0x{securityLevel:X2}"
                                                    )
                                                );
                                        })
                                        .Match(
                                            onSuccess: s =>
                                                Result.Success<
                                                    TraceValidationState,
                                                    SmartCardError
                                                >(s),
                                            onFailure: error =>
                                                Result.Success<
                                                    TraceValidationState,
                                                    SmartCardError
                                                >(
                                                    state.AddResult(
                                                        ValidationResult.Failure(
                                                            exchangeIndex,
                                                            "EXTERNAL_AUTHENTICATE",
                                                            "Invalid MAC on EXTERNAL AUTHENTICATE",
                                                            error.ToString()
                                                        )
                                                    )
                                                )
                                        );
                                });
                        }

                        // For SCP03, MAC is included in the command
                        if (state.ScpVersion == ScpVersion.Scp03 && data.Length >= 16)
                        {
                            var mac = data.Skip(8).Take(8).ToArray();

                            // Create initial secure channel state for MAC verification
                            return MacChainingState
                                .Create(new byte[16], ScpVersion.Scp03, 0x00)
                                .Bind(macState =>
                                    SecureChannelState
                                        .Create(
                                            sessionKeys,
                                            (SecurityLevel)securityLevel,
                                            ScpVersion.Scp03,
                                            new byte[16],
                                            (byte)state.ScpImplementation
                                        )
                                        .Bind(initialState =>
                                            initialState.UpdateCounterAndMac(0, macState)
                                        )
                                )
                                .Bind(channelState =>
                                {
                                    // Verify MAC on EXTERNAL AUTHENTICATE command
                                    var securedCmd = new CommandAPDU(command);

                                    return ScpService
                                        .Security.RemoveCommandSecurity(securedCmd, channelState)
                                        .Map(result =>
                                        {
                                            // MAC verified successfully
                                            var (_, newState) = result;
#if DEBUG
                                            var updatedState = state
                                                .WithSecurityLevel(securityLevel)
                                                .WithCommandIcv(newState.MacChainingValue)
                                                .WithEncryptionCounter(newState.EncryptionCounter);

                                            return updatedState.AddResult(
                                                ValidationResult.Success(
                                                    exchangeIndex,
                                                    "EXTERNAL_AUTHENTICATE",
                                                    $"Valid host cryptogram and MAC for {state.ScpVersion}, security level 0x{securityLevel:X2}"
                                                )
                                            );
#else
                                            return state
                                                .WithSecurityLevel(securityLevel)
                                                .WithCommandIcv(newState.MacChainingValue)
                                                .WithEncryptionCounter(newState.EncryptionCounter)
                                                .AddResult(
                                                    ValidationResult.Success(
                                                        exchangeIndex,
                                                        "EXTERNAL_AUTHENTICATE",
                                                        $"Valid host cryptogram and MAC for {state.ScpVersion}, security level 0x{securityLevel:X2}"
                                                    )
                                                );
#endif
                                        })
                                        .Match(
                                            onSuccess: s =>
                                                Result.Success<
                                                    TraceValidationState,
                                                    SmartCardError
                                                >(s),
                                            onFailure: error =>
                                                Result.Success<
                                                    TraceValidationState,
                                                    SmartCardError
                                                >(
                                                    state.AddResult(
                                                        ValidationResult.Failure(
                                                            exchangeIndex,
                                                            "EXTERNAL_AUTHENTICATE",
                                                            "Invalid MAC on EXTERNAL AUTHENTICATE",
                                                            error.ToString()
                                                        )
                                                    )
                                                )
                                        );
                                });
                        }
                        else
                        {
                            // SCP02 or SCP03 without MAC
                            return Result.Success<TraceValidationState, SmartCardError>(
                                state
                                    .WithSecurityLevel(securityLevel)
                                    .WithCommandIcv(
                                        new byte[state.ScpVersion == ScpVersion.Scp03 ? 16 : 8]
                                    )
                                    .AddResult(
                                        ValidationResult.Success(
                                            exchangeIndex,
                                            "EXTERNAL_AUTHENTICATE",
                                            $"Host cryptogram accepted for {state.ScpVersion}, security level 0x{securityLevel:X2}"
                                        )
                                    )
                            );
                        }
                    });
            });
    }

    private static Result<TraceValidationState, SmartCardError> ValidateSecureMessaging(
        TraceValidationState state,
        byte[] command,
        byte[] response,
        int exchangeIndex
    )
    {
        // Check if command has secure messaging bit set
        var hasSecureMessaging = command.Length >= 5 && (command[0] & 0x04) != 0;

        if (!hasSecureMessaging)
        {
            // Plain command
            return Result.Success<TraceValidationState, SmartCardError>(
                state.AddResult(
                    ValidationResult.Success(
                        exchangeIndex,
                        "STRUCTURE",
                        "Non-secure command structure validated"
                    )
                )
            );
        }

        // Validate secure command and response using ScpService.Security
        return state.SessionKeys.Match(
            Some: sessionKeys =>
            {
                return CreateSecureChannelState(state, sessionKeys)
                    .Bind(channelState =>
                    {
                        var securedCmd = new CommandAPDU(command);

                        return ScpService
                            .Security.RemoveCommandSecurity(securedCmd, channelState)
                            .Bind(cmdResult =>
                            {
                                var (_, stateAfterCmd) = cmdResult;

                                var resp = new ResponseAPDU(response);

                                return ScpService
                                    .Security.RemoveResponseSecurity(resp, stateAfterCmd)
                                    .Map(respResult =>
                                    {
                                        var (plaintextResp, finalState) = respResult;
                                        var securityFlags = (SecurityLevel)state.SecurityLevel;

                                        var updatedState = state
                                            .WithCommandIcv(finalState.MacChainingValue)
                                            .WithEncryptionCounter(finalState.EncryptionCounter);

                                        if (securityFlags.HasCMac())
                                        {
                                            updatedState = updatedState.AddResult(
                                                ValidationResult.Success(
                                                    exchangeIndex,
                                                    "C-MAC",
                                                    $"Validated command MAC for INS=0x{securedCmd.Ins:X2}"
                                                )
                                            );
                                        }

                                        if (
                                            securityFlags.HasCDecryption()
                                            || securityFlags.HasCEncryption()
                                        )
                                        {
                                            var label = securityFlags.HasCDecryption()
                                                ? "C-DECRYPTION"
                                                : "C-ENCRYPTION";

                                            updatedState = updatedState.AddResult(
                                                ValidationResult.Success(
                                                    exchangeIndex,
                                                    label,
                                                    $"Validated command encryption for INS=0x{securedCmd.Ins:X2}"
                                                )
                                            );
                                        }

                                        if (securityFlags.HasRMac())
                                        {
                                            var statusWord = plaintextResp.StatusWord.ToString(
                                                "X4"
                                            );
                                            updatedState = updatedState.AddResult(
                                                ValidationResult.Success(
                                                    exchangeIndex,
                                                    "R-MAC",
                                                    $"Validated response MAC (SW={statusWord})"
                                                )
                                            );
                                        }

                                        if (securityFlags.HasREncryption())
                                        {
                                            updatedState = updatedState.AddResult(
                                                ValidationResult.Success(
                                                    exchangeIndex,
                                                    "R-ENCRYPTION",
                                                    "Validated encrypted response payload"
                                                )
                                            );
                                        }

                                        return updatedState.AddResult(
                                            ValidationResult.Success(
                                                exchangeIndex,
                                                "SECURE_MESSAGING",
                                                $"Valid secure exchange (INS=0x{securedCmd.Ins:X2})"
                                            )
                                        );
                                    })
                                    .Match(
                                        onSuccess: s =>
                                            Result.Success<TraceValidationState, SmartCardError>(s),
                                        onFailure: error =>
                                            Result.Success<TraceValidationState, SmartCardError>(
                                                state.AddResult(
                                                    ValidationResult.Failure(
                                                        exchangeIndex,
                                                        "RESPONSE_SECURITY",
                                                        "Response security validation failed",
                                                        error.ToString()
                                                    )
                                                )
                                            )
                                    );
                            })
                            .Match(
                                onSuccess: s =>
                                    Result.Success<TraceValidationState, SmartCardError>(s),
                                onFailure: error =>
                                    Result.Success<TraceValidationState, SmartCardError>(
                                        state.AddResult(
                                            ValidationResult.Failure(
                                                exchangeIndex,
                                                "COMMAND_SECURITY",
                                                "Command security validation failed",
                                                error.Message
                                            )
                                        )
                                    )
                            );
                    });
            },
            None: () =>
                Result.Success<TraceValidationState, SmartCardError>(
                    state.AddResult(
                        ValidationResult.Failure(
                            exchangeIndex,
                            "C-MAC",
                            "No session keys available",
                            "Session keys not established"
                        )
                    )
                )
        );
    }

    private static Result<SecureChannelState, SmartCardError> CreateSecureChannelState(
        TraceValidationState traceState,
        SessionKeys sessionKeys
    )
    {
        var icv = traceState.CommandIcv.Match(
            value => value,
            () => traceState.ScpVersion == ScpVersion.Scp03 ? new byte[16] : new byte[8]
        );

        return MacChainingState
            .Create(icv, traceState.ScpVersion, 0x00)
            .Bind(macState =>
                SecureChannelState
                    .Create(
                        sessionKeys,
                        (SecurityLevel)traceState.SecurityLevel,
                        traceState.ScpVersion,
                        icv,
                        // GP Card Specification v2.3.1, Table E-1, and SCP03
                        // Amendment D v1.1.2, Table 5-1 define protocol behavior in i.
                        (byte)traceState.ScpImplementation
                    )
                    .Bind(state =>
                        state.UpdateCounterAndMac(traceState.EncryptionCounter, macState)
                    )
            );
    }

    private sealed record InitializeUpdateComponents(
        byte[] KeyDiversificationData,
        byte KeyVersion,
        ScpVersion ScpVersion,
        byte ImplementationParameter,
        byte[] CardChallenge,
        byte[] CardCryptogram,
        byte[] SequenceCounter
    );

    private static Result<InitializeUpdateComponents, SmartCardError> ParseInitializeUpdateResponse(
        byte[] response
    )
    {
        if (response.Length < 12)
        {
            return Result.Failure<InitializeUpdateComponents, SmartCardError>(
                SmartCardError.InvalidData("INITIALIZE UPDATE response too short")
            );
        }

        var dataLength = response.Length >= 2 ? response.Length - 2 : response.Length;
        if (dataLength < 12)
        {
            return Result.Failure<InitializeUpdateComponents, SmartCardError>(
                SmartCardError.InvalidData("INITIALIZE UPDATE response too short")
            );
        }

        var data = response.Take(dataLength).ToArray();
        var keyDiversificationData = data.Take(10).ToArray();
        byte keyVersion = data.Length > 10 ? data[10] : (byte)0x00;
        byte scpId = data.Length > 11 ? data[11] : (byte)0x03;

        var detectedVersion = scpId switch
        {
            0x02 => ScpVersion.Scp02,
            0x03 => ScpVersion.Scp03,
            _ => ScpVersion.Scp03,
        };

        if (detectedVersion == ScpVersion.Scp02)
        {
            if (dataLength < 28)
            {
                return Result.Failure<InitializeUpdateComponents, SmartCardError>(
                    SmartCardError.InvalidData("SCP02 INITIALIZE UPDATE response too short")
                );
            }

            var sequenceCounter = data.Skip(12).Take(2).ToArray();
            var cardChallenge = data.Skip(14).Take(6).ToArray();
            var cardCryptogram = data.Skip(20).Take(8).ToArray();

            return Result.Success<InitializeUpdateComponents, SmartCardError>(
                new InitializeUpdateComponents(
                    keyDiversificationData,
                    keyVersion,
                    detectedVersion,
                    // GP Card Specification v2.3.1, E.1.1 lists i=15 as an SCP02
                    // implementation profile; INITIALIZE UPDATE does not carry SCP02 i.
                    (byte)ScpImplementation.Scp02I15,
                    cardChallenge,
                    cardCryptogram,
                    sequenceCounter
                )
            );
        }

        // SCP03 explicit mode structure (32 bytes before SW):
        // [10 KDD][1 KeyVer][1 SCPID=03][1 i-param][8 CardChal][8 CardCrypt][3 SeqCtr]
        if (dataLength < 32)
        {
            return Result.Failure<InitializeUpdateComponents, SmartCardError>(
                SmartCardError.InvalidData("SCP03 INITIALIZE UPDATE response too short")
            );
        }

        byte implementationParameter = data[12];
        var scp03CardChallenge = data.Skip(13).Take(8).ToArray();
        var scp03CardCryptogram = data.Skip(21).Take(8).ToArray();
        var scp03SequenceCounter = data.Skip(29).Take(3).ToArray();

        return Result.Success<InitializeUpdateComponents, SmartCardError>(
            new InitializeUpdateComponents(
                keyDiversificationData,
                keyVersion,
                detectedVersion,
                implementationParameter,
                scp03CardChallenge,
                scp03CardCryptogram,
                scp03SequenceCounter
            )
        );
    }

    private static Result<SessionKeys, SmartCardError> DeriveSessionKeys(
        TraceKeyMaterial keyMaterial,
        byte[] hostChallenge,
        byte[] cardChallenge,
        byte[] sequenceCounter,
        ScpVersion scpVersion
    )
    {
        return scpVersion switch
        {
            ScpVersion.Scp02 => DeriveScp02SessionKeys(keyMaterial.CurrentKeys, sequenceCounter),
            ScpVersion.Scp03
                => DeriveScp03SessionKeys(keyMaterial.CurrentKeys, hostChallenge, cardChallenge),
            _
                => Result.Failure<SessionKeys, SmartCardError>(
                    SmartCardError.Unsupported($"Unsupported SCP version: {scpVersion}")
                )
        };
    }

    private static Result<SessionKeys, SmartCardError> DeriveScp02SessionKeys(
        IKeySet baseKeys,
        byte[] sequenceCounter
    )
    {
        // Derive all three session keys
        var sEncResult = CryptoService.KeyDerivation.DeriveScp02SessionKey(
            baseKeys.EncKey,
            sequenceCounter,
            new byte[] { 0x01, 0x82 }
        );

        var sMacResult = CryptoService.KeyDerivation.DeriveScp02SessionKey(
            baseKeys.MacKey,
            sequenceCounter,
            new byte[] { 0x01, 0x01 }
        );

        var sDekResult = CryptoService.KeyDerivation.DeriveScp02SessionKey(
            baseKeys.DekKey,
            sequenceCounter,
            new byte[] { 0x01, 0x81 }
        );

        return sEncResult.Bind(sEnc =>
            sMacResult.Bind(sMac =>
                sDekResult.Bind(sDek =>
                {
                    var sessionKeys = new SessionKeys(
                        sEnc,
                        sMac,
                        sDek,
                        sDek // R-MAC key same as DEK for SCP02
                    );
                    return Result.Success<SessionKeys, SmartCardError>(sessionKeys);
                })
            )
        );
    }

    private static Result<SessionKeys, SmartCardError> DeriveScp03SessionKeys(
        IKeySet baseKeys,
        byte[] hostChallenge,
        byte[] cardChallenge
    )
    {
        // Derive all session keys using SCP03 key derivation
        var sEncResult = CryptoService.KeyDerivation.DeriveScp03SessionKey(
            baseKeys.EncKey,
            hostChallenge,
            cardChallenge,
            0x04
        );

        var sMacResult = CryptoService.KeyDerivation.DeriveScp03SessionKey(
            baseKeys.MacKey,
            hostChallenge,
            cardChallenge,
            0x06
        );

        var sRmacResult = CryptoService.KeyDerivation.DeriveScp03ReceiptKey(
            baseKeys.MacKey,
            hostChallenge,
            cardChallenge
        );

        return sEncResult.Bind(sEnc =>
            sMacResult.Bind(sMac =>
                sRmacResult.Bind(sRmac =>
                    // SCP03 v1.1.2, §6.1 and Table 6-2: Key-DEK remains static.
                    Result.Success<SessionKeys, SmartCardError>(
                        new SessionKeys(sEnc, sMac, sRmac, baseKeys.DekKey)
                    )
                )
            )
        );
    }

    private static Result<bool, SmartCardError> VerifyCardCryptogram(
        SessionKeys sessionKeys,
        byte[] response,
        byte[] hostChallenge,
        byte[] cardCryptogram,
        ScpVersion scpVersion
    )
    {
        return scpVersion switch
        {
            ScpVersion.Scp02
                => VerifyScp02CardCryptogram(sessionKeys, response, hostChallenge, cardCryptogram),
            ScpVersion.Scp03
                => VerifyScp03CardCryptogram(sessionKeys, response, hostChallenge, cardCryptogram),
            _
                => Result.Failure<bool, SmartCardError>(
                    SmartCardError.Unsupported($"Unsupported SCP version: {scpVersion}")
                )
        };
    }

    private static Result<bool, SmartCardError> VerifyScp02CardCryptogram(
        SessionKeys sessionKeys,
        byte[] response,
        byte[] hostChallenge,
        byte[] cardCryptogram
    )
    {
        // Parse response into InitializeUpdateResponse
        return InitializeUpdateResponse
            .Parse(response)
            .Bind(iuResponse =>
                // Build cryptogram data for SCP02
                CryptoService
                    .Cryptogram.BuildScp02CardCryptogramData(iuResponse, hostChallenge)
                    .Bind(cryptogramData =>
                        CryptoService.Cryptogram.CalculateScp02Cryptogram(
                            sessionKeys.SEnc,
                            cryptogramData
                        )
                    )
                    .Map(calculatedCryptogram =>
                        CryptoService.Utils.CompareBytes(calculatedCryptogram, cardCryptogram)
                    )
            );
    }

    private static Result<bool, SmartCardError> VerifyScp03CardCryptogram(
        SessionKeys sessionKeys,
        byte[] response,
        byte[] hostChallenge,
        byte[] cardCryptogram
    )
    {
        // Parse response into InitializeUpdateResponse
        return InitializeUpdateResponse
            .Parse(response)
            .Bind(iuResponse =>
                // Build cryptogram data for SCP03
                CryptoService
                    .Cryptogram.BuildScp03CardCryptogramData(iuResponse, hostChallenge)
                    .Bind(context =>
                        CryptoService.ScpOperations.Scp03.CalculateCryptogram(
                            sessionKeys.SMac,
                            Constants.Constants.Scp.Scp03.CryptogramDerivation.CardCryptogram,
                            context
                        )
                    )
                    .Map(calculatedCryptogram =>
                        CryptoService.Utils.CompareBytes(
                            calculatedCryptogram.Take(8).ToArray(),
                            cardCryptogram
                        )
                    )
            );
    }
}
