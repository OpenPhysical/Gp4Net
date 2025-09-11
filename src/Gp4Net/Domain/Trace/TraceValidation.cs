using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using static Gp4Net.Cryptography.CryptoService;

namespace Gp4Net.Domain.Trace;

/// <summary>
/// Pure functional trace validation using existing CryptoService functions.
/// </summary>
[PublicAPI]
public static class TraceValidation
{
    /// <summary>
    /// Validates a trace exchange based on its command type.
    /// </summary>
    /// <param name="state">The current validation state.</param>
    /// <param name="command">The command APDU bytes.</param>
    /// <param name="response">The response APDU bytes.</param>
    /// <param name="exchangeIndex">The index of this exchange in the trace.</param>
    /// <returns>Updated validation state with results.</returns>
    public static Result<TraceValidationState, SmartCardError> ValidateExchange(
        TraceValidationState state,
        byte[] command,
        byte[] response,
        int exchangeIndex)
    {
        return Maybe<byte[]>.From(command)
            .ToResult(SmartCardError.InvalidArgument("Command is required"))
            .Bind(_ => command.Length > 0
                ? Result.Success<byte[], SmartCardError>(command)
                : Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidArgument("Command cannot be empty"))
            )
            .Bind(cmd =>
            {
                var ins = cmd.Length > 1 ? cmd[1] : (byte)0x00;
                var isSecure = (cmd[0] & 0x04) == 0x04;

                return ins switch
                {
                    0x50 => ValidateInitializeUpdate(state, command, response, exchangeIndex),
                    0x82 => ValidateExternalAuthenticate(state, command, response, exchangeIndex),
                    _ when isSecure => ValidateSecureCommand(state, command, response, exchangeIndex),
                    _ => Result.Success<TraceValidationState, SmartCardError>(state) // Non-secure commands pass through
                };
            });
    }

    private static Result<TraceValidationState, SmartCardError> ValidateInitializeUpdate(
        TraceValidationState state,
        byte[] command,
        byte[] response,
        int exchangeIndex)
    {
        return Maybe<byte[]>.From(response)
            .ToResult(SmartCardError.InvalidArgument("Response is required"))
            .Bind(resp => resp.Length > 0
                ? Result.Success<byte[], SmartCardError>(resp)
                : Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidArgument("Response cannot be empty"))
            )
            .Bind(resp =>
            {
                // Remove status word if present
                var responseData = resp.Length > 2 && 
                                   resp[^2] == 0x90 && 
                                   resp[^1] == 0x00
                    ? resp[..^2]
                    : resp;

                return InitializeUpdateResponse.Parse(responseData);
            })
            .Bind(parsedResponse =>
            {
                // Extract host challenge from command
                var hostChallenge = command.Length >= 13 
                    ? command.Skip(5).Take(8).ToArray()
                    : new byte[8];

                // Determine SCP version
                var scpVersion = parsedResponse.ScpVersion.GetValueOrDefault(ScpVersion.Scp02);

                // Derive session keys (for SCP03, we need host challenge)
                return DeriveSessionKeys(state.BaseKeys, parsedResponse, scpVersion, hostChallenge)
                    .Bind(sessionKeys =>
                    {
                        // Validate card cryptogram
                        return ValidateCardCryptogram(
                            sessionKeys, 
                            parsedResponse, 
                            hostChallenge,
                            scpVersion
                        )
                        .Map(isValid =>
                        {
                            var result = isValid
                                ? ValidationResult.Success(
                                    exchangeIndex, 
                                    "INITIALIZE_UPDATE", 
                                    "Card cryptogram validated")
                                : ValidationResult.Failure(
                                    exchangeIndex,
                                    "INITIALIZE_UPDATE",
                                    "Card cryptogram validation failed",
                                    "Invalid card cryptogram");

                            return state
                                .WithSessionKeys(sessionKeys)
                                .WithSequenceCounter(parsedResponse.SequenceCounter)
                                .WithScpVersion(scpVersion)
                                .WithCardChallenge(parsedResponse.CardChallenge)
                                .WithHostChallenge(hostChallenge)
                                .AddResult(result);
                        });
                    });
            });
    }

    private static Result<TraceValidationState, SmartCardError> ValidateExternalAuthenticate(
        TraceValidationState state,
        byte[] command,
        byte[] response,
        int exchangeIndex)
    {
        return state.SessionKeys.Match(
            sessionKeys =>
            {
                // Extract host cryptogram and MAC from command
                if (command.Length < 21)
                {
                    var failResult = ValidationResult.Failure(
                        exchangeIndex,
                        "EXTERNAL_AUTHENTICATE",
                        "Command too short",
                        "Invalid command length");
                    return Result.Success<TraceValidationState, SmartCardError>(
                        state.AddResult(failResult));
                }

                var hostCryptogram = command.Skip(5).Take(8).ToArray();
                var commandMac = command.Skip(13).Take(8).ToArray();

                // Validate the host cryptogram using the session keys
                return ValidateHostCryptogram(
                    sessionKeys, 
                    state.SequenceCounter, 
                    state.CardChallenge,
                    state.HostChallenge,
                    hostCryptogram,
                    state.ScpVersion)
                    .Bind(hostCryptogramValid =>
                    {
                        // Validate the C-MAC on the EXTERNAL AUTHENTICATE command
                        var macData = command.Take(13).ToArray(); // CLA|INS|P1|P2|Lc|HostCryptogram
                        macData[4] = 0x10; // Adjust Lc to include MAC length
                        
                        // Calculate MAC based on protocol version
                        var macResult = state.ScpVersion switch
                        {
                            ScpVersion.Scp02 => CryptoService.Mac.CalculateScp02CommandMac(
                                sessionKeys.SMac,
                                macData,
                                new byte[8] // Initial ICV is zeros for EXTERNAL AUTHENTICATE
                            ),
                            ScpVersion.Scp03 => 
                                // For SCP03, prepend the ICV to the data
                                CryptoService.Mac.CalculateScp03CommandMac(
                                    sessionKeys.SMac,
                                    new byte[16].Concat(macData).ToArray() // ICV || data
                                ),
                            _ => Result.Failure<byte[], SmartCardError>(
                                SmartCardError.Unsupported($"Unsupported SCP version: {state.ScpVersion}"))
                        };
                        
                        return macResult
                        .Map(expectedMac =>
                        {
                            var macValid = expectedMac.SequenceEqual(commandMac);
                            var result = hostCryptogramValid && macValid
                                ? ValidationResult.Success(
                                    exchangeIndex,
                                    "EXTERNAL_AUTHENTICATE",
                                    "Host cryptogram and C-MAC validated")
                                : ValidationResult.Failure(
                                    exchangeIndex,
                                    "EXTERNAL_AUTHENTICATE",
                                    "Validation failed",
                                    hostCryptogramValid ? "Invalid C-MAC" : "Invalid host cryptogram");

                            // The C-MAC becomes the new ICV
                            return state.WithCommandIcv(commandMac).AddResult(result);
                        });
                    })
                    .Match(
                        success => Result.Success<TraceValidationState, SmartCardError>(success),
                        error => Result.Failure<TraceValidationState, SmartCardError>(error)
                    );
            },
            () =>
            {
                var result = ValidationResult.Failure(
                    exchangeIndex,
                    "EXTERNAL_AUTHENTICATE",
                    "No session keys available",
                    "Session keys not established");
                return Result.Success<TraceValidationState, SmartCardError>(
                    state.AddResult(result));
            }
        );
    }

    private static Result<TraceValidationState, SmartCardError> ValidateSecureCommand(
        TraceValidationState state,
        byte[] command,
        byte[] response,
        int exchangeIndex)
    {
        return state.SessionKeys.Match(
            sessionKeys =>
            {
                // Check if there's a trailing Le byte (common in traces)
                // For secure messaging, Le comes after the MAC
                var hasLe = command.Length > 13 && command[^1] == 0x00;
                var effectiveBytes = hasLe 
                    ? command.Take(command.Length - 1).ToArray()
                    : command;
                
                // Extract MAC from end of command (excluding Le if present)
                if (effectiveBytes.Length < 13) // Min: CLA INS P1 P2 Lc (5) + MAC (8)
                {
                    var failResult = ValidationResult.Failure(
                        exchangeIndex,
                        "C-MAC",
                        "Command too short for MAC",
                        "Invalid command length");
                    return Result.Success<TraceValidationState, SmartCardError>(
                        state.AddResult(failResult));
                }

                var commandMac = effectiveBytes.Skip(effectiveBytes.Length - 8).ToArray();
                var commandData = effectiveBytes.Take(effectiveBytes.Length - 8).ToArray();

                // Get current ICV (or zeros if first command after EXTERNAL AUTHENTICATE)
                var icv = state.CommandIcv.GetValueOrDefault(new byte[8]);

                // Calculate expected MAC based on protocol version
                var macResult = state.ScpVersion switch
                {
                    ScpVersion.Scp02 => 
                        // For SCP02, encrypt the ICV before using it (except for first MAC)
                        (state.CommandIcv.HasValue
                            ? CryptoService.Mac.EncryptScp02Icv(icv, sessionKeys.SMac)
                            : Result.Success<byte[], SmartCardError>(icv))
                        .Bind(encryptedIcv =>
                            CryptoService.Mac.CalculateScp02CommandMac(
                                sessionKeys.SMac,
                                commandData,
                                encryptedIcv
                            )
                        ),
                    ScpVersion.Scp03 =>
                        // For SCP03, use AES-CMAC with chaining (ICV prepended to data)
                        CryptoService.Mac.CalculateScp03CommandMac(
                            sessionKeys.SMac,
                            icv.Concat(commandData).ToArray()
                        ),
                    _ => Result.Failure<byte[], SmartCardError>(
                        SmartCardError.Unsupported($"Unsupported SCP version: {state.ScpVersion}"))
                };

                return macResult
                .Map(expectedMac =>
                {
                    var isValid = expectedMac.SequenceEqual(commandMac);
                    var result = isValid
                        ? ValidationResult.Success(
                            exchangeIndex,
                            "C-MAC",
                            $"Command MAC valid")
                        : ValidationResult.Failure(
                            exchangeIndex,
                            "C-MAC",
                            "Command MAC validation failed",
                            $"Expected: {Convert.ToHexString(expectedMac)}, Got: {Convert.ToHexString(commandMac)}");

                    // Update ICV with the calculated MAC for next command
                    return state.WithCommandIcv(commandMac).AddResult(result);
                });
            },
            () => Result.Success<TraceValidationState, SmartCardError>(
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

    private static Result<SessionKeys, SmartCardError> DeriveSessionKeys(
        IKeySet baseKeys,
        InitializeUpdateResponse response,
        ScpVersion scpVersion,
        byte[] hostChallenge)
    {
        return scpVersion switch
        {
            ScpVersion.Scp02 => DeriveScp02SessionKeys(baseKeys, response.SequenceCounter),
            ScpVersion.Scp03 => DeriveScp03SessionKeys(baseKeys, response, hostChallenge),
            _ => Result.Failure<SessionKeys, SmartCardError>(
                SmartCardError.Unsupported($"Unsupported SCP version: {scpVersion}"))
        };
    }

    private static Result<SessionKeys, SmartCardError> DeriveScp02SessionKeys(
        IKeySet baseKeys,
        byte[] sequenceCounter)
    {
        // Derive all three session keys
        var sEncResult = CryptoService.KeyDerivation.DeriveScp02SessionKey(
            baseKeys.EncKey,
            sequenceCounter,
            Constants.Constants.Scp.Scp02.KeyDerivationConstants.SEnc
        );

        var sMacResult = CryptoService.KeyDerivation.DeriveScp02SessionKey(
            baseKeys.MacKey,
            sequenceCounter,
            Constants.Constants.Scp.Scp02.KeyDerivationConstants.SMac
        );

        var sDekResult = CryptoService.KeyDerivation.DeriveScp02SessionKey(
            baseKeys.DekKey,
            sequenceCounter,
            Constants.Constants.Scp.Scp02.KeyDerivationConstants.SDek
        );

        return sEncResult.Bind(sEnc =>
            sMacResult.Bind(sMac =>
                sDekResult.Map(sDek =>
                    new SessionKeys(sEnc, sMac, sMac, sDek) // R-MAC key same as MAC for SCP02
                )
            )
        );
    }
    
    private static Result<SessionKeys, SmartCardError> DeriveScp03SessionKeys(
        IKeySet baseKeys,
        InitializeUpdateResponse response,
        byte[] hostChallenge)
    {
        // Derive all session keys using SCP03 key derivation
        // Parameters: baseKey, hostChallenge, cardChallenge, derivationConstant
        var sEncResult = CryptoService.KeyDerivation.DeriveScp03SessionKey(
            baseKeys.EncKey,
            hostChallenge,
            response.CardChallenge,
            (byte)Constants.Constants.Scp.Scp03.KeyDerivationLabel.SEnc
        );

        var sMacResult = CryptoService.KeyDerivation.DeriveScp03SessionKey(
            baseKeys.MacKey,
            hostChallenge,
            response.CardChallenge,
            (byte)Constants.Constants.Scp.Scp03.KeyDerivationLabel.SMac
        );

        var sRmacResult = CryptoService.KeyDerivation.DeriveScp03SessionKey(
            baseKeys.MacKey,
            hostChallenge,
            response.CardChallenge,
            (byte)Constants.Constants.Scp.Scp03.KeyDerivationLabel.SRMac
        );

        // For SCP03, S-DEK uses label 0x08
        var sDekResult = CryptoService.KeyDerivation.DeriveScp03SessionKey(
            baseKeys.DekKey,
            hostChallenge,
            response.CardChallenge,
            0x08 // S-DEK label
        );

        return sEncResult.Bind(sEnc =>
            sMacResult.Bind(sMac =>
                sRmacResult.Bind(sRmac =>
                    sDekResult.Map(sDek =>
                        new SessionKeys(sEnc, sMac, sRmac, sDek)
                    )
                )
            )
        );
    }

    private static Result<bool, SmartCardError> ValidateCardCryptogram(
        SessionKeys sessionKeys,
        InitializeUpdateResponse response,
        byte[] hostChallenge,
        ScpVersion scpVersion)
    {
        return scpVersion switch
        {
            ScpVersion.Scp02 => ValidateScp02CardCryptogram(sessionKeys, response, hostChallenge),
            ScpVersion.Scp03 => ValidateScp03CardCryptogram(sessionKeys, response, hostChallenge),
            _ => Result.Failure<bool, SmartCardError>(
                SmartCardError.Unsupported($"Unknown SCP version: {scpVersion}"))
        };
    }
    
    private static Result<bool, SmartCardError> ValidateScp02CardCryptogram(
        SessionKeys sessionKeys,
        InitializeUpdateResponse response,
        byte[] hostChallenge)
    {
        // Build cryptogram data for SCP02
        return CryptoService.Cryptogram.BuildScp02CardCryptogramData(response, hostChallenge)
            .Bind(cryptogramData =>
                CryptoService.Cryptogram.CalculateScp02Cryptogram(sessionKeys.SEnc, cryptogramData)
            )
            .Map(calculatedCryptogram => 
                calculatedCryptogram.SequenceEqual(response.CardCryptogram));
    }
    
    private static Result<bool, SmartCardError> ValidateScp03CardCryptogram(
        SessionKeys sessionKeys,
        InitializeUpdateResponse response,
        byte[] hostChallenge)
    {
        // Build cryptogram data for SCP03
        return CryptoService.Cryptogram.BuildScp03CardCryptogramData(response, hostChallenge)
            .Bind(cryptogramData =>
                CryptoService.Cryptogram.CalculateScp03Cryptogram(sessionKeys.SMac, cryptogramData)
            )
            .Map(calculatedCryptogram => 
                calculatedCryptogram.SequenceEqual(response.CardCryptogram));
    }

    private static Result<bool, SmartCardError> ValidateHostCryptogram(
        SessionKeys sessionKeys,
        byte[] sequenceCounter,
        byte[] cardChallenge,
        byte[] hostChallenge,
        byte[] hostCryptogram,
        ScpVersion scpVersion)
    {
        return scpVersion switch
        {
            ScpVersion.Scp02 => ValidateScp02HostCryptogram(
                sessionKeys, sequenceCounter, cardChallenge, hostChallenge, hostCryptogram),
            ScpVersion.Scp03 => ValidateScp03HostCryptogram(
                sessionKeys, cardChallenge, hostChallenge, hostCryptogram),
            _ => Result.Failure<bool, SmartCardError>(
                SmartCardError.Unsupported($"Unknown SCP version: {scpVersion}"))
        };
    }
    
    private static Result<bool, SmartCardError> ValidateScp02HostCryptogram(
        SessionKeys sessionKeys,
        byte[] sequenceCounter,
        byte[] cardChallenge,
        byte[] hostChallenge,
        byte[] hostCryptogram)
    {
        // Build host cryptogram data (sequence counter || card challenge || host challenge)
        var cryptogramData = sequenceCounter
            .Concat(cardChallenge)
            .Concat(hostChallenge)
            .ToArray();

        return CryptoService.Cryptogram.CalculateScp02Cryptogram(sessionKeys.SEnc, cryptogramData)
            .Map(calculatedCryptogram => 
                calculatedCryptogram.SequenceEqual(hostCryptogram));
    }
    
    private static Result<bool, SmartCardError> ValidateScp03HostCryptogram(
        SessionKeys sessionKeys,
        byte[] cardChallenge,
        byte[] hostChallenge,
        byte[] hostCryptogram)
    {
        // Build host cryptogram data directly for SCP03 (card challenge || host challenge)
        var cryptogramData = cardChallenge.Concat(hostChallenge).ToArray();
        
        return CryptoService.Cryptogram.CalculateScp03Cryptogram(sessionKeys.SMac, cryptogramData)
            .Map(calculatedCryptogram => 
                calculatedCryptogram.SequenceEqual(hostCryptogram));
    }

    private static string GetCommandName(byte[] commandBytes)
    {
        if (commandBytes.Length < 2)
            return "UNKNOWN";

        return commandBytes[1] switch
        {
            0xF2 when commandBytes.Length > 2 && commandBytes[2] == 0x80 => "GET STATUS (ISD)",
            0xF2 when commandBytes.Length > 2 && commandBytes[2] == 0x40 => "GET STATUS (Apps)",
            0xF2 when commandBytes.Length > 2 && commandBytes[2] == 0x20 => "GET STATUS (Apps and SD)",
            0xF2 when commandBytes.Length > 2 && commandBytes[2] == 0x10 => "GET STATUS (Load Files)",
            0xF2 => "GET STATUS",
            0xE6 => "INSTALL",
            0xE8 => "LOAD",
            0xE4 => "DELETE",
            0xD8 => "PUT KEY",
            0xCA => "GET DATA",
            0xDA => "PUT DATA",
            _ => $"INS={commandBytes[1]:X2}"
        };
    }
}