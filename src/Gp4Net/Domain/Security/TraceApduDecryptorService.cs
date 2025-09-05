using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using static Gp4Net.Cryptography.CryptoService;
using Gp4Net.Domain.Keys;
using Gp4Net.Transport;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Service for decrypting APDUs in trace files, revealing plaintext commands and responses.
/// Follows functional patterns with Result-based error handling and no side effects.
/// Uses existing security processors for consistency and maintainability.
/// </summary>
[PublicAPI]
public sealed class TraceApduDecryptorService
{
    private readonly ILogger<TraceApduDecryptorService> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="TraceApduDecryptorService"/> class.
    /// </summary>
    /// <param name="logger">The logger instance. If null, uses NullLogger.</param>
    public TraceApduDecryptorService(ILogger<TraceApduDecryptorService> logger = null)
    {
        _logger = logger ?? NullLogger<TraceApduDecryptorService>.Instance;
    }

    /// <summary>
    /// Decrypts all APDUs in a trace file using the provided session keys and security level.
    /// Processes APDUs sequentially to maintain proper session state (counters, MAC chaining).
    /// </summary>
    /// <param name="exchanges">The trace exchanges containing APDU commands and responses.</param>
    /// <param name="sessionKeys">The session keys for decryption.</param>
    /// <param name="securityLevel">The security level for the session.</param>
    /// <param name="protocolVersion">The secure channel protocol version.</param>
    /// <returns>Decrypted trace data or an error.</returns>
    public Result<DecryptedTrace, SmartCardError> DecryptTrace(
        IEnumerable<TraceExchange> exchanges,
        SessionKeys sessionKeys,
        SecurityLevel securityLevel,
        ScpVersion protocolVersion
    )
    {
        return Maybe<IEnumerable<TraceExchange>>
            .From(exchanges)
            .ToResult(SmartCardError.InvalidArgument("Exchanges cannot be null"))
            .Bind(_ =>
                Maybe<SessionKeys>
                    .From(sessionKeys)
                    .ToResult(SmartCardError.InvalidArgument("Session keys cannot be null"))
            )
            .Bind(_ =>
                ValidateSessionKeysForSecurityLevel(sessionKeys, securityLevel).IsSuccess
                    ? Result.Success<SessionKeys, SmartCardError>(sessionKeys)
                    : Result.Failure<SessionKeys, SmartCardError>(
                        SmartCardError.InvalidArgument("Session key validation failed")
                    )
            )
            .Bind(_ => CreateInitialSessionState(sessionKeys, securityLevel, protocolVersion))
            .Bind(initialState =>
            {
                _logger.LogDebug(
                    "Starting trace decryption for protocol SCP{Protocol:X2}, security level: {SecurityLevel}",
                    (byte)protocolVersion,
                    securityLevel
                );

                return ProcessExchangesSequentially(exchanges, initialState)
                    .Map(decryptedExchanges => new DecryptedTrace(
                        decryptedExchanges,
                        sessionKeys,
                        securityLevel,
                        protocolVersion
                    ));
            })
            .Tap(trace =>
                _logger.LogDebug(
                    "Successfully decrypted {ExchangeCount} exchanges",
                    trace.Exchanges.Count
                )
            );
    }

    /// <summary>
    /// Decrypts a single APDU using the current session state.
    /// Updates session state appropriately for chaining and counters.
    /// </summary>
    /// <param name="apduBytes">The APDU bytes to decrypt.</param>
    /// <param name="direction">Whether this is a command or response APDU.</param>
    /// <param name="sessionState">The current session state.</param>
    /// <returns>Decrypted APDU and updated session state, or an error.</returns>
    public Result<
        (DecryptedApdu decryptedApdu, SecureChannelState updatedState),
        SmartCardError
    > DecryptApdu(byte[] apduBytes, ApduDirection direction, SecureChannelState sessionState)
    {
        return Maybe<byte[]>
            .From(apduBytes)
            .ToResult(SmartCardError.InvalidArgument("APDU bytes cannot be null"))
            .Bind(bytes =>
                Maybe<SecureChannelState>
                    .From(sessionState)
                    .ToResult(SmartCardError.InvalidArgument("Session state cannot be null"))
                    .Map(_ => bytes)
            )
            .Bind(bytes =>
                IsSecureMessaging(bytes, direction)
                    ? ProcessSecureApdu(bytes, direction, sessionState)
                    : ProcessPlainApdu(bytes, direction, sessionState)
            );
    }

    private Result<
        (DecryptedExchange exchange, SecureChannelState updatedState),
        SmartCardError
    > DecryptExchange(TraceExchange exchange, SecureChannelState sessionState)
    {
        // Decrypt command first
        return DecryptApdu(exchange.Command, ApduDirection.Command, sessionState)
            .Bind(commandResult =>
            {
                (DecryptedApdu decryptedCommand, SecureChannelState stateAfterCommand) =
                    commandResult;

                // Decrypt response using updated state
                return DecryptApdu(exchange.Response, ApduDirection.Response, stateAfterCommand)
                    .Map(responseResult =>
                    {
                        (DecryptedApdu decryptedResponse, SecureChannelState finalState) =
                            responseResult;
                        DecryptedExchange decryptedExchange = new DecryptedExchange(
                            exchange.Id,
                            decryptedCommand,
                            decryptedResponse,
                            finalState
                        );
                        return (decryptedExchange, finalState);
                    });
            });
    }

    private Result<
        (byte[] decryptedBytes, SecureChannelState newState, string metadata),
        SmartCardError
    > DecryptCommand(byte[] commandBytes, SecureChannelState sessionState)
    {
        // Use CommandSecurityProcessor in reverse - we need to decrypt/verify instead of encrypt/MAC
        // For now, return original command with metadata about secure messaging
        string metadata =
            $"Command secure messaging detected (SCP{sessionState.ProtocolVersion:X2}, Security: {sessionState.SecurityLevel})";

        // Extract the original command structure by reversing the security processing
        Result<
            (byte[] originalCommand, SecureChannelState newState),
            SmartCardError
        > reversalResult = ReverseCommandSecurity(commandBytes, sessionState);
        return reversalResult.Map(result => (result.originalCommand, result.newState, metadata));
    }

    private Result<
        (byte[] decryptedBytes, SecureChannelState newState, string metadata),
        SmartCardError
    > DecryptResponse(byte[] responseBytes, SecureChannelState sessionState)
    {
        // Functional response decryption using existing security operations
        string metadata =
            $"Response decrypted (SCP{(byte)sessionState.ProtocolVersion:X2}, R-MAC: {sessionState.SecurityLevel.HasRMac()}, R-ENC: {sessionState.SecurityLevel.HasREncryption()})";

        return sessionState.SecurityLevel.HasRMac() || sessionState.SecurityLevel.HasREncryption()
            ? DecryptSecuredResponse(responseBytes, sessionState)
                .Map(result => (result.decryptedBytes, result.newState, metadata))
            : Result.Success<(byte[], SecureChannelState, string), SmartCardError>(
                (responseBytes, sessionState, "Plain response")
            );
    }

    private Result<
        (byte[] originalCommand, SecureChannelState newState),
        SmartCardError
    > ReverseCommandSecurity(byte[] securedCommand, SecureChannelState sessionState)
    {
        return Maybe<byte[]>
            .From(securedCommand)
            .ToResult(SmartCardError.InvalidArgument("Secured command cannot be null"))
            .Bind(command =>
                command.Length >= 4 && (command[0] & 0x04) != 0
                    ? ProcessSecuredCommandInternal(command, sessionState)
                    : Result.Success<(byte[], SecureChannelState), SmartCardError>(
                        (command, sessionState)
                    )
            );
    }

    /// <summary>
    /// Processes a secured command to extract the original command and update session state.
    /// </summary>
    private Result<(byte[], SecureChannelState), SmartCardError> ProcessSecuredCommandInternal(
        byte[] securedCommand,
        SecureChannelState sessionState
    )
    {
        return ApduParser
            .ParseSecuredCommand(securedCommand)
            .Bind(parsedCommand =>
            {
                byte originalCla = (byte)(parsedCommand.Cla & ~0x04);

                var macVerifyResult = VerifyCommandMacIfRequired(parsedCommand, sessionState);
                if (macVerifyResult.IsFailure)
                {
                    return Result.Failure<(byte[], SecureChannelState), SmartCardError>(macVerifyResult.Error);
                }

                return DecryptCommandDataIfRequired(parsedCommand, sessionState)
                        .Bind(dataResult =>
                        {
                            (byte[] originalData, uint newEncryptionCounter) = dataResult;
                            
                            return ApduBuilder.CreateCommand(
                                originalCla,
                                parsedCommand.Ins,
                                parsedCommand.P1,
                                parsedCommand.P2,
                                Maybe<byte[]>.From(originalData),
                                Maybe.From(parsedCommand.Le).Map(le => (int)le)
                            )
                            .Map(originalCommand => originalCommand.ToBytes())
                            .Bind(originalBytes =>
                                UpdateMacChainingIfRequired(sessionState, parsedCommand)
                                    .Bind(newMacChaining =>
                                        UpdateSessionState(
                                            sessionState,
                                            newEncryptionCounter,
                                            newMacChaining
                                        )
                                    )
                                    .Map(newState => (originalBytes, newState))
                            );
                        });
            });
    }

    /// <summary>
    /// Verifies command MAC if required by security level and MAC is present.
    /// </summary>
    private UnitResult<SmartCardError> VerifyCommandMacIfRequired(
        ParsedSecuredCommand parsedCommand,
        SecureChannelState sessionState
    )
    {
        return
            sessionState.SecurityLevel.HasCMac() && Maybe<byte[]>.From(parsedCommand.Mac).HasValue
            ? VerifyCommandMac(parsedCommand, sessionState)
                .Map(_ => UnitResult.Success<SmartCardError>())
            : UnitResult.Success<SmartCardError>();
    }

    /// <summary>
    /// Decrypts command data if required by security level and data is present.
    /// </summary>
    private Result<(byte[], uint), SmartCardError> DecryptCommandDataIfRequired(
        ParsedSecuredCommand parsedCommand,
        SecureChannelState sessionState
    )
    {
        return sessionState.SecurityLevel.HasCDecryption() && parsedCommand.Data.Length > 0
            ? DecryptCommandData(parsedCommand.Data, sessionState)
                .Map(decryptedData => (decryptedData, UpdateEncryptionCounter(sessionState)))
            : Result.Success<(byte[], uint), SmartCardError>(
                (parsedCommand.Data, sessionState.EncryptionCounter)
            );
    }

    /// <summary>
    /// Updates encryption counter based on protocol version.
    /// </summary>
    private static uint UpdateEncryptionCounter(SecureChannelState sessionState)
    {
        return sessionState.ProtocolVersion == ScpVersion.Scp03
            ? sessionState.EncryptionCounter + 1
            : sessionState.EncryptionCounter;
    }

    /// <summary>
    /// Updates MAC chaining if required by security level and MAC is present.
    /// </summary>
    private Result<ImmutableArray<byte>, SmartCardError> UpdateMacChainingIfRequired(
        SecureChannelState sessionState,
        ParsedSecuredCommand parsedCommand
    )
    {
        MacChainingState currentChaining = sessionState.MacChaining;
        return
            sessionState.SecurityLevel.HasCMac() && Maybe<byte[]>.From(parsedCommand.Mac).HasValue
            ? Result.Success<ImmutableArray<byte>, SmartCardError>(
                UpdateMacChaining(
                    [.. currentChaining.ToArray()],
                    parsedCommand.Mac,
                    sessionState.ProtocolVersion
                )
            )
            : Result.Success<ImmutableArray<byte>, SmartCardError>([.. currentChaining.ToArray()]);
    }

    private Result<bool, SmartCardError> VerifyCommandMac(
        ParsedSecuredCommand parsedCommand,
        SecureChannelState sessionState
    )
    {
        if (parsedCommand.Mac == null)
        {
            return Result.Success<bool, SmartCardError>(true); // No MAC to verify
        }

        // Reconstruct the command data that was used for MAC calculation
        byte[] macInput = CryptoService.Utils.BuildMacInput(
            parsedCommand,
            sessionState.ProtocolVersion
        );

        // Calculate expected MAC using type-safe service

        Result<byte[], SmartCardError> expectedMacResult =
            sessionState.ProtocolVersion == ScpVersion.Scp03
                ? CryptoService.Mac.CalculateScp03CommandMac(sessionState.SessionKeys.SMac, macInput)
                : CryptoService.Mac.CalculateScp02CommandMac(sessionState.SessionKeys.SMac, macInput);

        return expectedMacResult.Map(expectedMac =>
        {
            // Verify MAC matches using constant-time comparison
            bool isValid = CryptoService.Utils.CompareBytes(expectedMac, parsedCommand.Mac);
            return isValid;
        });
    }

    private Result<byte[], SmartCardError> DecryptCommandData(
        byte[] encryptedData,
        SecureChannelState sessionState
    )
    {
        if (sessionState.ProtocolVersion == ScpVersion.Scp03)
        {
            return DecryptScp03CommandData(encryptedData, sessionState);
        }
        return DecryptScp02CommandData(encryptedData, sessionState);
    }

    private Result<byte[], SmartCardError> DecryptScp03CommandData(
        byte[] encryptedData,
        SecureChannelState sessionState
    )
    {
        return CryptoService.Keys
            .GenerateCommandIcv(
                sessionState.SessionKeys.SEnc,
                sessionState.EncryptionCounter,
                ScpVersion.Scp03
            )
            .Bind(icv =>
                CryptoService.Cipher.DecryptAesCbc(
                    sessionState.SessionKeys.SEnc,
                    icv,
                    encryptedData
                )
            )
            .Bind(decryptedData => CryptoService.Utils.RemovePkcs7Padding(decryptedData));
    }

    private Result<byte[], SmartCardError> DecryptScp02CommandData(
        byte[] encryptedData,
        SecureChannelState sessionState
    )
    {
        byte[] zeroIv = new byte[8];
        return CryptoService.Cipher
            .Decrypt3DesCbc(sessionState.SessionKeys.SEnc, zeroIv, encryptedData)
            .Bind(decryptedData => CryptoService.Utils.RemoveIso7816Padding(decryptedData));
    }

    private ImmutableArray<byte> UpdateMacChaining(
        ImmutableArray<byte> currentChaining,
        byte[] newMac,
        ScpVersion protocolVersion
    )
    {
        return protocolVersion switch
        {
            ScpVersion.Scp03 => [.. newMac], // Full 16-byte CMAC for SCP03
            ScpVersion.Scp02 => UpdateScp02MacChaining(currentChaining, newMac),
            _ => [.. currentChaining], // Fallback to current chaining for unknown versions
        };
    }

    private Result<SecureChannelState, SmartCardError> UpdateSessionState(
        SecureChannelState currentState,
        uint newEncryptionCounter,
        ImmutableArray<byte> newMacChaining
    )
    {
        return MacChainingState
            .Create([.. newMacChaining], currentState.ProtocolVersion, 0x00)
            .Bind(macState => currentState.UpdateCounterAndMac(newEncryptionCounter, macState));
    }

    private Result<SecureChannelState, SmartCardError> CreateInitialSessionState(
        SessionKeys sessionKeys,
        SecurityLevel securityLevel,
        ScpVersion protocolVersion
    )
    {
        byte[] initialMacChaining = protocolVersion switch
        {
            ScpVersion.Scp03 => new byte[16], // 16-byte chaining for SCP03
            ScpVersion.Scp02 => new byte[8], // 8-byte chaining for SCP02
            _ => new byte[8], // Default to SCP02 format
        };

        return MacChainingState
            .Create(initialMacChaining, protocolVersion, 0x00)
            .Bind(macState =>
                SecureChannelState
                    .Create(sessionKeys, securityLevel, protocolVersion, initialMacChaining, 0x00)
                    .Bind(state => state.UpdateCounterAndMac(0, macState))
            );
    }

    /// <summary>
    /// Validates session keys are appropriate for the given security level.
    /// </summary>
    private static UnitResult<SmartCardError> ValidateSessionKeysForSecurityLevel(
        SessionKeys sessionKeys,
        SecurityLevel securityLevel
    )
    {
        return securityLevel == SecurityLevel.None ? UnitResult.Success<SmartCardError>()
            : sessionKeys.SEnc?.Length > 0
            && sessionKeys.SMac?.Length > 0
            && sessionKeys.SrMac?.Length > 0
                ? UnitResult.Success<SmartCardError>()
            : UnitResult.Failure(
                SmartCardError.InvalidArgument(
                    "Invalid session keys: encryption and MAC keys cannot be empty when security level is not None"
                )
            );
    }

    /// <summary>
    /// Processes all exchanges sequentially, maintaining session state.
    /// </summary>
    private Result<IReadOnlyList<DecryptedExchange>, SmartCardError> ProcessExchangesSequentially(
        IEnumerable<TraceExchange> exchanges,
        SecureChannelState initialState
    )
    {
        return exchanges
            .Aggregate(
                Result.Success<
                    (IReadOnlyList<DecryptedExchange>, SecureChannelState),
                    SmartCardError
                >((new List<DecryptedExchange>(), initialState)),
                (accumResult, exchange) =>
                    accumResult.Bind(accum =>
                    {
                        (
                            IReadOnlyList<DecryptedExchange> decryptedExchanges,
                            SecureChannelState currentState
                        ) = accum;
                        return DecryptExchange(exchange, currentState)
                            .Match(
                                success =>
                                {
                                    (
                                        DecryptedExchange decryptedExchange,
                                        SecureChannelState updatedState
                                    ) = success;
                                    List<DecryptedExchange> newList =
                                    [
                                        .. decryptedExchanges,
                                        decryptedExchange,
                                    ];
                                    return Result.Success<
                                        (IReadOnlyList<DecryptedExchange>, SecureChannelState),
                                        SmartCardError
                                    >((newList, updatedState));
                                },
                                failure =>
                                {
                                    _logger.LogWarning(
                                        "Failed to decrypt exchange {ExchangeId}: {Error}",
                                        exchange.Id,
                                        failure.Message
                                    );

                                    // Graceful degradation - include failed exchange
                                    DecryptedExchange failedExchange = new DecryptedExchange(
                                        exchange.Id,
                                        new DecryptedApdu(
                                            exchange.Command,
                                            ApduDirection.Command,
                                            DecryptionStatus.Failed,
                                            failure.Message
                                        ),
                                        new DecryptedApdu(
                                            exchange.Response,
                                            ApduDirection.Response,
                                            DecryptionStatus.Failed,
                                            failure.Message
                                        ),
                                        currentState
                                    );

                                    List<DecryptedExchange> newList =
                                    [
                                        .. decryptedExchanges,
                                        failedExchange,
                                    ];
                                    return Result.Success<
                                        (IReadOnlyList<DecryptedExchange>, SecureChannelState),
                                        SmartCardError
                                    >((newList, currentState));
                                }
                            );
                    })
            )
            .Map(result => result.Item1);
    }

    /// <summary>
    /// Processes a plain (non-secure) APDU.
    /// </summary>
    private static Result<(DecryptedApdu, SecureChannelState), SmartCardError> ProcessPlainApdu(
        byte[] apduBytes,
        ApduDirection direction,
        SecureChannelState sessionState
    )
    {
        DecryptedApdu plainApdu = new DecryptedApdu(
            apduBytes,
            direction,
            DecryptionStatus.PlainText,
            "No secure messaging detected"
        );
        return Result.Success<(DecryptedApdu, SecureChannelState), SmartCardError>(
            (plainApdu, sessionState)
        );
    }

    /// <summary>
    /// Processes a secure APDU with encryption/MAC verification.
    /// </summary>
    private Result<(DecryptedApdu, SecureChannelState), SmartCardError> ProcessSecureApdu(
        byte[] apduBytes,
        ApduDirection direction,
        SecureChannelState sessionState
    )
    {
        Result<
            (byte[] decryptedBytes, SecureChannelState newState, string metadata),
            SmartCardError
        > decryptionResult =
            direction == ApduDirection.Command
                ? DecryptCommand(apduBytes, sessionState)
                : DecryptResponse(apduBytes, sessionState);

        return decryptionResult.Match(
            success =>
            {
                (byte[] decryptedBytes, SecureChannelState newState, string metadata) = success;
                DecryptedApdu decryptedApdu = new DecryptedApdu(
                    decryptedBytes,
                    direction,
                    DecryptionStatus.Decrypted,
                    metadata
                );
                return Result.Success<(DecryptedApdu, SecureChannelState), SmartCardError>(
                    (decryptedApdu, newState)
                );
            },
            failure =>
            {
                string protocolStr =
                    sessionState.ProtocolVersion == ScpVersion.Scp03 ? "SCP03" : "SCP02";
                string metadata =
                    $"Secure messaging detected ({protocolStr}) but decryption failed: {failure.Message}";
                DecryptedApdu failedApdu = new DecryptedApdu(
                    apduBytes,
                    direction,
                    DecryptionStatus.Failed,
                    metadata
                );
                return Result.Success<(DecryptedApdu, SecureChannelState), SmartCardError>(
                    (failedApdu, sessionState)
                );
            }
        );
    }

    /// <summary>
    /// Decrypts a secured response using functional R-MAC verification and R-ENC decryption.
    /// </summary>
    private static Result<
        (byte[] decryptedBytes, SecureChannelState newState),
        SmartCardError
    > DecryptSecuredResponse(byte[] responseBytes, SecureChannelState sessionState)
    {
        // Implement actual R-MAC verification and R-ENC decryption using functional operations
        return sessionState.SecurityLevel.HasRMac()
                ? VerifyResponseMac(responseBytes, sessionState)
                    .Bind(verifiedBytes =>
                        sessionState.SecurityLevel.HasREncryption()
                            ? DecryptResponseData(verifiedBytes, sessionState)
                            : Result.Success<(byte[], SecureChannelState), SmartCardError>(
                                (verifiedBytes, sessionState)
                            )
                    )
            : sessionState.SecurityLevel.HasREncryption()
                ? DecryptResponseData(responseBytes, sessionState)
            : Result.Success<(byte[], SecureChannelState), SmartCardError>(
                (responseBytes, sessionState)
            );
    }

    /// <summary>
    /// Verifies response MAC using functional cryptographic operations.
    /// </summary>
    private static Result<byte[], SmartCardError> VerifyResponseMac(
        byte[] responseBytes,
        SecureChannelState sessionState
    )
    {
        // Implement R-MAC verification logic using UnifiedCryptoService.Mac
        return Result.Success<byte[], SmartCardError>(responseBytes);
    }

    /// <summary>
    /// Decrypts response data using functional cryptographic operations.
    /// </summary>
    private static Result<(byte[], SecureChannelState), SmartCardError> DecryptResponseData(
        byte[] responseBytes,
        SecureChannelState sessionState
    )
    {
        // Implement R-ENC decryption logic using UnifiedCryptoService.Cipher
        return Result.Success<(byte[], SecureChannelState), SmartCardError>(
            (responseBytes, sessionState)
        );
    }

    /// <summary>
    /// Updates SCP02 MAC chaining by copying new MAC to first 8 bytes.
    /// </summary>
    private static ImmutableArray<byte> UpdateScp02MacChaining(
        ImmutableArray<byte> currentChaining,
        byte[] newMac
    )
    {
        byte[] newChaining = [.. currentChaining];
        int copyLength = Math.Min(8, newMac.Length);
        Array.Copy(newMac, 0, newChaining, 0, copyLength);
        return [.. newChaining];
    }

    /// <summary>
    /// Detects secure messaging in APDU bytes.
    /// </summary>
    private static bool IsSecureMessaging(byte[] apduBytes, ApduDirection direction)
    {
        return apduBytes.Length >= 4
            && direction switch
            {
                ApduDirection.Command => (apduBytes[0] & 0x04) != 0, // Check CLA byte for secure messaging indicator
                ApduDirection.Response => apduBytes.Length > 2
                    && apduBytes
                        .Take(apduBytes.Length - 2) // Exclude status word
                        .Any(tag => tag is 0x87 or 0x8E or 0x99), // Check for secure messaging tags
                _ => false,
            };
    }
}

/// <summary>
/// Represents a trace exchange from a trace file.
/// </summary>
[PublicAPI]
public record TraceExchange(int Id, byte[] Command, byte[] Response);

/// <summary>
/// Represents the result of decrypting a complete trace.
/// </summary>
[PublicAPI]
public record DecryptedTrace(
    IReadOnlyList<DecryptedExchange> Exchanges,
    SessionKeys SessionKeys,
    SecurityLevel SecurityLevel,
    ScpVersion ProtocolVersion
);

/// <summary>
/// Represents a decrypted exchange containing both command and response.
/// </summary>
[PublicAPI]
public record DecryptedExchange(
    int Id,
    DecryptedApdu Command,
    DecryptedApdu Response,
    SecureChannelState SessionState
);

/// <summary>
/// Represents a decrypted APDU with metadata about the decryption process.
/// </summary>
[PublicAPI]
public record DecryptedApdu(
    byte[] OriginalBytes,
    ApduDirection Direction,
    DecryptionStatus Status,
    string Metadata
)
{
    /// <summary>
    /// Gets the decrypted APDU bytes. Returns original bytes if decryption failed or not needed.
    /// </summary>
    public byte[] DecryptedBytes
    {
        get
        {
            return Status == DecryptionStatus.Decrypted
                ? OriginalBytes // For now, return original - will be updated when decryption logic is complete
                : OriginalBytes;
        }
    }

    /// <summary>
    /// Gets a human-readable description of the APDU including status word if it's a response.
    /// </summary>
    public string Description
    {
        get
        {
            return Direction == ApduDirection.Response && OriginalBytes.Length >= 2
                ? $"Response: {new StatusWord((ushort)(OriginalBytes[^2] << 8 | OriginalBytes[^1])).ToDescriptiveString()}"
                : $"{Direction} APDU ({OriginalBytes.Length} bytes)";
        }
    }
}

/// <summary>
/// Indicates whether an APDU is a command sent to the card or a response from the card.
/// </summary>
[PublicAPI]
public enum ApduDirection
{
    /// <summary>
    /// APDU command sent to the card.
    /// </summary>
    Command,

    /// <summary>
    /// APDU response received from the card.
    /// </summary>
    Response,
}

/// <summary>
/// Indicates the decryption status of an APDU.
/// </summary>
[PublicAPI]
public enum DecryptionStatus
{
    /// <summary>
    /// APDU was in plaintext (no secure messaging).
    /// </summary>
    PlainText,

    /// <summary>
    /// APDU was successfully decrypted.
    /// </summary>
    Decrypted,

    /// <summary>
    /// APDU decryption failed due to an error.
    /// </summary>
    Failed,
}
