using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Keys;
using Gp4Net.Services;
using Gp4Net.Transport;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using WSCT.ISO7816;
using static Gp4Net.Constants.Constants;
using static Gp4Net.Cryptography.CryptoService;

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
    public TraceApduDecryptorService(ILogger<TraceApduDecryptorService>? logger = null)
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
                (var decryptedCommand, var stateAfterCommand) = commandResult;

                // Decrypt response using updated state
                return DecryptApdu(exchange.Response, ApduDirection.Response, stateAfterCommand)
                    .Map(responseResult =>
                    {
                        (var decryptedResponse, var finalState) = responseResult;
                        var decryptedExchange = new DecryptedExchange(
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
        // Return original command with metadata about secure messaging
        string metadata =
            $"Command secure messaging detected (SCP{(int)sessionState.ProtocolVersion:X2}, Security: {sessionState.SecurityLevel})";

        // Extract the original command structure by reversing the security processing
        var reversalResult = ReverseCommandSecurity(commandBytes, sessionState);
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
                    return Result.Failure<(byte[], SecureChannelState), SmartCardError>(
                        macVerifyResult.Error
                    );
                }

                return DecryptCommandDataIfRequired(parsedCommand, sessionState)
                    .Bind(dataResult =>
                    {
                        (byte[] originalData, uint newEncryptionCounter) = dataResult;

                        return ApduBuilder
                            .CreateCommand(
                                originalCla,
                                parsedCommand.Ins,
                                parsedCommand.P1,
                                parsedCommand.P2,
                                Maybe<byte[]>.From(originalData),
                                parsedCommand.Le.HasValue
                                    ? Maybe<int>.From(parsedCommand.Le.Value)
                                    : Maybe<int>.None
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
            sessionState.SecurityLevel.HasCMac() && parsedCommand.Mac.Length > 0
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
        var currentChaining = sessionState.MacChaining;
        return
            sessionState.SecurityLevel.HasCMac() && parsedCommand.Mac.Length > 0
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
        byte[] macInput = Utils.BuildMacInput(parsedCommand, sessionState.ProtocolVersion);

        // Calculate expected MAC using CryptoService
        var commandMacChainingBytes = sessionState.MacChainingValue;

        var expectedMacResult =
            sessionState.ProtocolVersion == ScpVersion.Scp03
                ? CryptoService.ScpOperations.Scp03.CalculateCommandMac(
                    macInput,
                    sessionState.SessionKeys.SMac,
                    commandMacChainingBytes
                )
                : CryptoService.ScpOperations.Scp02.CalculateCommandMac(
                    macInput,
                    sessionState.SessionKeys.SMac,
                    commandMacChainingBytes
                );

        return expectedMacResult.Map(expectedMac =>
        {
            var expectedToCompare =
                sessionState.ProtocolVersion == ScpVersion.Scp03
                    ? expectedMac[..Scp.Scp03.MAC_SIZE]
                    : expectedMac;

            // Verify MAC matches using constant-time comparison
            bool isValid = Utils.CompareBytes(expectedToCompare, parsedCommand.Mac);
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
        return CryptoService
            .Keys.GenerateCommandIcv(
                sessionState.SessionKeys.SEnc,
                sessionState.EncryptionCounter,
                ScpVersion.Scp03
            )
            .Bind(icv => Cipher.DecryptAesCbc(sessionState.SessionKeys.SEnc, icv, encryptedData))
            .Bind(decryptedData => Utils.RemovePkcs7Padding(decryptedData));
    }

    private Result<byte[], SmartCardError> DecryptScp02CommandData(
        byte[] encryptedData,
        SecureChannelState sessionState
    )
    {
        byte[] zeroIv = new byte[8];
        return Cipher
            .Decrypt3DesCbc(sessionState.SessionKeys.SEnc, zeroIv, encryptedData)
            .Bind(decryptedData => Utils.RemoveIso7816Padding(decryptedData));
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
        return securityLevel == SecurityLevel.None
            ? UnitResult.Success<SmartCardError>()
            : ValidateKeyLengths(sessionKeys);
    }

    /// <summary>
    /// Validates that session keys have appropriate lengths for cryptographic operations.
    /// </summary>
    private static UnitResult<SmartCardError> ValidateKeyLengths(SessionKeys sessionKeys)
    {
        // SCP02 uses 3DES (16 bytes), SCP03 uses AES (16 bytes minimum)
        const int minKeyLength = 16;

        return
            sessionKeys.SEnc?.Length >= minKeyLength
            && sessionKeys.SMac?.Length >= minKeyLength
            && sessionKeys.SrMac?.Length >= minKeyLength
            ? UnitResult.Success<SmartCardError>()
            : UnitResult.Failure(
                SmartCardError.InvalidArgument(
                    $"Invalid session keys: keys must be at least {minKeyLength} bytes for cryptographic operations"
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
                        (var decryptedExchanges, var currentState) = accum;
                        return DecryptExchange(exchange, currentState)
                            .Match(
                                success =>
                                {
                                    (var decryptedExchange, var updatedState) = success;
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
                                    var failedExchange = new DecryptedExchange(
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
        var plainApdu = new DecryptedApdu(
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
        // Check if security is actually established
        if (sessionState.SecurityLevel == SecurityLevel.None)
        {
            string metadata =
                $"Secure {direction.ToString().ToLower()} received but decryption failed: no security established";
            var failedApdu = new DecryptedApdu(
                apduBytes,
                direction,
                DecryptionStatus.Failed,
                metadata
            );
            return Result.Success<(DecryptedApdu, SecureChannelState), SmartCardError>(
                (failedApdu, sessionState)
            );
        }

        // Use ScpService to remove security (verify MAC and decrypt)
        // Convert byte array to WSCT types
        var decryptionResult =
            direction == ApduDirection.Command
                ? apduBytes
                    .ParseCommandApdu()
                    .Bind(cmd => ScpService.Security.RemoveCommandSecurity(cmd, sessionState))
                    .Map(result => (result.plaintextCommand.BinaryCommand, result.newState))
                : apduBytes
                    .ParseResponseApdu()
                    .Bind(resp => ScpService.Security.RemoveResponseSecurity(resp, sessionState))
                    .Map(result =>
                        (result.plaintextResponse.CombineResponseBytes(), result.newState)
                    );

        return decryptionResult.Match(
            success =>
            {
                (byte[] plaintextBytes, var newState) = success;
                string metadata =
                    direction == ApduDirection.Command
                        ? "Command MAC verified and decrypted"
                        : "Response MAC verified and decrypted";
                var decryptedApdu = new DecryptedApdu(
                    apduBytes, // original bytes
                    direction,
                    DecryptionStatus.Decrypted,
                    metadata,
                    Maybe<byte[]>.From(plaintextBytes) // actual plaintext bytes
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
                var failedApdu = new DecryptedApdu(
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
        // Determine MAC size based on protocol version
        int macSize =
            sessionState.ProtocolVersion == ScpVersion.Scp03
                ? Scp.Scp03.MAC_SIZE
                : Scp.Scp02.MAC_SIZE;

        // Response must have at least MAC + status word (2 bytes)
        if (responseBytes.Length < macSize + 2)
        {
            return SmartCardError.InvalidData("Response too short to contain MAC and status word");
        }

        // Extract components: [data][MAC][SW1][SW2]
        int dataLength = responseBytes.Length - macSize - 2;
        byte[] responseData = dataLength > 0 ? responseBytes[..dataLength] : [];
        byte[] receivedMac = responseBytes[dataLength..(dataLength + macSize)];
        byte[] statusWord = responseBytes[^2..];

        // Construct MAC input: data + status word (MAC is computed over data and SW)
        byte[] macInput = responseData.Concat(statusWord).ToArray();

        // Add chaining value for SCP02 if using ICV
        if (sessionState.ProtocolVersion == ScpVersion.Scp02)
        {
            var chainingBytes = sessionState.MacChaining.Value.ToArray();
            if (chainingBytes.Length > 0)
            {
                macInput = chainingBytes.Concat(macInput).ToArray();
            }
        }

        // Calculate expected MAC based on protocol version using CryptoService
        var macChainingBytes = sessionState.MacChainingValue;

        var macResult = sessionState.ProtocolVersion switch
        {
            ScpVersion.Scp02
                => CryptoService.ScpOperations.Scp02.CalculateResponseMac(
                    responseData.Concat(statusWord).ToArray(),
                    sessionState.SessionKeys.SrMac,
                    macChainingBytes
                ),
            ScpVersion.Scp03
                => CryptoService.ScpOperations.Scp03.CalculateResponseMac(
                    responseData.Concat(statusWord).ToArray(),
                    sessionState.SessionKeys.SrMac,
                    macChainingBytes
                ),
            _
                => Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument(
                        $"Unsupported protocol version: {sessionState.ProtocolVersion}"
                    )
                ),
        };

        return macResult.Bind(expectedMac =>
        {
            // Verify MAC matches
            var expectedToCompare =
                sessionState.ProtocolVersion == ScpVersion.Scp03
                    ? expectedMac[..Scp.Scp03.MAC_SIZE]
                    : expectedMac[..macSize];

            bool macValid = expectedToCompare.SequenceEqual(receivedMac);

            if (!macValid)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.SecurityStatusNotSatisfied(
                        "Response MAC verification failed: computed MAC does not match received MAC"
                    )
                );
            }

            // Return response without MAC (data + status word)
            byte[] verifiedResponse = responseData.Concat(statusWord).ToArray();
            return Result.Success<byte[], SmartCardError>(verifiedResponse);
        });
    }

    /// <summary>
    /// Decrypts response data using functional cryptographic operations.
    /// </summary>
    private static Result<(byte[], SecureChannelState), SmartCardError> DecryptResponseData(
        byte[] responseBytes,
        SecureChannelState sessionState
    )
    {
        // Response must have at least status word (2 bytes)
        if (responseBytes.Length < 2)
        {
            return Result.Failure<(byte[], SecureChannelState), SmartCardError>(
                SmartCardError.InvalidData("Response too short to decrypt")
            );
        }

        // Check if there's data to decrypt (more than just SW1/SW2)
        if (responseBytes.Length == 2)
        {
            // No data to decrypt, just status word
            return Result.Success<(byte[], SecureChannelState), SmartCardError>(
                (responseBytes, sessionState)
            );
        }

        // Extract data and status word
        byte[] encryptedData = responseBytes[..^2];
        byte[] statusWord = responseBytes[^2..];

        // Decrypt based on protocol version
        var decryptResult = sessionState.ProtocolVersion switch
        {
            ScpVersion.Scp02 => DecryptScp02Response(encryptedData, sessionState),
            ScpVersion.Scp03 => DecryptScp03Response(encryptedData, sessionState),
            _
                => Result.Failure<byte[], SmartCardError>(
                    new UnsupportedProtocolError(
                        $"Unsupported protocol version for decryption: {sessionState.ProtocolVersion}"
                    )
                ),
        };

        return decryptResult.Map(decryptedData =>
        {
            // Reconstruct response with decrypted data + status word
            byte[] decryptedResponse = decryptedData.Concat(statusWord).ToArray();

            // Update state for SCP03 (increment encryption counter)
            var newState =
                sessionState.ProtocolVersion == ScpVersion.Scp03
                    ? sessionState.IncrementEncryptionCounter()
                    : sessionState;

            return (decryptedResponse, newState);
        });
    }

    /// <summary>
    /// Decrypts SCP02 response data using 3DES-CBC with zero IV.
    /// </summary>
    private static Result<byte[], SmartCardError> DecryptScp02Response(
        byte[] encryptedData,
        SecureChannelState sessionState
    )
    {
        // SCP02 uses 3DES-CBC with zero IV for response decryption
        byte[] zeroIv = new byte[Scp.Scp02.BLOCK_SIZE]; // 8 bytes of zeros

        return Cipher.Decrypt3DesCbcWithPadding(
            sessionState.SessionKeys.SEnc,
            zeroIv,
            encryptedData
        );
    }

    /// <summary>
    /// Decrypts SCP03 response data using AES-CBC with derived IV.
    /// </summary>
    private static Result<byte[], SmartCardError> DecryptScp03Response(
        byte[] encryptedData,
        SecureChannelState sessionState
    )
    {
        // SCP03 derives IV from encryption counter
        // IV = encryption counter (4 bytes) || 12 zero bytes
        byte[] iv = new byte[Scp.Scp03.BLOCK_SIZE]; // 16 bytes

        // Convert counter to big-endian bytes
        byte[] counterBytes = BitConverter.GetBytes(sessionState.EncryptionCounter);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(counterBytes);
        }

        // Copy counter to beginning of IV
        Array.Copy(counterBytes, 0, iv, 0, 4);

        return Cipher.DecryptAesCbcWithPadding(sessionState.SessionKeys.SEnc, iv, encryptedData);
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
                ApduDirection.Response
                    => apduBytes.Length > 2
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
    string Metadata,
    Maybe<byte[]> DecryptedBytesOverride = default
)
{
    /// <summary>
    /// Gets the decrypted APDU bytes. Returns actual decrypted data when available.
    /// For failed decryption, returns empty array to prevent leaking encrypted data.
    /// </summary>
    public byte[] DecryptedBytes =>
        Status switch
        {
            DecryptionStatus.Failed => Array.Empty<byte>(), // Never expose failed encrypted data
            _ => DecryptedBytesOverride.GetValueOrDefault(OriginalBytes),
        };

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

internal static class TraceApduDecryptorServiceExtensions
{
    internal static Result<CommandAPDU, SmartCardError> ParseCommandApdu(this byte[] bytes)
    {
        return Gp4Net.Core.Functional.ResultExtensions.Try(
            () => new CommandAPDU(bytes),
            ex => SmartCardError.InvalidData($"Failed to parse command APDU: {ex.Message}")
        );
    }

    internal static Result<ResponseAPDU, SmartCardError> ParseResponseApdu(this byte[] bytes)
    {
        return Gp4Net.Core.Functional.ResultExtensions.Try(
            () => new ResponseAPDU(bytes),
            ex => SmartCardError.InvalidData($"Failed to parse response APDU: {ex.Message}")
        );
    }

    internal static byte[] CombineResponseBytes(this ResponseAPDU response)
    {
        var udr = response.Udr ?? [];
        var result = new byte[udr.Length + 2];
        if (udr.Length > 0)
            Array.Copy(udr, 0, result, 0, udr.Length);
        result[^2] = response.Sw1;
        result[^1] = response.Sw2;
        return result;
    }
}
