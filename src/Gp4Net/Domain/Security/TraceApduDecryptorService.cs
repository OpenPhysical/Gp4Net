using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
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
    /// <param name="protocolVersion">The secure channel protocol version (0x02 or 0x03).</param>
    /// <returns>Decrypted trace data or an error.</returns>
    public Result<DecryptedTrace, SmartCardError> DecryptTrace(
        IEnumerable<TraceExchange> exchanges,
        SessionKeys sessionKeys,
        SecurityLevel securityLevel,
        byte protocolVersion)
    {
        try
        {
            _logger.LogDebug("Starting trace decryption for protocol SCP{Protocol:X2}, security level: {SecurityLevel}",
                protocolVersion, securityLevel);

            // Validate session keys for secure operations
            if (securityLevel != SecurityLevel.None)
            {
                if (sessionKeys.SEnc?.Length == 0 || sessionKeys.SMac?.Length == 0 || sessionKeys.SrMac?.Length == 0)
                {
                    return Result.Failure<DecryptedTrace, SmartCardError>(
                        SmartCardError.InvalidArgument("Invalid session keys: encryption and MAC keys cannot be empty when security level is not None"));
                }
            }

            // Initialize session state
            var initialStateResult = CreateInitialSessionState(sessionKeys, securityLevel, protocolVersion);
            if (initialStateResult.IsFailure)
            {
                return Result.Failure<DecryptedTrace, SmartCardError>(initialStateResult.Error);
            }

            var sessionState = initialStateResult.Value;
            var decryptedExchanges = new List<DecryptedExchange>();

            foreach (var exchange in exchanges)
            {
                var decryptedExchangeResult = DecryptExchange(exchange, sessionState);
                if (decryptedExchangeResult.IsFailure)
                {
                    _logger.LogWarning("Failed to decrypt exchange {ExchangeId}: {Error}",
                        exchange.Id, decryptedExchangeResult.Error.Message);
                    
                    // For graceful degradation, include failed exchange with original data
                    decryptedExchanges.Add(new DecryptedExchange(
                        exchange.Id,
                        new DecryptedApdu(exchange.Command, ApduDirection.Command, DecryptionStatus.Failed, decryptedExchangeResult.Error.Message),
                        new DecryptedApdu(exchange.Response, ApduDirection.Response, DecryptionStatus.Failed, decryptedExchangeResult.Error.Message),
                        sessionState));
                    continue;
                }

                var (decryptedExchange, updatedState) = decryptedExchangeResult.Value;
                decryptedExchanges.Add(decryptedExchange);
                sessionState = updatedState;
            }

            var decryptedTrace = new DecryptedTrace(
                decryptedExchanges,
                sessionKeys,
                securityLevel,
                protocolVersion);

            _logger.LogDebug("Successfully decrypted {ExchangeCount} exchanges", decryptedExchanges.Count);
            return Result.Success<DecryptedTrace, SmartCardError>(decryptedTrace);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Trace decryption failed");
            return Result.Failure<DecryptedTrace, SmartCardError>(
                SmartCardError.CryptographicError($"Trace decryption failed: {ex.Message}"));
        }
    }

    /// <summary>
    /// Decrypts a single APDU using the current session state.
    /// Updates session state appropriately for chaining and counters.
    /// </summary>
    /// <param name="apduBytes">The APDU bytes to decrypt.</param>
    /// <param name="direction">Whether this is a command or response APDU.</param>
    /// <param name="sessionState">The current session state.</param>
    /// <returns>Decrypted APDU and updated session state, or an error.</returns>
    public Result<(DecryptedApdu decryptedApdu, SecureChannelState updatedState), SmartCardError> DecryptApdu(
        byte[] apduBytes,
        ApduDirection direction,
        SecureChannelState sessionState)
    {
        try
        {
            if (!IsSecureMessaging(apduBytes, direction))
            {
                // No secure messaging - return original APDU
                var plainApdu = new DecryptedApdu(apduBytes, direction, DecryptionStatus.PlainText, "No secure messaging detected");
                return Result.Success<(DecryptedApdu, SecureChannelState), SmartCardError>((plainApdu, sessionState));
            }

            var decryptionResult = direction == ApduDirection.Command
                ? DecryptCommand(apduBytes, sessionState)
                : DecryptResponse(apduBytes, sessionState);

            if (decryptionResult.IsSuccess)
            {
                var (decryptedBytes, newState, metadata) = decryptionResult.Value;
                var decryptedApdu = new DecryptedApdu(decryptedBytes, direction, DecryptionStatus.Decrypted, metadata);
                return Result.Success<(DecryptedApdu, SecureChannelState), SmartCardError>((decryptedApdu, newState));
            }
            else
            {
                // Decryption failed, but we detected secure messaging - return failed status
                var protocolStr = sessionState.ProtocolVersion == ProtocolIdentifiers.Scp03 ? "SCP03" : "SCP02";
                var metadata = $"Secure messaging detected ({protocolStr}) but decryption failed: {decryptionResult.Error.Message}";
                var failedApdu = new DecryptedApdu(apduBytes, direction, DecryptionStatus.Failed, metadata);
                return Result.Success<(DecryptedApdu, SecureChannelState), SmartCardError>((failedApdu, sessionState));
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "APDU decryption failed for {Direction}", direction);
            var errorApdu = new DecryptedApdu(apduBytes, direction, DecryptionStatus.Failed, ex.Message);
            return Result.Success<(DecryptedApdu, SecureChannelState), SmartCardError>((errorApdu, sessionState));
        }
    }

    private Result<(DecryptedExchange exchange, SecureChannelState updatedState), SmartCardError> DecryptExchange(
        TraceExchange exchange,
        SecureChannelState sessionState)
    {
        // Decrypt command first
        return DecryptApdu(exchange.Command, ApduDirection.Command, sessionState)
            .Bind(commandResult =>
            {
                var (decryptedCommand, stateAfterCommand) = commandResult;

                // Decrypt response using updated state
                return DecryptApdu(exchange.Response, ApduDirection.Response, stateAfterCommand)
                    .Map(responseResult =>
                    {
                        var (decryptedResponse, finalState) = responseResult;
                        var decryptedExchange = new DecryptedExchange(
                            exchange.Id,
                            decryptedCommand,
                            decryptedResponse,
                            finalState);
                        return (decryptedExchange, finalState);
                    });
            });
    }

    private Result<(byte[] decryptedBytes, SecureChannelState newState, string metadata), SmartCardError> DecryptCommand(
        byte[] commandBytes,
        SecureChannelState sessionState)
    {
        // Use CommandSecurityProcessor in reverse - we need to decrypt/verify instead of encrypt/MAC
        // For now, return original command with metadata about secure messaging
        var metadata = $"Command secure messaging detected (SCP{sessionState.ProtocolVersion:X2}, Security: {sessionState.SecurityLevel})";
        
        // Extract the original command structure by reversing the security processing
        var reversalResult = ReverseCommandSecurity(commandBytes, sessionState);
        return reversalResult.Map(result => (result.originalCommand, result.newState, metadata));
    }

    private Result<(byte[] decryptedBytes, SecureChannelState newState, string metadata), SmartCardError> DecryptResponse(
        byte[] responseBytes,
        SecureChannelState sessionState)
    {
        // Use HostResponseSecurityProcessor to decrypt/verify response
        var processor = new HostResponseSecurityProcessor();
        
        return processor.ApplyResponseSecurity(
            responseBytes,
            sessionState.SecurityLevel,
            sessionState.SessionKeys,
            sessionState.MacChaining.Value,
            sessionState.EncryptionCounter,
            sessionState.ProtocolVersion)
            .Map(result =>
            {
                var (processedResponse, newState) = result;
                var metadata = $"Response decrypted (SCP{sessionState.ProtocolVersion:X2}, R-MAC: {sessionState.SecurityLevel.HasRMac()}, R-ENC: {sessionState.SecurityLevel.HasREncryption()})";
                return (processedResponse, newState, metadata);
            });
    }

    private Result<(byte[] originalCommand, SecureChannelState newState), SmartCardError> ReverseCommandSecurity(
        byte[] securedCommand,
        SecureChannelState sessionState)
    {
        try
        {
            // Check if command has secure messaging indicator in CLA byte
            if (securedCommand.Length < 4 || (securedCommand[0] & 0x04) == 0)
            {
                // No secure messaging - return as-is
                return Result.Success<(byte[], SecureChannelState), SmartCardError>((securedCommand, sessionState));
            }

            // Parse the secured command structure
            var parseResult = ApduParser.ParseSecuredCommand(securedCommand);
            if (parseResult.IsFailure)
            {
                return Result.Failure<(byte[], SecureChannelState), SmartCardError>(parseResult.Error);
            }

            var parsedCommand = parseResult.Value;
            
            // Remove secure messaging indicator from CLA byte
            var originalCla = (byte)(parsedCommand.Cla & ~0x04);
            
            // Verify C-MAC if present
            if (sessionState.SecurityLevel.HasCMac() && parsedCommand.Mac != null)
            {
                var macVerificationResult = VerifyCommandMac(parsedCommand, sessionState);
                if (macVerificationResult.IsFailure)
                {
                    return Result.Failure<(byte[], SecureChannelState), SmartCardError>(macVerificationResult.Error);
                }
            }

            // Decrypt data if present
            byte[] originalData = parsedCommand.Data;
            var newEncryptionCounter = sessionState.EncryptionCounter;
            
            if (sessionState.SecurityLevel.HasCDecryption() && parsedCommand.Data.Length > 0)
            {
                var decryptionResult = DecryptCommandData(parsedCommand.Data, sessionState);
                if (decryptionResult.IsFailure)
                {
                    return Result.Failure<(byte[], SecureChannelState), SmartCardError>(decryptionResult.Error);
                }

                originalData = decryptionResult.Value;
                newEncryptionCounter = sessionState.ProtocolVersion == ProtocolIdentifiers.Scp03 
                    ? sessionState.EncryptionCounter + 1 
                    : sessionState.EncryptionCounter;
            }

            // Reconstruct original command
            var originalCommand = ApduParser.BuildOriginalCommand(originalCla, parsedCommand.Ins, parsedCommand.P1, parsedCommand.P2, originalData, parsedCommand.Le);

            // Update session state with new counter and MAC chaining
            var newMacChaining = sessionState.MacChaining.Value;
            if (sessionState.SecurityLevel.HasCMac() && parsedCommand.Mac != null)
            {
                // Update MAC chaining value based on protocol
                newMacChaining = UpdateMacChaining(newMacChaining, parsedCommand.Mac, sessionState.ProtocolVersion);
            }

            var newStateResult = UpdateSessionState(sessionState, newEncryptionCounter, newMacChaining);
            if (newStateResult.IsFailure)
            {
                return Result.Failure<(byte[], SecureChannelState), SmartCardError>(newStateResult.Error);
            }

            return Result.Success<(byte[], SecureChannelState), SmartCardError>((originalCommand, newStateResult.Value));
        }
        catch (Exception ex)
        {
            return Result.Failure<(byte[], SecureChannelState), SmartCardError>(
                SmartCardError.CryptographicError($"Command security reversal failed: {ex.Message}"));
        }
    }


    private Result<bool, SmartCardError> VerifyCommandMac(ParsedSecuredCommand parsedCommand, SecureChannelState sessionState)
    {
        if (parsedCommand.Mac == null)
        {
            return Result.Success<bool, SmartCardError>(true); // No MAC to verify
        }

        // Reconstruct the command data that was used for MAC calculation
        var macInput = ApduParser.BuildMacInput(parsedCommand, sessionState.ProtocolVersion);
        
        // Calculate expected MAC using existing logic
        var macService = new MacService();
        var protocol = sessionState.ProtocolVersion == ProtocolIdentifiers.Scp03 
            ? ScpVersion.Scp03 
            : ScpVersion.Scp02;

        return macService.VerifyMac(
            sessionState.SessionKeys.SMac,
            macInput,
            parsedCommand.Mac,
            protocol);
    }

    private Result<byte[], SmartCardError> DecryptCommandData(byte[] encryptedData, SecureChannelState sessionState)
    {
        if (sessionState.ProtocolVersion == ProtocolIdentifiers.Scp03)
        {
            return DecryptScp03CommandData(encryptedData, sessionState);
        }
        else
        {
            return DecryptScp02CommandData(encryptedData, sessionState);
        }
    }

    private Result<byte[], SmartCardError> DecryptScp03CommandData(byte[] encryptedData, SecureChannelState sessionState)
    {
        return CryptographicOperations.GenerateCommandIcv(sessionState.SessionKeys.SEnc, sessionState.EncryptionCounter, ProtocolIdentifiers.Scp03)
            .Bind(icv => CryptographicOperations.DecryptAesCbc(sessionState.SessionKeys.SEnc, icv, encryptedData))
            .Bind(decryptedData => Protocol.CryptographicOperations.RemovePkcs7Padding(decryptedData));
    }

    private Result<byte[], SmartCardError> DecryptScp02CommandData(byte[] encryptedData, SecureChannelState sessionState)
    {
        var zeroIv = new byte[8];
        return CryptographicOperations.Decrypt3DesCbc(sessionState.SessionKeys.SEnc, zeroIv, encryptedData)
            .Bind(decryptedData => Protocol.CryptographicOperations.RemoveIso7816Padding(decryptedData));
    }


    private ImmutableArray<byte> UpdateMacChaining(ImmutableArray<byte> currentChaining, byte[] newMac, byte protocolVersion)
    {
        if (protocolVersion == ProtocolIdentifiers.Scp03)
        {
            // For SCP03, MAC chaining value is the full 16-byte CMAC
            return [..newMac];
        }
        else
        {
            // For SCP02, update first 8 bytes of chaining value
            var newChaining = currentChaining.ToArray();
            Array.Copy(newMac, 0, newChaining, 0, Math.Min(8, newMac.Length));
            return [..newChaining];
        }
    }

    private Result<SecureChannelState, SmartCardError> UpdateSessionState(
        SecureChannelState currentState,
        uint newEncryptionCounter,
        ImmutableArray<byte> newMacChaining)
    {
        return MacChainingState.Create(newMacChaining.ToArray(), currentState.ProtocolVersion, 0x00)
            .Bind(macState => currentState.UpdateCounterAndMac(newEncryptionCounter, macState));
    }

    private Result<SecureChannelState, SmartCardError> CreateInitialSessionState(
        SessionKeys sessionKeys,
        SecurityLevel securityLevel,
        byte protocolVersion)
    {
        var initialMacChaining = protocolVersion == ProtocolIdentifiers.Scp03 
            ? new byte[16] // 16-byte chaining for SCP03
            : new byte[8];  // 8-byte chaining for SCP02

        return MacChainingState.Create(initialMacChaining, protocolVersion, 0x00)
            .Bind(macState => SecureChannelState.Create(
                sessionKeys,
                securityLevel,
                protocolVersion,
                initialMacChaining,
                0x00)
                .Bind(state => state.UpdateCounterAndMac(0, macState)));
    }

    private static bool IsSecureMessaging(byte[] apduBytes, ApduDirection direction)
    {
        if (apduBytes.Length < 4)
        {
            return false;
        }

        if (direction == ApduDirection.Command)
        {
            // Check CLA byte for secure messaging indicator (bit 2)
            return (apduBytes[0] & 0x04) != 0;
        }
        else
        {
            // For responses, detect secure messaging by checking for typical SM tags
            // In secure messaging, response data often contains TLV structures with specific tags
            // For now, be conservative and only detect SM when we have clear indicators
            if (apduBytes.Length <= 2)
            {
                return false; // Only status word
            }

            // Look for common secure messaging tags in response data
            // Tag 0x87 (encrypted data), 0x8E (MAC), etc.
            // This is a simplified check - real implementation would be more sophisticated
            for (int i = 0; i < apduBytes.Length - 2; i++)
            {
                var tag = apduBytes[i];
                if (tag is 0x87 or 0x8E or 0x99)
                {
                    return true;
                }
            }
            
            return false; // No secure messaging indicators found
        }
    }


}

/// <summary>
/// Represents a trace exchange from a trace file.
/// </summary>
[PublicAPI]
public record TraceExchange(
    int Id,
    byte[] Command,
    byte[] Response);

/// <summary>
/// Represents the result of decrypting a complete trace.
/// </summary>
[PublicAPI]
public record DecryptedTrace(
    IReadOnlyList<DecryptedExchange> Exchanges,
    SessionKeys SessionKeys,
    SecurityLevel SecurityLevel,
    byte ProtocolVersion);

/// <summary>
/// Represents a decrypted exchange containing both command and response.
/// </summary>
[PublicAPI]
public record DecryptedExchange(
    int Id,
    DecryptedApdu Command,
    DecryptedApdu Response,
    SecureChannelState SessionState);

/// <summary>
/// Represents a decrypted APDU with metadata about the decryption process.
/// </summary>
[PublicAPI]
public record DecryptedApdu(
    byte[] OriginalBytes,
    ApduDirection Direction,
    DecryptionStatus Status,
    string Metadata)
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
                ? $"Response: {new StatusWord((ushort)((OriginalBytes[^2] << 8) | OriginalBytes[^1])).ToDescriptiveString()}"
                : $"{Direction} APDU ({OriginalBytes.Length} bytes)";
        }
    }
};

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
    Response
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
    Failed
}