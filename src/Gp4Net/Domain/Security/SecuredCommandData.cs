using System;
using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using WSCT.ISO7816;
using static Gp4Net.Cryptography.CryptoService;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Immutable data structure representing a secured command with MAC and optional encryption.
/// This type enforces that the command came from a valid secure channel session.
/// </summary>
/// <remarks>
/// This type can represent:
/// - MAC-only secured commands (C-MAC)
/// - MAC + Encrypted commands (C-MAC + C-ENC)
/// The presence of encryption is determined by the IsEncrypted property.
/// </remarks>
[PublicAPI]
public sealed record SecuredCommandData
{
    /// <summary>
    /// The plaintext or ciphertext data (depending on IsEncrypted).
    /// For encrypted commands, this contains the ciphertext that needs decryption.
    /// For MAC-only commands, this contains the plaintext data.
    /// </summary>
    public ImmutableArray<byte> Data { get; }

    /// <summary>
    /// The MAC extracted from the secured command (last 8 bytes of Udc).
    /// </summary>
    public ImmutableArray<byte> ExtractedMac { get; }

    /// <summary>
    /// Indicates whether the data is encrypted (C-ENC enabled).
    /// </summary>
    public bool IsEncrypted { get; }

    /// <summary>
    /// The validated session keys for MAC verification and optional decryption.
    /// </summary>
    public SessionKeys ValidatedKeys { get; }

    /// <summary>
    /// The encryption counter for SCP03 (used in counter mode).
    /// </summary>
    public uint EncryptionCounter { get; }

    /// <summary>
    /// The protocol version (SCP02 or SCP03).
    /// </summary>
    public ScpVersion ProtocolVersion { get; }

    /// <summary>
    /// Private constructor ensures validation through factory method.
    /// </summary>
    private SecuredCommandData(
        ImmutableArray<byte> data,
        ImmutableArray<byte> extractedMac,
        bool isEncrypted,
        SessionKeys keys,
        uint encryptionCounter,
        ScpVersion protocolVersion
    )
    {
        Data = data;
        ExtractedMac = extractedMac;
        IsEncrypted = isEncrypted;
        ValidatedKeys = keys;
        EncryptionCounter = encryptionCounter;
        ProtocolVersion = protocolVersion;
    }

    /// <summary>
    /// Extracts secured command data from a CommandAPDU with a valid session.
    /// </summary>
    /// <param name="command">The secured command APDU.</param>
    /// <param name="validSession">A valid secure channel session.</param>
    /// <returns>Success with SecuredCommandData if the command is secured, failure otherwise.</returns>
    public static Result<SecuredCommandData, SmartCardError> Extract(
        CommandAPDU command,
        SecureChannelState validSession
    )
    {
        return Maybe<CommandAPDU>
            .From(command)
            .ToResult(SmartCardError.InvalidArgument("Command cannot be null"))
            .Bind(cmd =>
                Maybe<SecureChannelState>
                    .From(validSession)
                    .ToResult(SmartCardError.InvalidArgument("Session state cannot be null"))
            )
            .Bind(session =>
            {
                // Check if command is secured (bit 2 of CLA set)
                var isSecured = (command.Cla & 0x04) != 0;
                if (!isSecured)
                {
                    return Result.Failure<SecureChannelState, SmartCardError>(
                        SmartCardError.SecurityError("Command is not secured")
                    );
                }

                // Session must have at least C-MAC
                if (!session.SecurityLevel.HasCMac())
                {
                    return Result.Failure<SecureChannelState, SmartCardError>(
                        SmartCardError.SecurityError("Session does not have C-MAC enabled")
                    );
                }

                return Result.Success<SecureChannelState, SmartCardError>(session);
            })
            .Bind(session => ExtractSecuredComponents(command, session))
            .Map(components => new SecuredCommandData(
                [.. components.data],
                [.. components.mac],
                validSession.SecurityLevel.HasCEncryption(),
                validSession.SessionKeys,
                validSession.EncryptionCounter,
                validSession.ProtocolVersion
            ));
    }

    /// <summary>
    /// Extracts MAC and data from a secured command.
    /// </summary>
    private static Result<(byte[] data, byte[] mac), SmartCardError> ExtractSecuredComponents(
        CommandAPDU command,
        SecureChannelState session
    )
    {
        var udc = command.Udc ?? [];
        var macSize = 8; // Both SCP02 and SCP03 use 8-byte MACs

        if (udc.Length < macSize)
        {
            return Result.Failure<(byte[], byte[]), SmartCardError>(
                SmartCardError.InvalidData($"Secured command data too short: {udc.Length} bytes")
            );
        }

        // MAC is the last 'macSize' bytes of Udc
        var extractedMac = new byte[macSize];
        Array.Copy(udc, udc.Length - macSize, extractedMac, 0, macSize);

        // Data is Udc without the MAC
        var data = new byte[udc.Length - macSize];
        if (data.Length > 0)
        {
            Array.Copy(udc, 0, data, 0, data.Length);
        }

        return Result.Success<(byte[], byte[]), SmartCardError>((data, extractedMac));
    }

    /// <summary>
    /// Creates secured command data for building a new secured command.
    /// </summary>
    /// <param name="plaintextData">The plaintext data to secure.</param>
    /// <param name="mac">The calculated MAC.</param>
    /// <param name="validSession">A valid secure channel session.</param>
    /// <returns>Success with SecuredCommandData for the new secured command.</returns>
    public static Result<SecuredCommandData, SmartCardError> CreateForBuilding(
        byte[] plaintextData,
        byte[] mac,
        SecureChannelState validSession
    )
    {
        return Maybe<byte[]>
            .From(mac)
            .Where(m => m.Length == 8)
            .ToResult(SmartCardError.InvalidArgument("MAC must be 8 bytes"))
            .Bind(_ =>
                Maybe<SecureChannelState>
                    .From(validSession)
                    .ToResult(SmartCardError.InvalidArgument("Session state cannot be null"))
            )
            .Bind(session =>
                session.SecurityLevel.HasCMac()
                    ? Result.Success<SecureChannelState, SmartCardError>(session)
                    : Result.Failure<SecureChannelState, SmartCardError>(
                        SmartCardError.SecurityError("C-MAC not enabled in session")
                    )
            )
            .Map(session =>
            {
                var data = plaintextData ?? [];

                return new SecuredCommandData(
                    [.. data],
                    [.. mac],
                    session.SecurityLevel.HasCEncryption(),
                    session.SessionKeys,
                    session.EncryptionCounter,
                    session.ProtocolVersion
                );
            });
    }
}
