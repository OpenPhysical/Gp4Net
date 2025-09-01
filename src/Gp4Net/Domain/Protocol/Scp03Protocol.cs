// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using static Gp4Net.Cryptography.CryptoService;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// Pure functional SCP03 secure channel protocol implementation.
/// Per GlobalPlatform Card Specification v2.3.1 Appendix E.5 "SCP03".
/// All operations are stateless and deterministic for testing with known values.
/// Uses UnifiedCryptoService for all cryptographic operations.
/// </summary>
[PublicAPI]
public static class Scp03Protocol
{
    /// <summary>
    /// The SCP03 protocol version constant.
    /// </summary>
    public static ScpVersion ProtocolVersion => ScpVersion.Scp03;

    /// <summary>
    /// The SCP03 block size for AES operations.
    /// </summary>
    public static int BlockSize => 16;

    /// <summary>
    /// The SCP03 MAC size.
    /// </summary>
    public static int MacSize => 8;

    /// <summary>
    /// The SCP03 chaining value size.
    /// </summary>
    public static int ChainingValueSize => 16;

    /// <summary>
    /// The SCP03 card challenge length.
    /// </summary>
    public static int CardChallengeLength => 8;

    /// <summary>
    /// Validates if the implementation parameter is valid for SCP03.
    /// </summary>
    public static bool IsValidImplementation(byte implementation)
    {
        return implementation == 0x00
            || // No R-MAC, no R-ENC
            implementation == 0x10
            || // R-MAC
            implementation == 0x20
            || // R-ENC
            implementation == 0x60
            || // R-MAC and R-ENC with random card challenge
            implementation == 0x70; // R-MAC and R-ENC with pseudo-random card challenge
    }

    /// <summary>
    /// Creates an INITIALIZE UPDATE command for SCP03.
    /// Per GP Card Spec v2.3.1 Section E.5.1.
    /// </summary>
    public static Result<InitializeUpdateCommand, SmartCardError> CreateInitializeUpdateCommand(
        byte keyVersion,
        byte[] hostChallenge
    )
    {
        // For SCP03, key identifier must be 0x00
        return InitializeUpdateCommand.Create(keyVersion, 0x00, hostChallenge);
    }

    /// <summary>
    /// Derives SCP03 session keys from key set and challenges.
    /// Per GP Card Spec v2.3.1 Section E.5.2.
    /// </summary>
    public static Result<SessionKeys, SmartCardError> DeriveSessionKeys(
        IKeySet keySet,
        byte[] hostChallenge,
        byte[] cardChallenge,
        byte implementationParameter = 0x70
    )
    {
        // Create key derivation context using the centralized approach
        return KeyDerivationContext
            .CreateForScp03(
                keySet,
                hostChallenge,
                cardChallenge,
                Maybe<ScpImplementation>.From(GetScpImplementation(implementationParameter))
            )
            .Bind(CryptoService.KeyDerivation.DeriveSessionKeys);
    }

    /// <summary>
    /// Creates an EXTERNAL AUTHENTICATE command with MAC for SCP03.
    /// Per GP Card Spec v2.3.1 Section E.5.3.
    /// </summary>
    public static Result<
        ExternalAuthenticateCommand,
        SmartCardError
    > CreateExternalAuthenticateCommand(
        SecurityLevel securityLevel,
        byte[] hostCryptogram,
        byte[] macKey
    )
    {
        return ExternalAuthenticateCommand
            .CreateWithoutMac(securityLevel, hostCryptogram)
            .Bind(command =>
            {
                byte[] apdu = BuildCommandApdu(command);
                byte[] zeroChaining = new byte[16]; // Zero chaining value for EXTERNAL AUTHENTICATE

                // SCP03 C-MAC per GP SCP03 v1.1.1 Section 6.2.4:
                byte[] macInput = new byte[zeroChaining.Length + apdu.Length];
                Array.Copy(zeroChaining, 0, macInput, 0, zeroChaining.Length);
                Array.Copy(apdu, 0, macInput, zeroChaining.Length, apdu.Length);

                return CryptoService.Mac
                    .CalculateScp03CommandMac(macKey, macInput)
                    .Map(mac => mac.Take(MacSize).ToArray()) // Truncate to 8 bytes
                    .Bind(truncatedMac =>
                        ExternalAuthenticateCommand.CreateWithMac(
                            securityLevel,
                            hostCryptogram,
                            truncatedMac
                        )
                    );
            });

        static byte[] BuildCommandApdu(ExternalAuthenticateCommand command)
        {
            byte[] apdu = new byte[5 + command.HostCryptogram.Length];
            apdu[0] = 0x84; // CLA with secure messaging
            apdu[1] = command.Ins;
            apdu[2] = command.P1;
            apdu[3] = command.P2;
            apdu[4] = 0x10; // Lc = 16 bytes (8 cryptogram + 8 MAC)
            Array.Copy(command.HostCryptogram, 0, apdu, 5, command.HostCryptogram.Length);
            return apdu;
        }
    }

    /// <summary>
    /// Maps SCP03 implementation parameter to ScpImplementation enum.
    /// </summary>
    public static ScpImplementation GetScpImplementation(byte implementationParameter)
    {
        return implementationParameter switch
        {
            0x70 => ScpImplementation.Scp03I70,
            0x60 => ScpImplementation.Scp03I60,
            0x11 => ScpImplementation.Scp03I11,
            _ => ScpImplementation.Scp03I70,
        };
    }

    // High-Level Protocol Operations for SecureChannelService Integration

    /// <summary>
    /// Processes an INITIALIZE UPDATE response for SCP03 and creates a secure channel context.
    /// </summary>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <param name="hostChallenge">The host challenge that was sent.</param>
    /// <param name="keySet">The key set to use for session key derivation.</param>
    /// <returns>A secure channel context for further protocol operations or error.</returns>
    public static Result<SecureChannelContext, SmartCardError> ProcessInitializeUpdateResponse(
        InitializeUpdateResponse response,
        byte[] hostChallenge,
        IKeySet keySet
    )
    {
        // Validate protocol version
        if (response.ScpId != ProtocolVersion)
        {
            return SmartCardError.InvalidResponse(
                $"Expected SCP03 but received {response.ScpId:X2}"
            );
        }

        // Validate key set type
        if (keySet is not Scp03KeySet scp03KeySet)
        {
            return SmartCardError.InvalidArgument("SCP03 requires Scp03KeySet");
        }

        // For SCP03, derive session keys and verify card cryptogram
        return DeriveSessionKeys(
                scp03KeySet,
                hostChallenge,
                response.CardChallenge,
                response.ImplementationParameter
            )
            .Bind(sessionKeys =>
            {
                // Verify card cryptogram using SCP03-specific logic
                Result<byte[], SmartCardError> cardCryptogramData =
                    CryptoService.Cryptogram.BuildScp03CardCryptogramData(response, hostChallenge);
                return cardCryptogramData
                    .Bind(cryptogramData =>
                        CryptoService.Cryptogram.CalculateScp03Cryptogram(sessionKeys.SEnc, cryptogramData)
                    )
                    .Bind(calculatedCryptogram =>
                    {
                        // SCP03 uses full 16-byte cryptogram comparison (first 8 bytes are used in response)
                        byte[] expectedCryptogram = [.. calculatedCryptogram.Take(8)];
                        if (
                            !CryptoService.Utils.CompareBytes(
                                expectedCryptogram,
                                response.CardCryptogram
                            )
                        )
                        {
                            return SmartCardError.AuthenticationFailed(
                                "Card cryptogram verification failed"
                            );
                        }

                        return SecureChannelContext.Create(
                            hostChallenge,
                            response,
                            sessionKeys,
                            ProtocolVersion,
                            keySet
                        );
                    });
            });
    }

    /// <summary>
    /// Creates a secure channel session from the established SCP03 context.
    /// </summary>
    /// <param name="context">The secure channel context.</param>
    /// <param name="securityLevel">The established security level.</param>
    /// <returns>The secure channel session state or error.</returns>
    public static Result<SecureChannelState, SmartCardError> CreateSecureChannelSession(
        SecureChannelContext context,
        SecurityLevel securityLevel
    )
    {
        // For SCP03, calculate initial MAC chaining value from EXTERNAL AUTHENTICATE command
        return CryptoService.Cryptogram
            .BuildScp03HostCryptogramData(context.InitializeUpdateResponse, context.HostChallenge)
            .Bind(hostCryptogramData =>
                CryptoService.Cryptogram.CalculateScp03Cryptogram(
                    context.SessionKeys.SEnc,
                    hostCryptogramData
                )
            )
            .Bind(hostCryptogram =>
            {
                // Create the EXTERNAL AUTHENTICATE command to calculate initial chaining
                byte[] truncatedCryptogram = [.. hostCryptogram.Take(8)];
                byte[] commandData = CryptoService.Utils.ConcatenateArrays(
                    truncatedCryptogram,
                    [(byte)securityLevel]
                );

                return ExternalAuthenticateCommand
                    .Create(commandData)
                    .Bind(command =>
                    {
                        // Calculate initial MAC chaining value using SCP03 logic
                        byte[] macData = CryptoService.Utils.ConcatenateArrays(
                            [command.Cla, command.Ins, command.P1, command.P2, command.Lc],
                            command.Data
                        );

                        return CryptoService.Mac
                            .CalculateScp03FullMac(context.SessionKeys.SMac, macData)
                            .Bind(initialChaining =>
                                // Create the secure channel state
                                SecureChannelState.Create(
                                    context.SessionKeys,
                                    securityLevel,
                                    ProtocolVersion,
                                    initialChaining, // SCP03 uses full 16-byte MAC as chaining value
                                    context.InitializeUpdateResponse.ImplementationParameter
                                )
                            );
                    });
            });
    }
}
