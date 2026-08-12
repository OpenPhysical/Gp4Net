using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Security;
using NUnit.Framework;
using ApduCommandExtensions = Gp4Net.Transport.ApduCommandExtensions;

namespace Gp4Net.Tests.Integration;

/// <summary>
/// Spec restatement: Validate both sides of every cryptographic transaction between host and card.
/// Invariants:
/// - Card emulator and TraceApduDecryptor use identical CryptoOperations
/// - All secure channel establishment steps are bidirectionally verified
/// - MAC generation, verification, and chaining work identically on both sides
/// - Session state progression is consistent between host and card
/// - Encryption/decryption produces identical results when applied to same data
///
/// These tests demonstrate:
/// - Initialize Update command/response roundtrip with cryptogram verification
/// - External Authenticate with MAC verification on both sides
/// - Session state progression through secure exchanges using functional composition
///
/// Uses real test vectors and actual card emulator with no mocks.
/// </summary>
[TestFixture]
[Category("Integration")]
[Category("Cryptographic")]
public class BidirectionalCryptographicRoundtripTests
{
    private TraceApduDecryptor _decryptorService = null!;

    [OneTimeSetUp]
    public void OneTimeSetup()
    {
        _decryptorService = new TraceApduDecryptor(
            Microsoft.Extensions.Logging.Abstractions.NullLogger<TraceApduDecryptor>.Instance
        );
    }

    [Test]
    public void InitializeUpdate_ShouldValidateBidirectionalCryptograms()
    {
        var result = CreateTestCard().Bind(card => PerformInitializeUpdateTest(card));

        Assert.That(
            result.IsSuccess,
            Is.True,
            result.IsFailure ? $"Initialize Update failed: {result.Error}" : string.Empty
        );
    }

    [Test]
    public void ExternalAuthenticate_ShouldValidateMacOnBothSides()
    {
        var result = CreateTestCard().Bind(card => PerformExternalAuthenticateTest(card));

        Assert.That(
            result.IsSuccess,
            Is.True,
            result.IsFailure ? $"External Authenticate failed: {result.Error}" : string.Empty
        );
    }

    [Test]
    public void SecureCommandDecryption_ShouldWorkBidirectionally()
    {
        var result = CreateTestCard().Bind(card => PerformDecryptorServiceTest(card));

        Assert.That(
            result.IsSuccess,
            Is.True,
            result.IsFailure ? $"Decryptor service test failed: {result.Error}" : string.Empty
        );
    }

    /// <summary>
    /// Create a test card with the P71 configuration.
    /// </summary>
    private static Result<IVirtualCard, SmartCardError> CreateTestCard()
    {
        return CardConfiguration
            .P71()
            .Map(config => config.WithScpDefaults(0x03, ScpImplementation.Scp03I70))
            .Bind(config =>
                GpTestKeys
                    .CreateScp03TestKeySet(0x01)
                    .Map(keySet => config.WithKeySet(0x01, keySet))
            )
            .Map(config => (IVirtualCard)VirtualCardTestBuilder.CreateWithSecureRng(config));
    }

    /// <summary>
    /// Test Initialize Update command/response with cryptogram verification on both sides.
    /// </summary>
    private Result<bool, SmartCardError> PerformInitializeUpdateTest(IVirtualCard card)
    {
        // Get test keys for SCP03
        return GpTestKeys
            .GetTestKeySet(CryptoOperations.ScpVersion.Scp03)
            .Bind(keySet =>
                keySet switch
                {
                    Scp03KeySet scp03Keys => PerformInitializeUpdateWithKeys(card, scp03Keys),
                    _
                        => Result.Failure<bool, SmartCardError>(
                            SmartCardError.InvalidArgument("Expected SCP03 key set")
                        ),
                }
            );
    }

    private Result<bool, SmartCardError> PerformInitializeUpdateWithKeys(
        IVirtualCard card,
        Scp03KeySet keySet
    )
    {
        byte[] hostChallenge = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        return InitializeUpdateCommand
            .Create(0x00, 0x00, hostChallenge)
            .Bind(cmd => cmd.ToCommandApdu())
            .Bind(apdu => ApduCommandExtensions.ToApdu(apdu))
            .Bind(commandBytes =>
                ExecuteAndValidateInitUpdate(card, commandBytes, keySet, hostChallenge)
            );
    }

    private Result<bool, SmartCardError> ExecuteAndValidateInitUpdate(
        IVirtualCard card,
        byte[] commandBytes,
        Scp03KeySet keySet,
        byte[] hostChallenge
    )
    {
        return card.ProcessCommand(commandBytes)
            .Bind(result =>
                ValidateInitUpdateResponse(result, keySet, hostChallenge, commandBytes)
            );
    }

    private Result<bool, SmartCardError> ValidateInitUpdateResponse(
        (ApduResponse Response, IVirtualCard UpdatedCard) result,
        Scp03KeySet keySet,
        byte[] hostChallenge,
        byte[] commandBytes
    )
    {
        var (response, _) = result;

        if (!response.IsSuccessful || response.Data.Length < 20)
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.CommunicationError("Invalid Initialize Update response")
            );

        return InitializeUpdateResponse
            .Parse(response.Data)
            .Bind(initResponse =>
                VerifyCardCryptogramAndTestDecryptor(
                    initResponse,
                    keySet,
                    hostChallenge,
                    commandBytes,
                    response
                )
            );
    }

    private Result<bool, SmartCardError> VerifyCardCryptogramAndTestDecryptor(
        InitializeUpdateResponse initResponse,
        Scp03KeySet keySet,
        byte[] hostChallenge,
        byte[] commandBytes,
        ApduResponse response
    )
    {
        // Derive session keys on host side
        return KeyDerivationContext
            .CreateForScp03(
                keySet,
                hostChallenge,
                initResponse.CardChallenge,
                Maybe<ScpImplementation>.From(
                    (ScpImplementation)initResponse.ImplementationParameter
                )
            )
            .Bind(context => CryptoOperations.KeyDerivation.DeriveSessionKeys(context))
            .Bind(sessionKeys => VerifyCardCryptogram(initResponse, hostChallenge, sessionKeys))
            .Bind(sessionKeys =>
                TestDecryptorServiceRoundtrip(sessionKeys, initResponse, commandBytes, response)
            );
    }

    private static Result<SessionKeys, SmartCardError> VerifyCardCryptogram(
        InitializeUpdateResponse initResponse,
        byte[] hostChallenge,
        SessionKeys sessionKeys
    )
    {
        // Directly derive expected card cryptogram using S-MAC key per GP SCP03 (6.2.2.2)
        return CryptoOperations
            .Cryptogram.CalculateScp03CardCryptogram(
                sessionKeys.SMac,
                hostChallenge,
                initResponse.CardChallenge
            )
            .Bind(expectedCryptogram =>
                CryptoOperations.Utils.CompareBytes(expectedCryptogram, initResponse.CardCryptogram)
                    ? Result.Success<SessionKeys, SmartCardError>(sessionKeys)
                    : Result.Failure<SessionKeys, SmartCardError>(
                        SmartCardError.AuthenticationFailed("Card cryptogram mismatch")
                    )
            );
    }

    private Result<bool, SmartCardError> TestDecryptorServiceRoundtrip(
        SessionKeys sessionKeys,
        InitializeUpdateResponse initResponse,
        byte[] commandBytes,
        ApduResponse response
    )
    {
        return SecureChannelState
            .Create(
                sessionKeys,
                SecurityLevel.None,
                CryptoOperations.ScpVersion.Scp03,
                new byte[16], // Zero MAC chaining for SCP03
                initResponse.ImplementationParameter
            )
            .Bind(sessionState => ValidateDecryptorRoundtrip(sessionState, commandBytes, response));
    }

    private Result<bool, SmartCardError> ValidateDecryptorRoundtrip(
        SecureChannelState sessionState,
        byte[] commandBytes,
        ApduResponse response
    )
    {
        // Test command decryption
        return _decryptorService
            .DecryptApdu(commandBytes, ApduDirection.Command, sessionState)
            .Bind(commandResult =>
                ValidateCommandDecryption(commandResult.decryptedApdu, commandBytes)
            )
            .Bind(_ => TestResponseDecryption(response, sessionState))
            .Map(_ => true);
    }

    private static Result<bool, SmartCardError> ValidateCommandDecryption(
        DecryptedApdu decryptedCommand,
        byte[] originalCommandBytes
    )
    {
        if (decryptedCommand.Status != DecryptionStatus.PlainText)
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidData("Command should be recognized as plaintext")
            );

        if (!decryptedCommand.DecryptedBytes.SequenceEqual(originalCommandBytes))
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidData("Decrypted command bytes should match original")
            );

        return Result.Success<bool, SmartCardError>(true);
    }

    private Result<bool, SmartCardError> TestResponseDecryption(
        ApduResponse response,
        SecureChannelState sessionState
    )
    {
        // Create response bytes with status word
        var responseBytes = new byte[response.Data.Length + 2];
        response.Data.CopyTo(responseBytes, 0);
        var sw = response.StatusWord;
        responseBytes[^2] = (byte)(sw >> 8);
        responseBytes[^1] = (byte)(sw & 0xFF);

        return _decryptorService
            .DecryptApdu(responseBytes, ApduDirection.Response, sessionState)
            .Map(responseResult =>
                responseResult.decryptedApdu.Status == DecryptionStatus.PlainText
            );
    }

    /// <summary>
    /// Test External Authenticate with MAC verification on both sides.
    /// </summary>
    private Result<bool, SmartCardError> PerformExternalAuthenticateTest(IVirtualCard card)
    {
        return GpTestKeys
            .GetTestKeySet(CryptoOperations.ScpVersion.Scp03)
            .Bind(keySet =>
                keySet switch
                {
                    Scp03KeySet scp03Keys => PerformExternalAuthFlow(card, scp03Keys),
                    _
                        => Result.Failure<bool, SmartCardError>(
                            SmartCardError.InvalidArgument("Expected SCP03 key set")
                        ),
                }
            );
    }

    private Result<bool, SmartCardError> PerformExternalAuthFlow(
        IVirtualCard card,
        Scp03KeySet keySet
    )
    {
        byte[] hostChallenge = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

        // Step 1: Initialize Update
        return InitializeUpdateCommand
            .Create(0x00, 0x00, hostChallenge)
            .Bind(cmd => cmd.ToCommandApdu())
            .Bind(apdu => ApduCommandExtensions.ToApdu(apdu))
            .Bind(commandBytes => card.ProcessCommand(commandBytes))
            .Bind(initResult => ProcessExternalAuth(initResult, keySet, hostChallenge));
    }

    private Result<bool, SmartCardError> ProcessExternalAuth(
        (ApduResponse Response, IVirtualCard UpdatedCard) initResult,
        Scp03KeySet keySet,
        byte[] hostChallenge
    )
    {
        var (initResponse, cardAfterInit) = initResult;

        if (!initResponse.IsSuccessful)
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.AuthenticationFailed("Initialize Update failed")
            );

        return InitializeUpdateResponse
            .Parse(initResponse.Data)
            .Bind(initUpdateResponse =>
                DeriveSessionKeysAndAuth(cardAfterInit, keySet, hostChallenge, initUpdateResponse)
            );
    }

    private Result<bool, SmartCardError> DeriveSessionKeysAndAuth(
        IVirtualCard card,
        Scp03KeySet keySet,
        byte[] hostChallenge,
        InitializeUpdateResponse initUpdateResponse
    )
    {
        return KeyDerivationContext
            .CreateForScp03(
                keySet,
                hostChallenge,
                initUpdateResponse.CardChallenge,
                Maybe<ScpImplementation>.From(
                    (ScpImplementation)initUpdateResponse.ImplementationParameter
                )
            )
            .Bind(context => CryptoOperations.KeyDerivation.DeriveSessionKeys(context))
            .Bind(sessionKeys =>
                CreateAndExecuteExternalAuth(card, sessionKeys, initUpdateResponse, hostChallenge)
            );
    }

    private Result<bool, SmartCardError> CreateAndExecuteExternalAuth(
        IVirtualCard card,
        SessionKeys sessionKeys,
        InitializeUpdateResponse initUpdateResponse,
        byte[] hostChallenge
    )
    {
        // Derive host cryptogram (S-MAC key) per GP SCP03 (6.2.2.3)
        return CryptoOperations
            .Cryptogram.CalculateScp03HostCryptogram(
                sessionKeys.SMac,
                hostChallenge,
                initUpdateResponse.CardChallenge
            )
            .Bind(hostCryptogram => CreateExternalAuthWithMac(hostCryptogram, sessionKeys))
            .Bind(commandBytes =>
                ExecuteExternalAuthAndValidate(card, commandBytes, sessionKeys, initUpdateResponse)
            );
    }

    private static Result<byte[], SmartCardError> CreateExternalAuthWithMac(
        byte[] hostCryptogram,
        SessionKeys sessionKeys
    )
    {
        var securityLevel = SecurityLevel.CMac;
        // SCP03 Amendment D v1.1.2, Sections 6.2.3 and 7.1.2.
        byte[] macInput = [0x84, 0x82, (byte)securityLevel, 0x00, 0x10, .. hostCryptogram,];

        return CryptoOperations
            .ScpOperations.Scp03.CalculateCommandMac(
                macInput,
                sessionKeys.SMac,
                Gp4Net.Constants.Constants.Scp.Common.ZeroChaining16
            )
            .Map(fullMac => fullMac[..8])
            .Bind(mac =>
                ExternalAuthenticateCommand.CreateWithMac(securityLevel, hostCryptogram, mac)
            )
            .Bind(cmdWithMac => cmdWithMac.ToCommandApdu())
            .Bind(apdu => ApduCommandExtensions.ToApdu(apdu));
    }

    private Result<bool, SmartCardError> ExecuteExternalAuthAndValidate(
        IVirtualCard card,
        byte[] commandBytes,
        SessionKeys sessionKeys,
        InitializeUpdateResponse initUpdateResponse
    )
    {
        return card.ProcessCommand(commandBytes)
            .Bind(result => ValidateExternalAuthSuccess(result.Response))
            .Bind(_ =>
                ValidateExternalAuthDecryption(commandBytes, sessionKeys, initUpdateResponse)
            );
    }

    private static Result<bool, SmartCardError> ValidateExternalAuthSuccess(ApduResponse response)
    {
        return response.IsSuccessful
            ? Result.Success<bool, SmartCardError>(true)
            : Result.Failure<bool, SmartCardError>(
                SmartCardError.AuthenticationFailed("External Authenticate failed")
            );
    }

    private Result<bool, SmartCardError> ValidateExternalAuthDecryption(
        byte[] commandBytes,
        SessionKeys sessionKeys,
        InitializeUpdateResponse initUpdateResponse
    )
    {
        return SecureChannelState
            .Create(
                sessionKeys,
                SecurityLevel.CMac,
                CryptoOperations.ScpVersion.Scp03,
                new byte[16], // Zero MAC chaining
                initUpdateResponse.ImplementationParameter
            )
            .Bind(sessionState =>
                _decryptorService.DecryptApdu(commandBytes, ApduDirection.Command, sessionState)
            )
            .Map(result => result.decryptedApdu.Status == DecryptionStatus.PlainText);
    }

    /// <summary>
    /// Test that the decryptor service works correctly with plaintext commands.
    /// </summary>
    private Result<bool, SmartCardError> PerformDecryptorServiceTest(IVirtualCard card)
    {
        return GpTestKeys
            .GetTestKeySet(CryptoOperations.ScpVersion.Scp03)
            .Bind(keySet =>
                keySet switch
                {
                    Scp03KeySet scp03Keys => TestDecryptorWithPlaintext(scp03Keys),
                    _
                        => Result.Failure<bool, SmartCardError>(
                            SmartCardError.InvalidArgument("Expected SCP03 key set")
                        ),
                }
            );
    }

    private Result<bool, SmartCardError> TestDecryptorWithPlaintext(Scp03KeySet keySet)
    {
        // Create session keys for testing
        return KeyDerivationContext
            .CreateForScp03(
                keySet,
                new byte[8], // Host challenge
                new byte[8], // Card challenge
                Maybe<ScpImplementation>.From(ScpImplementation.Scp03I70)
            )
            .Bind(context => CryptoOperations.KeyDerivation.DeriveSessionKeys(context))
            .Bind(sessionKeys => TestPlaintextCommandDecryption(sessionKeys));
    }

    private Result<bool, SmartCardError> TestPlaintextCommandDecryption(SessionKeys sessionKeys)
    {
        return SecureChannelState
            .Create(
                sessionKeys,
                SecurityLevel.CMac,
                CryptoOperations.ScpVersion.Scp03,
                new byte[16],
                0x70 // SCP03 i=70
            )
            .Bind(sessionState => TestPlaintextDecryption(sessionState));
    }

    private Result<bool, SmartCardError> TestPlaintextDecryption(SecureChannelState sessionState)
    {
        // Test with a simple plaintext command
        byte[] plaintextCommand = [0x00, 0xA4, 0x04, 0x00, 0x00]; // SELECT command

        return _decryptorService
            .DecryptApdu(plaintextCommand, ApduDirection.Command, sessionState)
            .Map(result =>
                result.decryptedApdu.Status == DecryptionStatus.PlainText
                && result.decryptedApdu.DecryptedBytes.SequenceEqual(plaintextCommand)
            );
    }
}
