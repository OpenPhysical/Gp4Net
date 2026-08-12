using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using NUnit.Framework;

namespace Gp4Net.Tests.Cryptography;

[TestFixture]
public class Scp03CryptogramTests
{
    // Test data from actual trace log at tests/Gp4Net.Tests/TestData/Traces/Raw/gp_pro_p71_scp03.txt
    private static readonly byte[] MasterKey = Convert.FromHexString(
        "404142434445464748494A4B4C4D4E4F"
    );

    // From line 88-89 of trace
    private static readonly byte[] HostChallenge = Convert.FromHexString("FE0530CF61BAA9F3");
    private static readonly byte[] CardChallenge = Convert.FromHexString("83FA042C5C10F778");

    // From line 93-94 of trace
    private static readonly byte[] ExpectedCardCryptogram = Convert.FromHexString(
        "148C0CAF84B0E110"
    );
    private static readonly byte[] ExpectedHostCryptogram = Convert.FromHexString(
        "7B54E3B21E27DA5F"
    );

    [Test]
    public void Should_Calculate_Correct_Card_Cryptogram_With_Known_Test_Values()
    {
        var macKey = DeriveMacSessionKey(HostChallenge, CardChallenge);
        var cardCryptogramResult = CryptoOperations.Cryptogram.CalculateScp03CardCryptogram(
            macKey,
            HostChallenge,
            CardChallenge
        );

        Assert.That(cardCryptogramResult.IsSuccess, Is.True, "Failed to calculate card cryptogram");
        var calculatedCryptogram = cardCryptogramResult.Value;

        Assert.That(
            calculatedCryptogram[..8],
            Is.EqualTo(ExpectedCardCryptogram),
            "Card cryptogram mismatch"
        );
    }

    [Test]
    public void Should_Calculate_Correct_Host_Cryptogram_With_Known_Test_Values()
    {
        var macKey = DeriveMacSessionKey(HostChallenge, CardChallenge);
        var hostCryptogramResult = CryptoOperations.Cryptogram.CalculateScp03HostCryptogram(
            macKey,
            HostChallenge,
            CardChallenge
        );

        Assert.That(hostCryptogramResult.IsSuccess, Is.True, "Failed to calculate host cryptogram");
        var calculatedCryptogram = hostCryptogramResult.Value;

        Assert.That(
            calculatedCryptogram[..8],
            Is.EqualTo(ExpectedHostCryptogram),
            "Host cryptogram mismatch"
        );
    }

    [Test]
    public void Should_Calculate_Correct_Cryptogram_Using_InitializeUpdateResponse()
    {
        // Create a mock InitializeUpdateResponse with our test data
        // Response structure from GP spec:
        // - 10 bytes key diversification data (or padding)
        // - 1 byte key version
        // - 1 byte SCP identifier (0x03 for SCP03)
        // - 8 bytes card challenge
        // - 8 bytes card cryptogram
        // - 3 bytes sequence counter (optional for SCP03)

        var initUpdateResponse = Convert.FromHexString(
            "03700000000000000000010370BE906A81C79CAF176D073D7EF2F518F300004F"
        );

        var parseResult = InitializeUpdateResponse.Parse(initUpdateResponse);
        Assert.That(parseResult.IsSuccess, Is.True, "Failed to parse INIT UPDATE response");
        var response = parseResult.Value;

        // Build cryptogram data using the response
        var hostChallengeForResponse = Convert.FromHexString("A51709B085AF91C1");
        var macKey = DeriveMacSessionKey(hostChallengeForResponse, response.CardChallenge);
        var calculatedCryptogramResult = CryptoOperations.Cryptogram.CalculateScp03CardCryptogram(
            macKey,
            hostChallengeForResponse,
            response.CardChallenge
        );

        Assert.That(
            calculatedCryptogramResult.IsSuccess,
            Is.True,
            "Failed to calculate card cryptogram"
        );
        var calculatedCryptogram = calculatedCryptogramResult.Value;

        Assert.That(
            calculatedCryptogram[..8],
            Is.EqualTo(response.CardCryptogram),
            "Cryptogram should match parsed response"
        );
    }

    [Test]
    public void Should_Verify_Card_And_Host_Cryptograms_Use_Different_Derivation_Constants()
    {
        // This test verifies that card and host cryptograms are different
        // due to using different derivation constants per GP spec

        var macKey = DeriveMacSessionKey(HostChallenge, CardChallenge);
        var cardCryptogramResult = CryptoOperations.Cryptogram.CalculateScp03CardCryptogram(
            macKey,
            HostChallenge,
            CardChallenge
        );

        var hostCryptogramResult = CryptoOperations.Cryptogram.CalculateScp03HostCryptogram(
            macKey,
            HostChallenge,
            CardChallenge
        );

        Assert.That(cardCryptogramResult.IsSuccess, Is.True);
        Assert.That(hostCryptogramResult.IsSuccess, Is.True);

        var cardCryptogram = cardCryptogramResult.Value[..8];
        var hostCryptogram = hostCryptogramResult.Value[..8];

        Assert.That(
            cardCryptogram,
            Is.Not.EqualTo(hostCryptogram),
            "Card and host cryptograms must be different"
        );
    }

    [Test]
    public void Should_Fail_With_Invalid_Mac_Key()
    {
        // Test with invalid MAC key length
        var invalidMacKey = new byte[8]; // Too short
        var result = CryptoOperations.Cryptogram.CalculateScp03CardCryptogram(
            invalidMacKey,
            HostChallenge,
            CardChallenge
        );

        Assert.That(result.IsFailure, Is.True, "Should fail with invalid MAC key");
    }

    [Test]
    public void Should_Fail_With_Invalid_Challenge_Lengths()
    {
        var macKey = DeriveMacSessionKey(HostChallenge, CardChallenge);

        // Test with wrong host challenge length
        var shortHostChallenge = new byte[4];
        var result1 = CryptoOperations.Cryptogram.CalculateScp03CardCryptogram(
            macKey,
            shortHostChallenge,
            CardChallenge
        );
        Assert.That(result1.IsFailure, Is.True, "Should fail with short host challenge");

        // Test with wrong card challenge length (SCP03 requires 8 bytes)
        var shortCardChallenge = new byte[6];
        var result2 = CryptoOperations.Cryptogram.CalculateScp03CardCryptogram(
            macKey,
            HostChallenge,
            shortCardChallenge
        );
        Assert.That(result2.IsFailure, Is.True, "Should fail with wrong card challenge length");
    }

    /// <summary>
    /// SCP03 v1.1.2, Table 4-1 marks 0x08 RFU; §6.1 states that no session Key-DEK is generated.
    /// </summary>
    [Test]
    public void Should_Reject_Rfu_SDek_Derivation_Constant()
    {
        var result = CryptoOperations.KeyDerivation.DeriveScp03SessionKey(
            MasterKey,
            HostChallenge,
            CardChallenge,
            0x08
        );

        Assert.That(result.IsFailure, Is.True);
    }

    private static byte[] DeriveMacSessionKey(byte[] hostChallenge, byte[] cardChallenge)
    {
        var keySetResult = Scp03KeySet.Create(MasterKey, MasterKey, MasterKey, 0x01);
        Assert.That(keySetResult.IsSuccess, Is.True, "Failed to create SCP03 key set");

        var macKeyResult = CryptoOperations.KeyDerivation.DeriveScp03SessionKey(
            keySetResult.Value.MacKey,
            hostChallenge,
            cardChallenge,
            0x06
        );

        Assert.That(macKeyResult.IsSuccess, Is.True, "Failed to derive SCP03 MAC session key");
        return macKeyResult.Value;
    }
}
