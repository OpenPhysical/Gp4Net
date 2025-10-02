using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Commands;
using NUnit.Framework;

namespace Gp4Net.Tests.Cryptography;

[TestFixture]
public class Scp02CryptogramTests
{
    // Test data from actual trace log at tests/Gp4Net.Tests/TestData/Traces/Raw/gp_pro_scp02_enc.log
    private static readonly byte[] MasterKey = Convert.FromHexString(
        "404142434445464748494A4B4C4D4E4F"
    );
    private static readonly byte[] HostChallenge = Convert.FromHexString("CE410ED7FACD71A1");
    private static readonly byte[] SequenceCounter = Convert.FromHexString("0013");
    private static readonly byte[] CardChallenge = Convert.FromHexString("884AB6A84A18");
    private static readonly byte[] ExpectedCardCryptogram = Convert.FromHexString(
        "19A72830637708FB"
    );

    // Derived session keys from the log (line 31)
    private static readonly byte[] SEncKey = Convert.FromHexString(
        "E94829A5FD577FB1512772AC2DD27024"
    );

    [Test]
    public void Should_Calculate_Correct_Card_Cryptogram_With_Known_Test_Values()
    {
        // Arrange
        // Build the card cryptogram data: hostChallenge || sequenceCounter || cardChallenge
        var cryptogramData = HostChallenge.Concat(SequenceCounter).Concat(CardChallenge).ToArray();

        // Act - CalculateScp02Cryptogram now handles padding internally
        var result = CryptoService.Cryptogram.CalculateScp02Cryptogram(SEncKey, cryptogramData);

        // Assert
        if (!result.IsSuccess)
        {
            Assert.Fail($"Calculation failed: {result.Error}");
        }

        var calculatedCryptogram = result.Value;

        TestContext.Out.WriteLine($"Input data (16 bytes): {Convert.ToHexString(cryptogramData)}");
        TestContext.Out.WriteLine($"S-ENC Key: {Convert.ToHexString(SEncKey)}");
        TestContext.Out.WriteLine(
            $"Expected cryptogram: {Convert.ToHexString(ExpectedCardCryptogram)}"
        );
        TestContext.Out.WriteLine(
            $"Calculated cryptogram: {Convert.ToHexString(calculatedCryptogram)}"
        );

        Assert.That(calculatedCryptogram, Is.EqualTo(ExpectedCardCryptogram));
    }

    [Test]
    public void Should_Calculate_Correct_Cryptogram_Using_BuildScp02CardCryptogramData()
    {
        // Arrange
        // Create a mock InitializeUpdateResponse with our test data
        var initUpdateResponseData = new byte[28];
        Array.Copy(
            new byte[] { 0x00, 0x00, 0x23, 0x45, 0x55, 0x80, 0x83, 0x20, 0x48, 0x39 },
            0,
            initUpdateResponseData,
            0,
            10
        ); // Diversification data
        initUpdateResponseData[10] = 0x01; // Key version
        initUpdateResponseData[11] = 0x02; // SCP version
        Array.Copy(SequenceCounter, 0, initUpdateResponseData, 12, 2);
        Array.Copy(CardChallenge, 0, initUpdateResponseData, 14, 6);
        Array.Copy(ExpectedCardCryptogram, 0, initUpdateResponseData, 20, 8);

        var parseResult = InitializeUpdateResponse.Parse(initUpdateResponseData);
        if (!parseResult.IsSuccess)
        {
            Assert.Fail($"Failed to parse response: {parseResult.Error}");
        }

        var response = parseResult.Value;

        // Act
        var finalResult = CryptoService
            .Cryptogram.BuildScp02CardCryptogramData(response, HostChallenge)
            .Bind(paddedData =>
                CryptoService.Cryptogram.CalculateScp02Cryptogram(SEncKey, paddedData)
            );

        Assert.That(finalResult.IsSuccess, Is.True);

        var calculatedCryptogram = finalResult.Value;

        // Log for debugging
        var seqCounterHex =
            response.SequenceCounter.Length > 0
                ? Convert.ToHexString(response.SequenceCounter)
                : "None";
        TestContext.Out.WriteLine($"Response sequence counter: {seqCounterHex}");
        TestContext.Out.WriteLine(
            $"Response card challenge: {Convert.ToHexString(response.CardChallenge)}"
        );
        TestContext.Out.WriteLine(
            $"Expected cryptogram: {Convert.ToHexString(ExpectedCardCryptogram)}"
        );
        TestContext.Out.WriteLine(
            $"Calculated cryptogram: {Convert.ToHexString(calculatedCryptogram)}"
        );

        // Assert
        Assert.That(calculatedCryptogram, Is.EqualTo(ExpectedCardCryptogram));
    }
}
