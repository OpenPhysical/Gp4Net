using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Cryptography;
using NUnit.Framework;

namespace Gp4Net.Tests.Cryptography;

[TestFixture]
public class SimpleScp02Test
{
    [Test]
    public void Test_SCP02_Cryptogram_Calculation()
    {
        // Test data from actual trace log at tests/Gp4Net.Tests/TestData/Traces/Raw/gp_pro_scp02_enc.log
        var sEncKey = Convert.FromHexString("E94829A5FD577FB1512772AC2DD27024");
        var hostChallenge = Convert.FromHexString("CE410ED7FACD71A1");
        var sequenceCounter = Convert.FromHexString("0013");
        var cardChallenge = Convert.FromHexString("884AB6A84A18");
        var expectedCardCryptogram = Convert.FromHexString("19A72830637708FB");

        // Build the card cryptogram data: hostChallenge || sequenceCounter || cardChallenge
        var cryptogramData = hostChallenge.Concat(sequenceCounter).Concat(cardChallenge).ToArray();

        Console.WriteLine($"Input data (16 bytes): {Convert.ToHexString(cryptogramData)}");
        Console.WriteLine($"S-ENC Key: {Convert.ToHexString(sEncKey)}");
        Console.WriteLine($"Expected cryptogram: {Convert.ToHexString(expectedCardCryptogram)}");

        // Calculate cryptogram - now expects unpadded data, padding handled internally
        var result = CryptoService.Cryptogram.CalculateScp02Cryptogram(sEncKey, cryptogramData);

        result.Match(
            calculatedCryptogram =>
            {
                Console.WriteLine($"Calculated cryptogram: {Convert.ToHexString(calculatedCryptogram)}");
                Assert.That(calculatedCryptogram, Is.EqualTo(expectedCardCryptogram));
            },
            error => Assert.Fail($"Calculation failed: {error}")
        );
    }
}
