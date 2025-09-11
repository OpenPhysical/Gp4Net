using System;
using CSharpFunctionalExtensions;
using NUnit.Framework;
using Gp4Net.Cryptography;
using Gp4Net.Core;

namespace Gp4Net.Tests.Unit.Security;

[TestFixture]
public class TestMacCalculation
{
    [Test]
    public void Test_ExternalAuth_Mac_Calculation()
    {
        var commandHex = "848201001095A78968A09DB5D9";
        var expectedMacHex = "A3077662BA8EA35B";
        var sMacKeyHex = "89D93B2D2D7E7AB95B61F82EDE3975B7";
        var icvHex = "0000000000000000";
        
        var command = Convert.FromHexString(commandHex);
        var expectedMac = Convert.FromHexString(expectedMacHex);
        var sMacKey = Convert.FromHexString(sMacKeyHex);
        var icv = Convert.FromHexString(icvHex);
        
        var result = CryptoService.ScpOperations.Scp02.CalculateCommandMac(
            command, 
            sMacKey, 
            icv
        );
        
        result.Match(
            calculatedMac =>
            {
                Console.WriteLine($"Expected MAC: {BitConverter.ToString(expectedMac).Replace("-", "")}");
                Console.WriteLine($"Calculated MAC: {BitConverter.ToString(calculatedMac).Replace("-", "")}");
                
                Assert.That(calculatedMac, Is.EqualTo(expectedMac), 
                    "Calculated MAC does not match expected MAC from trace");
                return 0;
            },
            error =>
            {
                Assert.Fail($"MAC calculation failed: {error.Message}");
                return 0;
            }
        );
    }
}