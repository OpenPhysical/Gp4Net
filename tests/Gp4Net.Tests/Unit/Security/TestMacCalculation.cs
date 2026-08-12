using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Security;
using Gp4Net.Domain.Trace;
using Gp4Net.Services;
using NUnit.Framework;
using WSCT.ISO7816;
using GpConstants = Gp4Net.Constants.Constants;

namespace Gp4Net.Tests.Unit.Security;

[TestFixture]
[Category("Unit")]
[Category("Cryptography")]
[Category("MAC")]
public class TestMacCalculation
{
    private static readonly byte[] GpTestKey = Convert.FromHexString(
        "404142434445464748494A4B4C4D4E4F"
    );

    [Test]
    [Category("SCP02")]
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

        var result = CryptoOperations.ScpOperations.Scp02.CalculateCommandMac(
            command,
            sMacKey,
            icv
        );

        result.Match(
            calculatedMac =>
            {
                Assert.That(calculatedMac, Is.EqualTo(expectedMac));
                return 0;
            },
            error =>
            {
                Assert.Fail($"MAC calculation failed: {error.Message}");
                return 0;
            }
        );
    }

    [Test]
    [Category("SCP03")]
    public void Scp03_CommandMac_ShouldMatchTraceValue()
    {
        var keySet = GpTestKeys.CreateScp03TestKeySet(0x01).Value;
        var state = TraceValidationState.Create(keySet);

        state = ValidateExchange(
            state,
            "8050000008F5E88C6C30039A5300",
            "037000000000000000000103700D607A25D729A20F7E793686DEE77FAF00004A9000",
            10
        );

        state = ValidateExchange(state, "84820300103B50EF3764CCDD83AF26B8D11ED7034000", "9000", 11);

        state = ValidateExchange(
            state,
            "84F280021847D799BDC908166D61B7CEAFD6205F731A7B8648F31BC58000",
            "E3264F08A0000001510000009F700101C5039EFE80C407A0000001515350CC08A0000001510000009000",
            12
        );

        var result = state.Results.Last(r => r.ExchangeIndex == 12);
        Assert.That(result.IsValid, Is.True, result.Details);
        Assert.That(result.ValidationType, Is.EqualTo("SECURE_MESSAGING"));
    }

    [Test]
    [Category("SCP03")]
    public void Scp03_ResponseMac_ShouldMatchTraceValue()
    {
        var keySet = GpTestKeys.CreateScp03TestKeySet(0x01).Value;
        var state = TraceValidationState.Create(keySet);

        state = ValidateExchange(
            state,
            "8050000008A51709B085AF91C100",
            "03700000000000000000010370BE906A81C79CAF176D073D7EF2F518F300004F9000",
            10
        );

        state = ValidateExchange(state, "84823300102A233480144D41037D79C57D90E3067200", "9000", 11);

        state = ValidateExchange(
            state,
            "84F2800218A7EA1DB31FC2BB6B648E7D0E9C4AE73C8F5117736D54228900",
            "4E44DB0863ED9F4514FD486ADB60ABA86605A4E37F3513858891E0A87ADF2E488471521D30C42CB372EF09B0508EC5BA25D4CA2294EA19F19000",
            12
        );

        var result = state.Results.Last(r => r.ExchangeIndex == 12);
        Assert.That(result.IsValid, Is.True, result.Details);
        Assert.That(result.ValidationType, Is.EqualTo("SECURE_MESSAGING"));
    }

    [Test]
    [Category("SCP03")]
    public void Scp03_Should_Fail_With_Invalid_Mac_Chaining_Length()
    {
        var command = Convert.FromHexString("84F2010000");
        var macChaining = new byte[15];

        var result = CryptoOperations.ScpOperations.Scp03.CalculateCommandMac(
            command,
            GpTestKey,
            macChaining
        );

        Assert.That(result.IsFailure, Is.True);
    }

    [Test]
    [Category("SCP03")]
    [TestCase("", Description = "Empty command")]
    [TestCase("80", Description = "Single byte command")]
    [TestCase("80CA", Description = "Two byte command")]
    [TestCase("80CA00", Description = "Three byte command")]
    [TestCase("80CA0066", Description = "Four byte command")]
    public void Scp03_Should_Handle_Short_Commands(string commandHex)
    {
        var input = commandHex.Length > 0 ? Convert.FromHexString(commandHex) : Array.Empty<byte>();
        var result = CryptoOperations.Mac.CalculateScp03CommandMac(GpTestKey, input);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value.Length, Is.EqualTo(GpConstants.Scp.Scp03.MAC_SIZE));
    }

    private static TraceValidationState ValidateExchange(
        TraceValidationState state,
        string commandHex,
        string responseHex,
        int exchangeIndex
    )
    {
        var command = Convert.FromHexString(commandHex);
        var response = Convert.FromHexString(responseHex);

        var result = TraceValidation.ValidateExchange(state, command, response, exchangeIndex);

        if (result.IsFailure)
        {
            Assert.Fail($"Exchange {exchangeIndex} validation failed: {result.Error.Message}");
        }

        return result.Value;
    }
}
