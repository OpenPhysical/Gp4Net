using System;
using AwesomeAssertions;
using Gp4Net.Constants;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Extensions;
using Gp4Net.Services;
using NUnit.Framework;
using WSCT.ISO7816;

namespace Gp4Net.Tests.Compliance;

[TestFixture]
[Category("GpCompliance")]
[Category("SCP02")]
public class Scp02CommandSecurityTests
{
    private static readonly byte[] SEnc = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
    private static readonly byte[] SMac = Convert.FromHexString("0102030405060708090A0B0C0D0E0F10");

    [Test]
    public void Should_Mac_Unmodified_Apdu_When_B2_Is_Set()
    {
        // GP Card Specification v2.3.1, Table E-1 and Appendix E.4.4.
        var command = new CommandAPDU(Convert.FromHexString("80E2000003010203"));
        SecureChannelState state = CreateState(ScpImplementation.Scp02I02, new byte[8]);
        byte[] expectedInput = Convert.FromHexString("80E2000003010203");
        byte[] expectedMac = CryptoService
            .Mac.CalculateScp02CommandMac(SMac, expectedInput, new byte[8])
            .Value;

        var result = ScpService.Security.ApplyCommandSecurity(command, state);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.securedCommand.Udc[^8..].Should().Equal(expectedMac);
        _ = command.GetMacInput(modifyHeader: false).Value.Bytes.Should().Equal(expectedInput);
    }

    [Test]
    public void Should_Mac_Modified_Apdu_When_B2_Is_Clear()
    {
        // GP Card Specification v2.3.1, Table E-1 and Appendix E.4.4.
        var command = new CommandAPDU(Convert.FromHexString("80E2000003010203"));
        SecureChannelState state = CreateState(ScpImplementation.Scp02I04, new byte[8]);
        byte[] expectedInput = Convert.FromHexString("84E200000B010203");
        byte[] expectedMac = CryptoService
            .Mac.CalculateScp02CommandMac(SMac, expectedInput, new byte[8])
            .Value;

        var result = ScpService.Security.ApplyCommandSecurity(command, state);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.securedCommand.Udc[^8..].Should().Equal(expectedMac);
        _ = command.GetMacInput().Value.Bytes.Should().Equal(expectedInput);
    }

    [TestCase(ScpImplementation.Scp02I04, false)]
    [TestCase(ScpImplementation.Scp02I14, true)]
    public void Should_Apply_Icv_Encryption_According_To_B5(
        ScpImplementation implementation,
        bool encryptIcv
    )
    {
        // GP Card Specification v2.3.1, Table E-1 and Appendix E.3.4.
        byte[] chaining = Convert.FromHexString("1122334455667788");
        var command = new CommandAPDU(Convert.FromHexString("80E2000003010203"));
        byte[] icv = encryptIcv
            ? CryptoService.Mac.EncryptScp02Icv(chaining, SMac).Value
            : chaining;
        byte[] expectedMac = CryptoService
            .Mac.CalculateScp02CommandMac(SMac, command.GetMacInput().Value.Bytes, icv)
            .Value;

        var result = ScpService.Security.ApplyCommandSecurity(
            command,
            CreateState(implementation, chaining)
        );

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.securedCommand.Udc[^8..].Should().Equal(expectedMac);
    }

    private static SecureChannelState CreateState(
        ScpImplementation implementation,
        byte[] chaining
    ) =>
        SecureChannelState
            .Create(
                new SessionKeys(SEnc, SMac, SMac),
                SecurityLevel.CMac,
                CryptoService.ScpVersion.Scp02,
                chaining,
                (byte)implementation
            )
            .Value;
}
