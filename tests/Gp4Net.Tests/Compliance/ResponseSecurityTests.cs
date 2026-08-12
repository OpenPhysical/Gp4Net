using System;
using AwesomeAssertions;
using Gp4Net.Constants;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Services;
using Gp4Net.Transport;
using NUnit.Framework;
using WSCT.ISO7816;

namespace Gp4Net.Tests.Compliance;

[TestFixture]
[Category("GpCompliance")]
public class ResponseSecurityTests
{
    private static readonly byte[] SEnc = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
    private static readonly byte[] SMac = Convert.FromHexString("0102030405060708090A0B0C0D0E0F10");
    private static readonly byte[] SRMac = Convert.FromHexString(
        "102030405060708090A0B0C0D0E0F000"
    );

    [Test]
    public void Should_Use_Independent_Scp02_Response_Mac_Chaining()
    {
        // GP Card Specification v2.3.1, Appendix E.3.2 and E.4.5.
        byte[] authenticationMac = Convert.FromHexString("1122334455667788");
        SecureChannelState state = CreateScp02State(authenticationMac);
        var command = new CommandAPDU(Convert.FromHexString("80CA9F7F00"));

        var protectedCommand = ScpService.Security.ApplyCommandSecurity(command, state).Value;

        byte[] responseData = Convert.FromHexString("0102");
        byte[] status = Convert.FromHexString("9000");
        byte[] rMacInput = Convert.FromHexString("80CA9F7F000201029000");
        byte[] rMac = CryptoService
            .Mac.CalculateScp02ResponseMac(SRMac, rMacInput, authenticationMac)
            .Value;
        var securedResponse = new ResponseAPDU([.. responseData, .. rMac, .. status]);

        var result = ScpService.Security.RemoveResponseSecurity(
            securedResponse,
            protectedCommand.newState
        );

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.plaintextResponse.ToBytes().Should().Equal([.. responseData, .. status]);
        _ = result.Value.newState.ResponseMacChainingValue.Should().Equal(rMac);
        _ = result
            .Value.newState.MacChainingValue.Should()
            .Equal(protectedCommand.newState.MacChainingValue);
    }

    [Test]
    public void Should_Verify_Scp02_Error_Response_Mac()
    {
        // GP Card Specification v2.3.1, Appendix E.4.5: errors use 00 and status bytes.
        byte[] authenticationMac = Convert.FromHexString("1122334455667788");
        SecureChannelState state = CreateScp02State(authenticationMac);
        var command = new CommandAPDU(Convert.FromHexString("80CA9F7F00"));
        SecureChannelState commandState = ScpService
            .Security.ApplyCommandSecurity(command, state)
            .Value.newState;
        byte[] rMacInput = Convert.FromHexString("80CA9F7F00006A80");
        byte[] rMac = CryptoService
            .Mac.CalculateScp02ResponseMac(SRMac, rMacInput, authenticationMac)
            .Value;
        var securedResponse = new ResponseAPDU([.. rMac, 0x6A, 0x80]);

        var result = ScpService.Security.RemoveResponseSecurity(securedResponse, commandState);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.plaintextResponse.ToBytes().Should().Equal(0x6A, 0x80);
        _ = result.Value.newState.ResponseMacChainingValue.Should().Equal(rMac);
    }

    [Test]
    public void Should_Verify_Eight_Byte_Scp03_Response_Mac_In_S8_Mode()
    {
        // SCP03 Amendment D v1.2, section 6.2.5: S8 responses carry eight MAC bytes.
        byte[] chaining = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
        SecureChannelState state = SecureChannelState
            .Create(
                new SessionKeys(SEnc, SMac, SRMac),
                SecurityLevel.RMac,
                CryptoService.ScpVersion.Scp03,
                chaining,
                (byte)ScpImplementation.Scp03I20
            )
            .Value;
        byte[] responseWithoutMac = Convert.FromHexString("01029000");
        byte[] fullMac = CryptoService
            .ScpOperations.Scp03.CalculateResponseMac(responseWithoutMac, SRMac, chaining)
            .Value;
        var securedResponse = new ResponseAPDU([0x01, 0x02, .. fullMac[..8], 0x90, 0x00]);

        var result = ScpService.Security.RemoveResponseSecurity(securedResponse, state);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.plaintextResponse.ToBytes().Should().Equal(responseWithoutMac);
        _ = result.Value.newState.MacChainingValue.Should().Equal(chaining);
    }

    private static SecureChannelState CreateScp02State(byte[] chaining) =>
        SecureChannelState
            .Create(
                new SessionKeys(SEnc, SMac, SRMac),
                SecurityLevel.CMac | SecurityLevel.RMac,
                CryptoService.ScpVersion.Scp02,
                chaining,
                (byte)ScpImplementation.Scp02I15
            )
            .Value;
}
