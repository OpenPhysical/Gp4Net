using System;
using System.Linq;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Security;
using Gp4Net.Services;
using NUnit.Framework;
using WSCT.ISO7816;

namespace Gp4Net.Tests.Domain;

[TestFixture]
public class CommandMacDataTests
{
    private static SecureChannelState CreateScp02State(SecurityLevel level)
    {
        var masterKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var sequenceCounter = Convert.FromHexString("0013");

        var encKey = CryptoService
            .KeyDerivation.DeriveScp02SessionKey(
                masterKey,
                sequenceCounter,
                Gp4Net.Constants.Constants.Scp.Scp02.KeyDerivationConstants.SEnc
            )
            .Value;
        var macKey = CryptoService
            .KeyDerivation.DeriveScp02SessionKey(
                masterKey,
                sequenceCounter,
                Gp4Net.Constants.Constants.Scp.Scp02.KeyDerivationConstants.SMac
            )
            .Value;
        var rmacKey = CryptoService
            .KeyDerivation.DeriveScp02SessionKey(
                masterKey,
                sequenceCounter,
                Gp4Net.Constants.Constants.Scp.Scp02.KeyDerivationConstants.SrMac
            )
            .Value;

        var sessionKeys = SessionKeys.Create(encKey, macKey, rmacKey).Value;
        var state = SecureChannelState
            .Create(sessionKeys, level, CryptoService.ScpVersion.Scp02, new byte[8], 0x00)
            .Value;
        return state;
    }

    [Test]
    public void Should_Build_Scp02_Cmac_Input_For_Plain_Command()
    {
        var commandBytes = Convert.FromHexString("84F240020A4F0029AA9C8EF87BE9D200");
        var command = new CommandAPDU(commandBytes);
        var state = CreateScp02State(SecurityLevel.CMac);

        var result = CommandMacData.Create(command, state);

        if (result.IsFailure)
        {
            Assert.Fail(result.Error.Message);
        }
        Assert.That(
            Convert.ToHexString(result.Value.CalculationBytes.ToArray()),
            Is.EqualTo("84F240020A4F00")
        );
    }

    [Test]
    public void Should_Build_Scp02_Cmac_Input_For_Encrypted_Command()
    {
        var commandBytes = Convert.FromHexString("84F280021013A84162D6CF3D3EB2037DBFF3A4A09100");
        var command = new CommandAPDU(commandBytes);
        var state = CreateScp02State(SecurityLevel.CDecryption);
        TestContext.Out.WriteLine("S-ENC: " + Convert.ToHexString(state.SessionKeys.SEnc));

        var result = CommandMacData.Create(command, state);

        if (result.IsFailure)
        {
            Assert.Fail(result.Error.Message);
        }
        Assert.That(
            Convert.ToHexString(result.Value.CalculationBytes.ToArray()),
            Is.EqualTo("84F280020A4F00")
        );

        var chainingIcv = Convert.FromHexString("D0C159C17E6D3F9A");
        var encryptedIcv = CryptoService
            .Mac.EncryptScp02Icv(chainingIcv, state.SessionKeys.SMac)
            .Value;
        var expectedMac = CryptoService
            .Mac.CalculateScp02CommandMac(
                state.SessionKeys.SMac,
                result.Value.CalculationBytes.ToArray(),
                encryptedIcv
            )
            .Value;

        Assert.That(Convert.ToHexString(expectedMac), Is.EqualTo("B2037DBFF3A4A091"));
    }

    [Test]
    public void Should_Remove_Scp02_Command_Security_With_Encryption()
    {
        var commandBytes = Convert.FromHexString("84F280021013A84162D6CF3D3EB2037DBFF3A4A09100");
        var command = new CommandAPDU(commandBytes);
        var state = CreateScp02State(SecurityLevel.CDecryption);
        var macChaining = MacChainingState
            .Create(Convert.FromHexString("D0C159C17E6D3F9A"), CryptoService.ScpVersion.Scp02, 0x00)
            .Value;
        var seededState = state with { MacChaining = macChaining };

        var result = ScpService.Security.RemoveCommandSecurity(command, seededState);

        if (result.IsFailure)
        {
            Assert.Fail(result.Error.Message);
        }

        Assert.That(result.Value.Item1.Udc, Is.EqualTo(new byte[] { 0x4F, 0x00 }));
    }
}
