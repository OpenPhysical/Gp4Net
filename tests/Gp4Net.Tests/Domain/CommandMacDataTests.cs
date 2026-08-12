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
    private static SecureChannelState CreateScp02State(
        SecurityLevel level,
        byte implementation = 0x00
    )
    {
        var masterKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var sequenceCounter = Convert.FromHexString("0013");

        var encKey = CryptoOperations
            .KeyDerivation.DeriveScp02SessionKey(
                masterKey,
                sequenceCounter,
                Gp4Net.Constants.Constants.Scp.Scp02.KeyDerivationConstants.SEnc
            )
            .Value;
        var macKey = CryptoOperations
            .KeyDerivation.DeriveScp02SessionKey(
                masterKey,
                sequenceCounter,
                Gp4Net.Constants.Constants.Scp.Scp02.KeyDerivationConstants.SMac
            )
            .Value;
        var rmacKey = CryptoOperations
            .KeyDerivation.DeriveScp02SessionKey(
                masterKey,
                sequenceCounter,
                Gp4Net.Constants.Constants.Scp.Scp02.KeyDerivationConstants.SrMac
            )
            .Value;

        var sessionKeys = SessionKeys.Create(encKey, macKey, rmacKey).Value;
        var state = SecureChannelState
            .Create(
                sessionKeys,
                level,
                CryptoOperations.ScpVersion.Scp02,
                new byte[8],
                implementation
            )
            .Value;
        return state;
    }

    [Test]
    public void Should_Keep_Scp02_SMac_And_SRMac_Distinct()
    {
        // GP Card Spec 2.3.1, E.4.1: S-MAC uses 01 01 and S-RMAC uses 01 02.
        var state = CreateScp02State(SecurityLevel.RMac);

        Assert.That(state.SessionKeys.SrMac, Is.Not.EqualTo(state.SessionKeys.SMac));
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
        var state = CreateScp02State(SecurityLevel.CDecryption, implementation: 0x10);
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
        var encryptedIcv = CryptoOperations
            .Mac.EncryptScp02Icv(chainingIcv, state.SessionKeys.SMac)
            .Value;
        var expectedMac = CryptoOperations
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
        var state = CreateScp02State(SecurityLevel.CDecryption, implementation: 0x10);
        var macChaining = MacChainingState
            .Create(
                Convert.FromHexString("D0C159C17E6D3F9A"),
                CryptoOperations.ScpVersion.Scp02,
                0x00
            )
            .Value;
        var seededState = state with { MacChaining = macChaining };

        var result = ScpOperations.Security.RemoveCommandSecurity(command, seededState);

        if (result.IsFailure)
        {
            Assert.Fail(result.Error.Message);
        }

        Assert.That(result.Value.Item1.Udc, Is.EqualTo(new byte[] { 0x4F, 0x00 }));
    }

    [Test]
    public void Should_Not_Encrypt_Scp02_Icv_When_Implementation_B5_Is_Clear()
    {
        // GP Card Specification v2.3.1, Table E-1 and E.3.4: i.b5=0 leaves the
        // preceding C-MAC unencrypted when it becomes the next command's ICV.
        var command = new CommandAPDU(Convert.FromHexString("80CA9F7F00"));
        var state = CreateScp02State(SecurityLevel.CMac, implementation: 0x00);
        var chaining = MacChainingState
            .Create(
                Convert.FromHexString("D0C159C17E6D3F9A"),
                CryptoOperations.ScpVersion.Scp02,
                0x00
            )
            .Value;
        var seededState = state with { MacChaining = chaining };

        var secured = ScpOperations.Security.ApplyCommandSecurity(command, seededState).Value;
        var removed = ScpOperations.Security.RemoveCommandSecurity(
            secured.securedCommand,
            seededState
        );

        Assert.That(removed.IsSuccess, Is.True);
        Assert.That(
            removed.Value.plaintextCommand.BinaryCommand,
            Is.EqualTo(command.BinaryCommand)
        );
    }

    [Test]
    public void Should_Reject_Tampered_Scp02_Command_Mac_Without_Disclosing_Expected_Mac()
    {
        // GP Card Specification v2.3.1, E.5.1.3: a failed C-MAC check returns
        // security status not satisfied and does not expose the expected MAC.
        var command = new CommandAPDU(Convert.FromHexString("80CA9F7F00"));
        var state = CreateScp02State(SecurityLevel.CMac);
        var secured = ScpOperations
            .Security.ApplyCommandSecurity(command, state)
            .Value.securedCommand;
        byte[] tampered = secured.BinaryCommand.ToArray();
        tampered[^2] ^= 0x01;

        var result = ScpOperations.Security.RemoveCommandSecurity(new CommandAPDU(tampered), state);

        Assert.That(result.IsFailure, Is.True);
        Assert.That(result.Error.Message, Does.Not.Contain("expected"));
    }
}
