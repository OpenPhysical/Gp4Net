using AwesomeAssertions;
using Gp4Net.Services.Helpers;
using NUnit.Framework;
using static Gp4Net.Constants.Constants.GlobalPlatform;

namespace Gp4Net.Tests.Services;

public class PrivilegeHelpersTests
{
    [Test]
    public void P71PrivilegeFixture_Should_Follow_Tables_11_7_Through_11_9()
    {
        // GP Card Spec 2.3.1, Tables 11-7 through 11-9. In C5 03 9E FE 80,
        // b1 of byte 1 is clear, b1 of byte 2 is clear, and b8 of byte 3 is set.
        var privileges = PrivilegeHelpers.ToList([0x9E, 0xFE, 0x80]);

        _ = privileges.Should().HaveCount(13);
        _ = privileges.Should().Contain(Privilege.TrustedPath);
        _ = privileges.Should().Contain(Privilege.ReceiptGeneration);
        _ = privileges.Should().NotContain(Privilege.MandatedDapVerification);
        _ = privileges.Should().NotContain(Privilege.GlobalService);
    }

    [Test]
    public void Byte3Privileges_Should_RoundTrip_In_MostSignificant_Bits()
    {
        // GP Card Spec 2.3.1, Table 11-9 assigns Receipt Generation through
        // Contactless Self-Activation to b8 through b5.
        Privilege flags =
            Privilege.ReceiptGeneration
            | Privilege.CipheredLoadFileDataBlock
            | Privilege.ContactlessActivation
            | Privilege.ContactlessSelfActivation;

        _ = flags.ToBytes().Should().Equal(0x00, 0x00, 0xF0);
        _ = PrivilegeHelpers.FromBytes([0x00, 0x00, 0xF0]).Value.Should().Be(flags);
    }
}
