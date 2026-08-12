using System;
using AwesomeAssertions;
using Gp4Net.Domain.CardInfo;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.CardInfo;

[TestFixture]
public class KeyInformationTemplateTests
{
    [Test]
    public void Should_Parse_Actual_Component_Length()
    {
        // GP Card Specification v2.3.1, section 11.3.3.1.1 and Table 11-28.
        byte[] data = Convert.FromHexString("E006C00410028820");

        var result = KeyInformationTemplate.Parse(data);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Keys.Should().ContainSingle();
        KeyEntry key = result.Value.Keys[0];
        _ = key.KeyId.Should().Be(0x10);
        _ = key.KeyVersion.Should().Be(0x02);
        _ = key.PrimaryKeyType.HasValue.Should().BeTrue();
        _ = key.PrimaryKeyType.Value.Should().Be(KeyType.Aes);
        _ = key.KeyLength.Should().Be(256);
    }

    [Test]
    public void Should_Parse_Multiple_Components_As_Type_Length_Pairs()
    {
        // GP Card Specification v2.3.1, Table 11-28.
        byte[] data = Convert.FromHexString("E008C006200380088810");

        var result = KeyInformationTemplate.Parse(data);

        _ = result.IsSuccess.Should().BeTrue();
        KeyEntry key = result.Value.Keys[0];
        _ = key.KeyTypes.Should().Equal(KeyType.Des, KeyType.Aes);
        _ = key.Components[0].Length.Should().Be(0x08);
        _ = key.Components[1].Length.Should().Be(0x10);
    }

    [Test]
    public void Should_Treat_Historical_Key_Type_Values_As_Unknown()
    {
        // GP Card Specification v2.3.1, Table 11-16: 81 through 84 are reserved.
        byte[] data = Convert.FromHexString("E006C00401018110");

        var result = KeyInformationTemplate.Parse(data);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Keys[0].PrimaryKeyType.HasNoValue.Should().BeTrue();
        _ = result.Value.Keys[0].Components[0].Type.Should().Be(0x81);
    }

    [Test]
    public void Should_Parse_All_C0_Key_Information_Data_Objects()
    {
        // GP Card Specification v2.3.1, section 11.3.3.1.1: each key is introduced by C0.
        byte[] data = Convert.FromHexString("E00CC00401018810C00402018810");

        var result = KeyInformationTemplate.Parse(data);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Keys.Should().HaveCount(2);
        _ = result.Value.Keys[1].KeyId.Should().Be(0x02);
    }

    [Test]
    public void Should_Format_Key_Using_Reported_Length()
    {
        // GP Card Specification v2.3.1, Table 11-28: component length is carried on the wire.
        var result = KeyInformationTemplate.Parse(Convert.FromHexString("E006C00401028818"));

        string output = result.Value.Keys[0].ToString();

        _ = output.Should().Contain("Version: 2 (0x02)");
        _ = output.Should().Contain("ID: 1 (0x01)");
        _ = output.Should().Contain("type: AES");
        _ = output.Should().Contain("length: 24");
    }

    [Test]
    public void Should_Use_Table_11_16_Key_Type_Names()
    {
        // GP Card Specification v2.3.1, Table 11-16.
        _ = KeyType.Des.ToFriendlyString().Should().Be("DES");
        _ = KeyType.Aes.ToFriendlyString().Should().Be("AES");
        _ = KeyType.PreSharedTls.ToFriendlyString().Should().Be("TLS-PSK");
        _ = KeyType.EccPublic.ToFriendlyString().Should().Be("ECC-PUBLIC");
        _ = KeyType.Unknown.ToFriendlyString().Should().Be("Unknown(0x00)");
    }

    [Test]
    public void Should_Reject_Empty_Data()
    {
        var result = KeyInformationTemplate.Parse([]);

        _ = result.IsFailure.Should().BeTrue();
    }

    [Test]
    public void Should_Reject_Key_Without_Component()
    {
        // GP Card Specification v2.3.1, Tables 11-28 and 11-29: a component is mandatory.
        var result = KeyInformationTemplate.Parse(Convert.FromHexString("E004C0020101"));

        _ = result.IsFailure.Should().BeTrue();
    }
}
