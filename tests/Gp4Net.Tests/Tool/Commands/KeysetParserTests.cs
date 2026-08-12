using System;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Keys;
using Gp4Net.Services;
using Gp4Net.Tool.Commands.Common;
using NUnit.Framework;
using static Gp4Net.Cryptography.CryptoOperations;

namespace Gp4Net.Tests.Tool.Commands;

[TestFixture]
public class KeysetParserTests
{
    [Test]
    public void ParseKeysetSpecification_Should_Return_GP_Test_Keys_When_Empty()
    {
        var result = KeysetParser.ParseKeysetSpecification("", ScpVersion.Scp03, 0x00);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value, Is.Not.Null);
        Assert.That(result.Value.KeyVersion, Is.EqualTo(0x00));
    }

    [Test]
    public void ParseKeysetSpecification_Should_Return_GP_Test_Keys_When_gp_test()
    {
        var result = KeysetParser.ParseKeysetSpecification("gp_test", ScpVersion.Scp03, 0x00);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value, Is.Not.Null);
        Assert.That(result.Value.KeyVersion, Is.EqualTo(0x00));
    }

    [Test]
    public void ParseKeysetSpecification_Should_Parse_Single_Hex_Key()
    {
        var testKey = "404142434445464748494A4B4C4D4E4F";

        var result = KeysetParser.ParseKeysetSpecification(testKey, ScpVersion.Scp03, 0x00);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value, Is.Not.Null);
        Assert.That(result.Value.KeyVersion, Is.EqualTo(0x00));
    }

    [Test]
    public void ParseKeysetSpecification_Should_Parse_Three_Key_Format()
    {
        var encKey = "404142434445464748494A4B4C4D4E4F";
        var macKey = "505152535455565758595A5B5C5D5E5F";
        var dekKey = "606162636465666768696A6B6C6D6E6F";
        var keysetSpec = $"{encKey}:{macKey}:{dekKey}";

        var result = KeysetParser.ParseKeysetSpecification(keysetSpec, ScpVersion.Scp03, 0x00);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value, Is.Not.Null);
        Assert.That(result.Value.KeyVersion, Is.EqualTo(0x00));
    }

    [Test]
    public void ParseKeysetSpecification_Should_Fail_On_Invalid_Hex()
    {
        var invalidHex = "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG";

        var result = KeysetParser.ParseKeysetSpecification(invalidHex, ScpVersion.Scp03, 0x00);

        Assert.That(result.IsFailure, Is.True);
    }

    [Test]
    public void ParseKeysetSpecification_Should_Fail_On_Wrong_Three_Key_Count()
    {
        var invalidSpec = "404142434445464748494A4B4C4D4E4F:505152535455565758595A5B5C5D5E5F";

        var result = KeysetParser.ParseKeysetSpecification(invalidSpec, ScpVersion.Scp03, 0x00);

        Assert.That(result.IsFailure, Is.True);
    }

    [Test]
    public void ParseKeysetSpecification_Should_Work_With_Different_Key_Versions()
    {
        var testKey = "404142434445464748494A4B4C4D4E4F";

        var result = KeysetParser.ParseKeysetSpecification(testKey, ScpVersion.Scp03, 0x01);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value.KeyVersion, Is.EqualTo(0x01));
    }

    [Test]
    public void ParseKeysetSpecification_Should_Work_With_Scp02()
    {
        var testKey = "404142434445464748494A4B4C4D4E4F";

        var result = KeysetParser.ParseKeysetSpecification(testKey, ScpVersion.Scp02, 0x00);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value, Is.Not.Null);
    }

    [Test]
    public void ParseRawKeysetSpecification_Should_Return_GP_Test_Keys_When_Empty()
    {
        var result = KeysetParser.ParseRawKeysetSpecification("", 0x00);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value, Is.Not.Null);
        Assert.That(result.Value.KeyVersion, Is.EqualTo(0x00));
    }

    [Test]
    public void ParseRawKeysetSpecification_Should_Parse_Single_Hex_Key()
    {
        var testKey = "404142434445464748494A4B4C4D4E4F";

        var result = KeysetParser.ParseRawKeysetSpecification(testKey, 0x00);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value, Is.Not.Null);
    }

    [Test]
    public void ParseRawKeysetSpecification_Should_Parse_Three_Key_Format()
    {
        var encKey = "404142434445464748494A4B4C4D4E4F";
        var macKey = "505152535455565758595A5B5C5D5E5F";
        var dekKey = "606162636465666768696A6B6C6D6E6F";
        var keysetSpec = $"{encKey}:{macKey}:{dekKey}";

        var result = KeysetParser.ParseRawKeysetSpecification(keysetSpec, 0x00);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value, Is.Not.Null);
    }

    [Test]
    public void ParseRawKeysetSpecification_Should_Handle_Case_Insensitive_gp_test()
    {
        var result1 = KeysetParser.ParseRawKeysetSpecification("GP_TEST", 0x00);
        var result2 = KeysetParser.ParseRawKeysetSpecification("Gp_Test", 0x00);

        Assert.That(result1.IsSuccess, Is.True);
        Assert.That(result2.IsSuccess, Is.True);
    }

    [Test]
    public void ParseKeysetSpecification_Should_Fail_On_Too_Short_Key()
    {
        var shortKey = "404142";

        var result = KeysetParser.ParseKeysetSpecification(shortKey, ScpVersion.Scp03, 0x00);

        Assert.That(result.IsFailure, Is.True);
    }
}
