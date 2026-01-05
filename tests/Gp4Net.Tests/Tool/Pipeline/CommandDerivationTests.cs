using System;
using System.Reflection;
using Gp4Net.Tool.Pipeline;
using NUnit.Framework;

namespace Gp4Net.Tests.Tool.Pipeline;

public class CommandDerivationTests
{
    [Test]
    public void Should_Derive_Command_Name_From_Valid_Input()
    {
        var result = DeriveCommandNameViaReflection("ListReadersCommand");

        Assert.That(result, Is.EqualTo("list-readers"));
    }

    [Test]
    public void Should_Handle_Single_Word_Command()
    {
        var result = DeriveCommandNameViaReflection("InfoCommand");

        Assert.That(result, Is.EqualTo("info"));
    }

    [Test]
    public void Should_Handle_Multi_Word_Command()
    {
        var result = DeriveCommandNameViaReflection("TestSecureChannelCommand");

        Assert.That(result, Is.EqualTo("test-secure-channel"));
    }

    [Test]
    public void Should_Handle_Command_Without_Suffix()
    {
        var result = DeriveCommandNameViaReflection("SimpleTest");

        Assert.That(result, Is.EqualTo("simple-test"));
    }

    [Test]
    public void Should_Handle_Single_Character_Name()
    {
        var result = DeriveCommandNameViaReflection("ACommand");

        Assert.That(result, Is.EqualTo("a"));
    }

    [Test]
    public void Should_Handle_All_Caps_Acronym()
    {
        var result = DeriveCommandNameViaReflection("HTTPSProxyCommand");

        Assert.That(result, Is.EqualTo("h-t-t-p-s-proxy"));
    }

    [Test]
    public void Should_Handle_Empty_After_Suffix_Removal()
    {
        var result = DeriveCommandNameViaReflection("Command");

        Assert.That(result, Is.EqualTo(""));
    }

    [Test]
    public void Should_Handle_Consecutive_Uppercase()
    {
        var result = DeriveCommandNameViaReflection("XMLParserCommand");

        Assert.That(result, Is.EqualTo("x-m-l-parser"));
    }

    [Test]
    public void Should_Handle_Numeric_Characters()
    {
        var result = DeriveCommandNameViaReflection("Scp02AuthCommand");

        Assert.That(result, Is.EqualTo("scp02-auth"));
    }

    [Test]
    public void Should_Handle_Lowercase_Start()
    {
        var result = DeriveCommandNameViaReflection("testCommand");

        Assert.That(result, Is.EqualTo("test"));
    }

    private static string DeriveCommandNameViaReflection(string className)
    {
        var method = typeof(CommandRegistrationService).GetMethod(
            "DeriveCommandName",
            BindingFlags.NonPublic | BindingFlags.Static
        );

        if (method == null)
        {
            throw new InvalidOperationException("DeriveCommandName method not found");
        }

        var result = method.Invoke(null, new object[] { className });
        return result?.ToString() ?? string.Empty;
    }
}
