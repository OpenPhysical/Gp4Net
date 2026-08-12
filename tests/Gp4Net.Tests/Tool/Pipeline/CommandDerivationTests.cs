using Gp4Net.Tool.Infrastructure;
using NUnit.Framework;

namespace Gp4Net.Tests.Tool.Pipeline;

public class CommandDerivationTests
{
    [Test]
    public void Should_Derive_Command_Name_From_Valid_Input()
    {
        var result = CommandCatalog.DeriveCommandName("ListReadersCommand");

        Assert.That(result, Is.EqualTo("list-readers"));
    }

    [Test]
    public void Should_Handle_Single_Word_Command()
    {
        var result = CommandCatalog.DeriveCommandName("InfoCommand");

        Assert.That(result, Is.EqualTo("info"));
    }

    [Test]
    public void Should_Handle_Multi_Word_Command()
    {
        var result = CommandCatalog.DeriveCommandName("TestSecureChannelCommand");

        Assert.That(result, Is.EqualTo("test-secure-channel"));
    }

    [Test]
    public void Should_Handle_Command_Without_Suffix()
    {
        var result = CommandCatalog.DeriveCommandName("SimpleTest");

        Assert.That(result, Is.EqualTo("simple-test"));
    }

    [Test]
    public void Should_Handle_Single_Character_Name()
    {
        var result = CommandCatalog.DeriveCommandName("ACommand");

        Assert.That(result, Is.EqualTo("a"));
    }

    [Test]
    public void Should_Handle_All_Caps_Acronym()
    {
        var result = CommandCatalog.DeriveCommandName("HTTPSProxyCommand");

        Assert.That(result, Is.EqualTo("h-t-t-p-s-proxy"));
    }

    [Test]
    public void Should_Handle_Empty_After_Suffix_Removal()
    {
        var result = CommandCatalog.DeriveCommandName("Command");

        Assert.That(result, Is.EqualTo(""));
    }

    [Test]
    public void Should_Handle_Consecutive_Uppercase()
    {
        var result = CommandCatalog.DeriveCommandName("XMLParserCommand");

        Assert.That(result, Is.EqualTo("x-m-l-parser"));
    }

    [Test]
    public void Should_Handle_Numeric_Characters()
    {
        var result = CommandCatalog.DeriveCommandName("Scp02AuthCommand");

        Assert.That(result, Is.EqualTo("scp02-auth"));
    }

    [Test]
    public void Should_Handle_Lowercase_Start()
    {
        var result = CommandCatalog.DeriveCommandName("testCommand");

        Assert.That(result, Is.EqualTo("test"));
    }
}
