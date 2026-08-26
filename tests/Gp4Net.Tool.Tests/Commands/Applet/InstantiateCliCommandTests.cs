using System;
using Gp4Net.Tool.Commands.Applet;
using NUnit.Framework;

namespace Gp4Net.Tool.Tests.Commands.Applet;

public class InstantiateCliCommandTests
{
    [Test]
    public void CreateInstallCommandWrapsApplicationParametersInC9Template()
    {
        var settings = new InstantiateCliCommand.Settings
        {
            PackageAid = "A000000647",
            AppletAid = "A0000006472F0001",
            InstallParams = "A102F5",
            MakeSelectable = true,
        };

        var command = InstantiateCliCommand.CreateInstallCommand(settings);

        Assert.That(command.IsSuccess, Is.True);
        byte[] bytes = command.Value.ToBytes();
        Assert.That(bytes, Does.Contain(0xC9));
        Assert.That(
            Convert.ToHexString(bytes),
            Does.Contain("05C903A102F5")
        );
        Assert.That(bytes[2], Is.EqualTo(0x0C));
    }

    [Test]
    public void CreateInstallCommandEncodesNamedPrivileges()
    {
        var settings = new InstantiateCliCommand.Settings
        {
            PackageAid = "A000000647",
            AppletAid = "A0000006472F0001",
            Privileges = ["card-reset"],
        };

        var command = InstantiateCliCommand.CreateInstallCommand(settings);

        Assert.That(command.IsSuccess, Is.True);
        Assert.That(Convert.ToHexString(command.Value.ToBytes()), Does.Contain("0104"));
    }

    [Test]
    public void CreateInstallCommandAcceptsDocumentedCommaSeparatedPrivileges()
    {
        var settings = new InstantiateCliCommand.Settings
        {
            PackageAid = "A000000647",
            AppletAid = "A0000006472F0001",
            Privileges = ["security-domain,delegated-management"],
        };

        var command = InstantiateCliCommand.CreateInstallCommand(settings);

        Assert.That(command.IsSuccess, Is.True);
        Assert.That(Convert.ToHexString(command.Value.ToBytes()), Does.Contain("01A0"));
        Assert.That(settings.Validate().Successful, Is.True);
    }
}
