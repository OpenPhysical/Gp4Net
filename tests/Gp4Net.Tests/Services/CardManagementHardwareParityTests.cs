using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Pipeline;
using Gp4Net.Services.GlobalPlatform;
using Gp4Net.Transport;
using NUnit.Framework;
using WSCT.ISO7816;

namespace Gp4Net.Tests.Services;

public class CardManagementHardwareParityTests
{
    [Test]
    public async Task InstallCapFile_LoadsBinaryComponentsInsteadOfZipArchive()
    {
        byte[] archive = await File.ReadAllBytesAsync(
            Path.GetFullPath(Path.Combine(
                TestContext.CurrentContext.TestDirectory,
                "..", "..", "..", "..", "applets", "OpenFIPS201-v1_10_2.cap"
            ))
        );
        var commands = new List<byte[]>();

        var result = await CardManagement.InstallCapFileAsync(
            archive,
            Maybe<byte[]>.None,
            installApplets: false,
            makeSelectable: false,
            (command, _) =>
            {
                commands.Add(command.BinaryCommand);
                return Task.FromResult(Result.Success<CommandResponse, SmartCardError>(CommandResponse.Success()));
            }
        );

        Assert.That(result.IsSuccess, Is.True, () => result.Error.Message);
        byte[] firstLoad = commands.First(command => command[1] == 0xE8);
        Assert.That(firstLoad, Does.Contain((byte)0xC4));
        Assert.That(firstLoad, Does.Not.Contain((byte)0x50).And.Not.Contain((byte)0x4B));
        Assert.That(
            firstLoad.AsSpan().IndexOf(new byte[] { 0x01, 0x00, 0x13, 0xDE, 0xCA, 0xFF, 0xED }),
            Is.GreaterThanOrEqualTo(0)
        );
    }
}
