using System;
using System.IO;
using Gp4Net.CardEmulator.Services;
using Gp4Net.CardEmulator.Core;
using Gp4Net.Domain.CapFile;
using NUnit.Framework;

namespace Gp4Net.CardEmulator.Tests.Functional;

public class LoadFileDataBlockValidationTests
{
    [Test]
    public void RejectsZipArchiveWrappedAsLoadFileDataBlock()
    {
        byte[] invalid = [0xC4, 0x07, 0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x00];

        Assert.That(VirtualCard.ValidateLoadFileDataBlock(invalid).IsFailure, Is.True);
    }

    [Test]
    public void AcceptsCapHeaderComponentAtStartOfLoadFileDataBlock()
    {
        byte[] valid =
        [
            0xC4,
            0x0D,
            0x01,
            0x00,
            0x0A,
            0xDE,
            0xCA,
            0xFF,
            0xED,
            0x01,
            0x02,
            0x00,
            0x01,
            0x00,
            0x00,
        ];

        Assert.That(VirtualCard.ValidateLoadFileDataBlock(valid).IsSuccess, Is.True);
    }

    [Test]
    public void ParsesExpandedHardwareLoadStreamFromRealCap()
    {
        string capPath = Path.GetFullPath(
            Path.Combine(
                TestContext.CurrentContext.TestDirectory,
                "../../../../applets/OpenFIPS201-v1_10_2.cap"
            )
        );
        var structure = CapFileStructure.Parse(File.ReadAllBytes(capPath));
        Assert.That(structure.IsSuccess, Is.True);

        var result = new EmulatorCapFiles().ProcessLoadFileDataBlockPayload(
            structure.Value.ToBinaryFormat()
        );

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(
            result.Value.Aid,
            Is.EqualTo(Convert.FromHexString("A00000030800001000"))
        );
    }
}
