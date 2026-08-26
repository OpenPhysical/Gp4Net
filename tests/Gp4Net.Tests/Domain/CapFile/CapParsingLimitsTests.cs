using System.IO;
using System.IO.Compression;
using Gp4Net.Domain.CapFile;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.CapFile;

public class CapParsingLimitsTests
{
    [Test]
    public void Parse_RejectsArchiveAboveConfiguredLimit()
    {
        var limits = CapParsingLimits.Default with { MaxArchiveBytes = 3 };
        var result = CapFileStructure.Parse([1, 2, 3, 4], limits);

        Assert.That(result.IsFailure, Is.True);
        Assert.That(result.Error.Message, Does.Contain("archive").IgnoreCase);
    }

    [Test]
    public void Parse_RejectsTooManyEntriesBeforeAcceptingArchive()
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            archive.CreateEntry("a");
            archive.CreateEntry("b");
        }

        var limits = CapParsingLimits.Default with { MaxEntries = 1 };
        var result = CapFileStructure.Parse(stream.ToArray(), limits);

        Assert.That(result.IsFailure, Is.True);
        Assert.That(result.Error.Message, Does.Contain("entries").IgnoreCase);
    }
}
