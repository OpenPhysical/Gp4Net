using System.Collections.Generic;
using Gp4Net.Tool.Commands.Card;
using NUnit.Framework;

namespace Gp4Net.Tool.Tests.Commands.Card;

[TestFixture]
public sealed class GetIsdDataCommandTests
{
    [Test]
    public void TryCreateOpid_MissingOptionalObjects_ReturnsNoneWithoutParsingDisplayText()
    {
        var rawResults = new Dictionary<string, byte[]>
        {
            ["Card Data"] = [0x66, 0x00],
        };

        var result = GetIsdDataCommand.TryCreateOpid(rawResults);

        Assert.That(result.HasNoValue, Is.True);
    }
}
