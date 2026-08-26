using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Domain;
using Gp4Net.Tool.Commands.Applet;
using NUnit.Framework;
using static Gp4Net.Constants.Constants.GlobalPlatform;

namespace Gp4Net.Tool.Tests.Commands;

public class ApplicationTableBuilderTests
{
    private static readonly ApplicationInfo App = new(
        [0xA0, 0, 0, 0, 1], 0x07, ImmutableList<Privilege>.Empty, ApplicationType.Application
    );
    private static readonly ApplicationInfo Package = new(
        [0xA0, 0, 0, 0, 2], 0x01, ImmutableList<Privilege>.Empty,
        ApplicationType.ExecutableLoadFile, Maybe<string>.None
    );

    [TestCase("apps", "A000000001")]
    [TestCase("applets", "A000000001")]
    [TestCase("packages", "A000000002")]
    public void BuildApplicationRows_AppliesRegisteredFilters(string filter, string aid)
    {
        var rows = ApplicationTableBuilder.BuildApplicationRows(
            [App, Package], filter: filter
        ).OfType<ApplicationTableBuilder.ApplicationDataRow>().ToList();

        Assert.That(rows, Has.Count.EqualTo(1));
        Assert.That(rows[0].Aid, Does.Contain(aid));
    }

    [Test]
    public void MachineReadableFormatsContainNoDisplayMarkup()
    {
        Assert.That(ApplicationTableBuilder.ToJson([App]), Does.Not.Contain("[cyan]"));
        Assert.That(ApplicationTableBuilder.ToCsv([App]), Does.StartWith("Type,AID"));
    }
}
