using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Pipeline;
using Gp4Net.Services.GlobalPlatform;
using NUnit.Framework;

namespace Gp4Net.Tests.Services.GlobalPlatform;

[TestFixture]
[Category("Unit")]
public class ApplicationsGetStatusTests
{
    [Test]
    public async Task GetApplications_Should_RequestNextOccurrence_After6310()
    {
        // GP Card Specification v2.3.1, Table 11-34 and Table 11-38.
        var responses = new Queue<CommandResponse>(
            [
                Response("E3104F05A0000000019F700107C503000000", 0x6310),
                Response("E3104F05A0000000029F700107C503000000", 0x9000),
            ]
        );
        var p2Values = new List<byte>();

        var result = await Applications.GetApplicationsAndSecurityDomainsAsync(
            (command, _) =>
            {
                p2Values.Add(command.P2);
                return Task.FromResult(
                    Result.Success<CommandResponse, SmartCardError>(responses.Dequeue())
                );
            },
            CancellationToken.None
        );

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Should().HaveCount(2);
        _ = p2Values.Should().Equal(0x02, 0x03);
    }

    [Test]
    public async Task GetLoadFilesWithModules_ReassemblesHardwareTlvSplitAcross6310Pages()
    {
        // NXP P71D321/JCOP4 capture. The first page ends in the middle of E3 { 4F ... }.
        // GP Card Specification v2.3.1, section 11.4.2.2 requires concatenating the
        // response data before parsing when SW=6310 requests the next occurrence.
        const string firstPage =
            "E3254F07A00000015153509F700101CE02FFFF8408A000000151535041CC08A000000151000000"
            + "E3314F0DA00000016443446F634C6974659F700101CE020100840EA00000016443446F634C69746501CC08A000000151000000"
            + "E31B4F07A00000006202049F700101CE020100CC08A000000151000000"
            + "E31B4F07A00000006202029F700101CE020103CC08A000000151000000"
            + "E32A4F09A000000308000010009F700101CE02010A840BA000000308000010000100CC08A000000151000000"
            + "E32A4F0AA00000038200110001009F700101CE020100840AA0000003820011000101CC08A000000151000000"
            + "E32C4F";
        const string secondPage =
            "06D276000124019F700101CE0201008410D276000124010304AFAF000000000000CC08A000000151000000";
        var responses = new Queue<CommandResponse>(
            [Response(firstPage, 0x6310), Response(secondPage, 0x9000)]
        );
        var p2Values = new List<byte>();

        var result = await Applications.GetExecutableLoadFilesWithModulesAsync(
            (command, _) =>
            {
                p2Values.Add(command.P2);
                return Task.FromResult(
                    Result.Success<CommandResponse, SmartCardError>(responses.Dequeue())
                );
            },
            CancellationToken.None
        );

        _ = result.IsSuccess.Should().BeTrue(result.IsFailure ? result.Error.Message : string.Empty);
        _ = p2Values.Should().Equal(0x02, 0x03);
        var smartPgp = result.Value.Should().ContainSingle(file =>
            Convert.ToHexString(file.Aid) == "D27600012401"
        ).Subject;
        _ = smartPgp.VersionString.Should().Be("1.0");
        _ = smartPgp.ExecutableModules.Should().ContainSingle(module =>
            Convert.ToHexString(module.Aid) == "D276000124010304AFAF000000000000"
        );
        _ = Convert.ToHexString(smartPgp.AssociatedSecurityDomainAid.GetValueOrThrow())
            .Should().Be("A000000151000000");
    }

    private static CommandResponse Response(string data, ushort statusWord) =>
        new(
            Convert.FromHexString(data),
            statusWord,
            ImmutablePipelineContext.Empty,
            new Dictionary<string, object>()
        );
}
