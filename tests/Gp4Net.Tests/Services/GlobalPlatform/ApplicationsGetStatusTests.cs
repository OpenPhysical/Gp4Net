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

    private static CommandResponse Response(string data, ushort statusWord) =>
        new(
            Convert.FromHexString(data),
            statusWord,
            ImmutablePipelineContext.Empty,
            new Dictionary<string, object>()
        );
}
