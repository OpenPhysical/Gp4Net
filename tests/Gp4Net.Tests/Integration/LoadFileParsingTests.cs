using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Pipeline;
using Gp4Net.Services.GlobalPlatform;
using NUnit.Framework;
using WSCT.ISO7816;
using static Gp4Net.Constants.Constants.GlobalPlatform;

namespace Gp4Net.Tests.Integration;

[TestFixture]
[Category("Integration")]
public class LoadFileParsingTests
{
    private static CommandResponse MakeResponse(string hexData)
    {
        byte[] data = Convert.FromHexString(hexData.Replace(" ", string.Empty));
        return new CommandResponse(
            data,
            StatusWords.SUCCESS,
            new ImmutablePipelineContext(),
            new Dictionary<string, object>()
        );
    }

    private static Func<
        CommandAPDU,
        CancellationToken,
        Task<Result<CommandResponse, SmartCardError>>
    > ResponseExecutor(CommandResponse response)
    {
        return (_, __) =>
            Task.FromResult(Result.Success<CommandResponse, SmartCardError>(response));
    }

    [Test]
    public async Task Parse_ExecutableLoadFiles_WithModules_FromTrace_GpProList()
    {
        // From docs/traces/gp_pro_list_success.txt, response to 84F21002 ... (P1=0x10: load files with modules)
        const string respHex =
            "E3254F07A00000015153509F700101CE02FFFF8408A000000151535041CC08A000000151000000"
            + "E3314F0DA00000016443446F634C6974659F700101CE020100840EA00000016443446F634C69746501CC08A000000151000000"
            + "E31B4F07A00000006202049F700101CE020100CC08A000000151000000"
            + "E31B4F07A00000006202029F700101CE020103CC08A000000151000000";

        var response = MakeResponse(respHex);
        var exec =
            ResponseExecutor(response);

        Result<ImmutableList<ExecutableLoadFile>, SmartCardError> result =
            await Applications.GetExecutableLoadFilesWithModulesAsync(exec);

        _ = result.IsSuccess.Should().BeTrue();
        var elfs = result.Value;

        // Expect at least 4 entries
        _ = elfs.Count.Should().BeGreaterThanOrEqualTo(4);

        // SSD creation package
        var ssdPkg = elfs.FirstOrDefault(e =>
            Convert.ToHexString(e.Aid) == "A0000001515350"
        );
        _ = ssdPkg.Should().NotBeNull();
        _ = ssdPkg!.LifecycleState.Should().Be(LifecycleState.Loaded);
        _ = ssdPkg.VersionString.Should().Be("255.255");
        _ = ssdPkg.AssociatedSecurityDomainAid.HasValue.Should().BeTrue();
        _ = Convert
            .ToHexString(ssdPkg.AssociatedSecurityDomainAid.GetValueOrThrow())
            .Should()
            .Be("A000000151000000");
        // Module present
        _ = ssdPkg.ExecutableModules.Count.Should().BeGreaterThanOrEqualTo(1);
        _ = ssdPkg
            .ExecutableModules.Any(m => Convert.ToHexString(m.Aid) == "A000000151535041")
            .Should()
            .BeTrue();
    }

    [Test]
    public async Task Parse_ExecutableLoadFiles_FromTrace_GpProList_AdditionalEntries()
    {
        // From docs/traces/gp_pro_list_success.txt, response to 84F22002 ... (P1=0x20: load files only)
        const string respHex =
            "E31B4F07A00000015153509F700101CE02FFFFCC08A000000151000000"
            + "E3214F0DA00000016443446F634C6974659F700101CE020100CC08A000000151000000"
            + "E31B4F07A00000006202049F700101CE020100CC08A000000151000000"
            + "E31B4F07A00000006202029F700101CE020103CC08A000000151000000";

        var response = MakeResponse(respHex);
        var exec =
            ResponseExecutor(response);

        Result<ImmutableList<ExecutableLoadFile>, SmartCardError> result =
            await Applications.GetExecutableLoadFilesAsync(exec);

        _ = result.IsSuccess.Should().BeTrue();
        var elfs = result.Value;
        _ = elfs.Count.Should().BeGreaterThanOrEqualTo(4);

        // DocLite package
        var docLite = elfs.FirstOrDefault(e =>
            Convert.ToHexString(e.Aid) == "A00000016443446F634C697465"
        );
        _ = docLite.Should().NotBeNull();
        _ = docLite!.VersionString.Should().Be("1.0");
        _ = docLite.LifecycleState.Should().Be(LifecycleState.Loaded);
        _ = Convert
            .ToHexString(docLite.AssociatedSecurityDomainAid.GetValueOrThrow())
            .Should()
            .Be("A000000151000000");
    }
}
