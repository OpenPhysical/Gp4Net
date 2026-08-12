using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Pipeline;
using Gp4Net.Services.GlobalPlatform;
using NUnit.Framework;
using static Gp4Net.Constants.Constants.GlobalPlatform;

namespace Gp4Net.Tests.Integration;

[TestFixture]
[Category("Integration")]
public class ApplicationStatusParsingTests
{
    private static CommandResponse MakeResponse(string hexData)
    {
        byte[] data = Convert.FromHexString(hexData.Replace(" ", string.Empty));
        return new CommandResponse(
            data,
            0x9000,
            new ImmutablePipelineContext(),
            new Dictionary<string, object>()
        );
    }

    [Test]
    public void Parse_Apps_And_SDs_From_TLV_Response()
    {
        // From docs/traces/gp_pro_list_success.txt: response to 84F28002 ...
        const string resp =
            "E3264F08A0000001510000009F700101C5039EFE80C407A0000001515350CC08A000000151000000";

        var r = MakeResponse(resp);
        Result<ImmutableList<ApplicationInfo>, SmartCardError> parsed =
            Responses.ParseGetStatusResponse(
                r,
                Maybe<byte[]>.From(Convert.FromHexString("A000000151000000"))
            );

        _ = parsed.IsSuccess.Should().BeTrue();
        var list = parsed.Value;

        // Should include ISD AID with lifecycle (0x01) and privileges (C5: 03 9E FE)
        var isd = list.FirstOrDefault(static x => Convert.ToHexString(x.Aid) == "A000000151000000");
        _ = isd.Should().NotBeNull();
        // GP Card Specification v2.3.1, Table 11-6: ISD 0x01 is OP_READY.
        _ = isd!.RawLifecycleState.Should().Be(0x01);
        _ = isd.LifecycleStateString.Should().Be("OpReady");
        _ = isd.Privileges.Should().NotBeEmpty();
        _ = isd.Privileges.Contains(Privilege.SecurityDomain).Should().BeTrue();

        // C4 (Executable Load File AID) is carried on the application entry per Table 11-36.
        // Verify it is captured on the parsed application model.
        _ = isd!.ExecutableLoadFileAid.HasValue.Should().BeTrue();
        _ = Convert
            .ToHexString(isd.ExecutableLoadFileAid.GetValueOrThrow())
            .Should()
            .Be("A0000001515350");
    }
}
