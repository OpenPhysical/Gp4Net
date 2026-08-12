using AwesomeAssertions;
using Gp4Net.Domain;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain;

[TestFixture]
public class GlobalPlatformLifecycleTests
{
    /// <summary>
    /// GP Card Specification v2.3.1, Table 11-4 leaves b7 through b4 application-specific.
    /// </summary>
    [Test]
    public void Should_Preserve_Application_Specific_State_Bits()
    {
        const byte state = 0x77;

        _ = GlobalPlatformLifecycle.IsApplicationState(state).Should().BeTrue();
        _ = GlobalPlatformLifecycle
            .DescribeApplicationState(state)
            .Should()
            .Be("ApplicationSpecific(0x77)");
    }

    /// <summary>
    /// GP Card Specification v2.3.1, Table 11-4 defines LOCKED by b8, b2, and b1.
    /// </summary>
    [TestCase(0x83)]
    [TestCase(0xFF)]
    public void Should_Recognize_Application_Locked_Bit_Pattern(byte state)
    {
        _ = GlobalPlatformLifecycle.IsApplicationState(state).Should().BeTrue();
        _ = GlobalPlatformLifecycle.DescribeApplicationState(state).Should().Be("Locked");
    }

    /// <summary>
    /// GP Card Specification v2.3.1, Table 11-5 requires b7 through b5 to be zero for LOCKED.
    /// </summary>
    [Test]
    public void Should_Reject_Security_Domain_Locked_State_With_Rfu_Bits_Set()
    {
        _ = GlobalPlatformLifecycle.IsSecurityDomainState(0xA3).Should().BeFalse();
        _ = GlobalPlatformLifecycle.IsSecurityDomainState(0x8F).Should().BeTrue();
    }

    /// <summary>
    /// GP Card Specification v2.3.1, Table 11-6 assigns 0x7F and 0xFF only to card states.
    /// </summary>
    [Test]
    public void Should_Interpret_Card_Locked_And_Terminated_Contextually()
    {
        _ = GlobalPlatformLifecycle.DescribeCardState(0x7F).Should().Be("CardLocked");
        _ = GlobalPlatformLifecycle.DescribeCardState(0xFF).Should().Be("Terminated");
    }

    /// <summary>GP Card Specification v2.3.1, Figure 5-1.</summary>
    [TestCase(CardLifecycleState.OpReady, CardLifecycleState.Initialized)]
    [TestCase(CardLifecycleState.Initialized, CardLifecycleState.Secured)]
    [TestCase(CardLifecycleState.Secured, CardLifecycleState.CardLocked)]
    [TestCase(CardLifecycleState.CardLocked, CardLifecycleState.Secured)]
    [TestCase(CardLifecycleState.OpReady, CardLifecycleState.Terminated)]
    public void Should_Accept_Card_Lifecycle_Transitions(
        CardLifecycleState from,
        CardLifecycleState to
    )
    {
        _ = GlobalPlatformLifecycle.CanTransitionCard(from, to).Should().BeTrue();
    }

    /// <summary>GP Card Specification v2.3.1, Figure 5-1.</summary>
    [TestCase(CardLifecycleState.OpReady, CardLifecycleState.Secured)]
    [TestCase(CardLifecycleState.Initialized, CardLifecycleState.OpReady)]
    [TestCase(CardLifecycleState.Terminated, CardLifecycleState.Terminated)]
    public void Should_Reject_Card_Lifecycle_Transitions_Not_In_Figure_5_1(
        CardLifecycleState from,
        CardLifecycleState to
    )
    {
        _ = GlobalPlatformLifecycle.CanTransitionCard(from, to).Should().BeFalse();
    }
}
