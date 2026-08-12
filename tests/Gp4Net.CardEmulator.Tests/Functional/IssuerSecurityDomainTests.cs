using System.Collections.Immutable;
using AwesomeAssertions;
using Gp4Net.CardEmulator.Applications;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.Core;
using Gp4Net.Domain;
using NUnit.Framework;
using static Gp4Net.Constants.Constants.GlobalPlatform;
using static Gp4Net.Cryptography.CryptoOperations;

namespace Gp4Net.CardEmulator.Tests.Functional;

[TestFixture]
public class IssuerSecurityDomainTests
{
    /// <summary>
    /// GP Card Specification v2.3.1, §6.6.2 requires these 13 initial ISD privileges in OP_READY.
    /// </summary>
    [Test]
    public void Should_Assign_Required_Initial_Privileges()
    {
        var expected =
            Privilege.SecurityDomain
            | Privilege.AuthorizedManagement
            | Privilege.GlobalRegistry
            | Privilege.GlobalLock
            | Privilege.GlobalDelete
            | Privilege.TokenVerification
            | Privilege.CardLock
            | Privilege.CardTerminate
            | Privilege.TrustedPath
            | Privilege.CvmManagement
            | Privilege.CardReset
            | Privilege.FinalApplication
            | Privilege.ReceiptGeneration;

        var result = IssuerSecurityDomain.Create(
            ImmutableArray.Create<byte>(0xA0, 0x00, 0x00, 0x00, 0x03)
        );

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Privileges.Should().Be(expected);
        _ = result.Value.CardLifecycleState.Should().Be(CardLifecycleState.OpReady);
    }

    /// <summary>
    /// CPLC is not defined by GP Card Specification v2.3.1. Its industry format is a 42-byte value.
    /// </summary>
    [Test]
    public void Should_Create_A_42_Byte_Cplc_Value()
    {
        var result = IssuerSecurityDomain.Create(
            ImmutableArray.Create<byte>(0xA0, 0x00, 0x00, 0x00, 0x03)
        );

        _ = result.IsSuccess.Should().BeTrue();
        byte[] cplc = result.Value.DataObjects[0x9F7F];
        _ = cplc.Should().HaveCount(45);
        _ = cplc[..3].Should().Equal(0x9F, 0x7F, 0x2A);
        _ = cplc[3..].Should().HaveCount(42);
    }

    /// <summary>
    /// GP Card Specification v2.3.1, Tables 11-85 through 11-87 and Figure 5-1.
    /// </summary>
    [Test]
    public void Should_Apply_Isd_Set_Status_To_The_Card_Lifecycle()
    {
        var isd = IssuerSecurityDomain
            .Create(ImmutableArray.Create<byte>(0xA0, 0x00, 0x00, 0x00, 0x03))
            .Value;
        var state = CardState.Create().Value;
        var config = CardConfiguration.P71().Value;
        byte[] setInitialized = [0x80, 0xF0, 0x80, 0x07, 0x00];

        var result = isd.ProcessCommand(setInitialized, state, config, Rng.CreateSecureContext());

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Response.StatusWord.Should().Be((StatusWord)0x9000);
        _ = result
            .Value.UpdatedState.CardLifecycleState.Should()
            .Be(CardLifecycleState.Initialized);
        _ = ((IssuerSecurityDomain)result.Value.UpdatedApplication)
            .CardLifecycleState.Should()
            .Be(CardLifecycleState.Initialized);
    }

    /// <summary>
    /// GP Card Specification v2.3.1, §11.10.2.2 rejects a transition to the current state.
    /// </summary>
    [Test]
    public void Should_Reject_Set_Status_To_The_Current_Card_State()
    {
        var isd = IssuerSecurityDomain
            .Create(ImmutableArray.Create<byte>(0xA0, 0x00, 0x00, 0x00, 0x03))
            .Value;
        var state = CardState.Create().Value;
        byte[] setOpReady = [0x80, 0xF0, 0x80, 0x01, 0x00];

        var result = isd.ProcessCommand(
            setOpReady,
            state,
            CardConfiguration.P71().Value,
            Rng.CreateSecureContext()
        );

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Response.StatusWord.Should().Be((StatusWord)0x6985);
        _ = result.Value.UpdatedState.CardLifecycleState.Should().Be(CardLifecycleState.OpReady);
    }
}
