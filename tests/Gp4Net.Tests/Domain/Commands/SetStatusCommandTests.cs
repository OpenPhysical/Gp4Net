using System;
using AwesomeAssertions;
using Gp4Net.Domain.Commands;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands;

public class SetStatusCommandTests
{
    [Test]
    public void ApplicationLock_Should_Encode_StatusType_In_P1_And_State_In_P2()
    {
        // GP Card Spec 2.3.1, Tables 11-85/86: P1=40 selects an Application
        // or SSD, while P2 carries the application LOCKED state 83.
        byte[] aid = Convert.FromHexString("A000000151000000");

        byte[] apdu = SetStatusCommand.CreateForLock(aid).Value.ToBytes();

        _ = apdu[2].Should().Be(0x40);
        _ = apdu[3].Should().Be(0x83);
        _ = apdu[5..].Should().Equal(aid);
    }

    [Test]
    public void CardLock_Should_Encode_Isd_StatusType_And_No_Aid()
    {
        // GP Card Spec 2.3.1, Tables 11-85/86: P1=80 selects the ISD and
        // P2=7F requests CARD_LOCKED; the card-level data field is absent.
        byte[] apdu = SetStatusCommand.CreateForCardLock().Value.ToBytes();

        _ = apdu.Should().Equal(0x80, 0xF0, 0x80, 0x7F);
    }
}
