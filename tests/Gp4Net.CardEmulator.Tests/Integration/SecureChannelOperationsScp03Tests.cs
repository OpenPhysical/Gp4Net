using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.CardEmulator.Profiles;
using Gp4Net.CardEmulator.Tests.TestHelpers;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Services;
using Gp4Net.Tool.Services;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace Gp4Net.CardEmulator.Tests.Integration;

public class SecureChannelOperationsScp03Tests
{
    private static readonly Lazy<string> Scp03ProfilePath =
        new(
            () =>
                Path.Combine(
                    RepositoryPathLocator.FindRepositoryRoot(),
                    "src",
                    "Gp4Net.CardEmulator",
                    "Profiles",
                    "p71_card_2.json"
                )
        );

    [Test]
    public async Task Should_Establish_Scp03_Secure_Channel_With_Default_Test_Keys()
    {
        string readerSpec = $"virtual:{Scp03ProfilePath.Value}";
        var serviceResult = await VirtualCardConnections.CreateServiceAsync(
            readerSpec,
            NullLogger<CardSessionCommands>.Instance,
            CancellationToken.None
        );

        Assert.That(serviceResult.IsSuccess, Is.True, () => serviceResult.Error.ToString());
        using var service = serviceResult.Value;

        var rawKeysetResult = RawKeyset.Create(
            (byte[])GpTestKeys.GpTestKey.Clone(),
            (byte[])GpTestKeys.GpTestKey.Clone(),
            (byte[])GpTestKeys.GpTestKey.Clone(),
            keyVersion: 0x01
        );
        Assert.That(rawKeysetResult.IsSuccess, Is.True, () => rawKeysetResult.Error.ToString());

        var establishResult = await ScpOperations.Establishment.EstablishAsync(
            service.SendCommandAsync,
            rawKeysetResult.Value,
            SecurityLevel.CMac,
            CancellationToken.None
        );

        Assert.That(establishResult.IsSuccess, Is.True, () => establishResult.Error.ToString());
        var session = establishResult.Value;
        Assert.That(
            session.State.ProtocolVersion,
            Is.EqualTo(Cryptography.CryptoOperations.ScpVersion.Scp03)
        );
        Assert.That(session.State.SecurityLevel.HasCMac(), Is.True);

        // SCP03 Amendment D v1.1.2, Sections 6.2.3 and 6.2.4.
        var secured = ScpOperations.Security.ApplyCommandSecurity(
            new WSCT.ISO7816.CommandAPDU(Convert.FromHexString("80F24000024F00")),
            session.State
        );
        Assert.That(secured.IsSuccess, Is.True, () => secured.Error.ToString());
        var response = await service.SendCommandAsync(
            secured.Value.securedCommand.BinaryCommand,
            CancellationToken.None
        );
        Assert.That(response.IsSuccess, Is.True, () => response.Error.ToString());
        Assert.That(response.Value.StatusWord.Value, Is.EqualTo(0x9000));
    }

    [Test]
    public async Task Should_Fail_When_Scp03_Keys_Are_Incorrect()
    {
        string readerSpec = $"virtual:{Scp03ProfilePath.Value}";
        var serviceResult = await VirtualCardConnections.CreateServiceAsync(
            readerSpec,
            NullLogger<CardSessionCommands>.Instance,
            CancellationToken.None
        );

        Assert.That(serviceResult.IsSuccess, Is.True, () => serviceResult.Error.ToString());
        using var service = serviceResult.Value;

        var rawKeysetResult = RawKeyset.Create(
            (byte[])GpTestKeys.GpTestKey.Clone(),
            (byte[])GpTestKeys.GpTestKey.Clone(),
            (byte[])GpTestKeys.GpTestKey.Clone(),
            keyVersion: 0xFE
        );
        Assert.That(rawKeysetResult.IsSuccess, Is.True, () => rawKeysetResult.Error.ToString());

        var establishResult = await ScpOperations.Establishment.EstablishAsync(
            service.SendCommandAsync,
            rawKeysetResult.Value,
            SecurityLevel.CMac,
            CancellationToken.None
        );

        Assert.That(
            establishResult.IsFailure,
            Is.True,
            "Establishment should fail with unknown key version"
        );
        Assert.That(establishResult.Error.Code, Is.EqualTo("SECURITY_ERROR"));
    }

    [Test]
    public void Should_Increment_PseudoRandom_Counter_Before_Each_Challenge()
    {
        // SCP03 Amendment D v1.1.2 §6.2.2.1: increment first, then derive with the new value.
        var config = CardProfileLoader
            .LoadFromFile(Scp03ProfilePath.Value)
            .Value.WithScpDefaults(0x03, ScpImplementation.Scp03I10);
        var state = CardState.Create().Value with
        {
            ScpVersion = 0x03,
            ScpImplementation = ScpImplementation.Scp03I10,
        };
        byte[] command = Convert.FromHexString("8050000008000102030405060700");
        var rng = CryptoOperations.Rng.CreateSecureContext();

        var first = Scp03CommandProcessors.ProcessScp03InitializeUpdate(
            command,
            state,
            config,
            rng
        );
        Assert.That(first.IsSuccess, Is.True, () => first.Error.ToString());
        var second = Scp03CommandProcessors.ProcessScp03InitializeUpdate(
            command,
            first.Value.Item2,
            config,
            rng
        );

        Assert.That(second.IsSuccess, Is.True, () => second.Error.ToString());
        Assert.That(first.Value.Item1.Data[^3..], Is.EqualTo(new byte[] { 0x00, 0x00, 0x01 }));
        Assert.That(second.Value.Item1.Data[^3..], Is.EqualTo(new byte[] { 0x00, 0x00, 0x02 }));
        Assert.That(
            second.Value.Item1.Data[13..21],
            Is.Not.EqualTo(first.Value.Item1.Data[13..21])
        );
    }

    [Test]
    public void Should_Accept_I30_As_Table_5_1_Bitmap()
    {
        // SCP03 Amendment D v1.1.2 Table 5-1: i=30 is pseudo-random challenge plus R-MAC.
        var config = CardProfileLoader
            .LoadFromFile(Scp03ProfilePath.Value)
            .Value.WithScpDefaults(0x03, ScpImplementation.Scp03I30);
        var state = CardState.Create().Value with
        {
            ScpVersion = 0x03,
            ScpImplementation = ScpImplementation.Scp03I30,
        };

        var result = Scp03CommandProcessors.ProcessScp03InitializeUpdate(
            Convert.FromHexString("8050010008000102030405060700"),
            state,
            config,
            CryptoOperations.Rng.CreateSecureContext()
        );

        Assert.That(result.IsSuccess, Is.True, () => result.Error.ToString());
        Assert.That(result.Value.Item1.Data[12], Is.EqualTo(0x30));
        Assert.That(result.Value.Item1.Data[^3..], Is.EqualTo(new byte[] { 0x00, 0x00, 0x01 }));
    }

    [Test]
    public void Should_Omit_Sequence_Counter_For_Random_Challenge()
    {
        // SCP03 Amendment D v1.1.2 Table 7-3: the counter is present only for pseudo-random mode.
        var config = CardProfileLoader
            .LoadFromFile(Scp03ProfilePath.Value)
            .Value.WithScpDefaults(0x03, ScpImplementation.Scp03I00);
        var state = CardState.Create().Value with
        {
            ScpVersion = 0x03,
            ScpImplementation = ScpImplementation.Scp03I00,
        };

        var result = Scp03CommandProcessors.ProcessScp03InitializeUpdate(
            Convert.FromHexString("8050010008000102030405060700"),
            state,
            config,
            CryptoOperations.Rng.CreateSecureContext()
        );

        Assert.That(result.IsSuccess, Is.True, () => result.Error.ToString());
        Assert.That(result.Value.Item1.Data, Has.Length.EqualTo(29));
    }

    [Test]
    public void Should_Reject_Exhausted_PseudoRandom_Counter()
    {
        // SCP03 Amendment D v1.1.2 §6.2.2.1 requires rejection at the maximum value.
        var config = CardProfileLoader
            .LoadFromFile(Scp03ProfilePath.Value)
            .Value.WithScpDefaults(0x03, ScpImplementation.Scp03I10);
        var state = (
            CardState.Create().Value with
            {
                ScpVersion = 0x03,
                ScpImplementation = ScpImplementation.Scp03I10,
            }
        ).WithSequenceCounter(0x01, [0xFF, 0xFF, 0xFF]);

        var result = Scp03CommandProcessors.ProcessScp03InitializeUpdate(
            Convert.FromHexString("8050010008000102030405060700"),
            state,
            config,
            CryptoOperations.Rng.CreateSecureContext()
        );

        Assert.That(result.IsFailure, Is.True);
        Assert.That(result.Error.Code, Is.EqualTo("CONDITIONS_NOT_SATISFIED"));
    }

    // SCP03 Amendment D v1.1.2, Sections 6.2.3 and 7.1.2.
    [Test]
    public async Task Should_Reject_External_Authenticate_Without_CMac()
    {
        string readerSpec = $"virtual:{Scp03ProfilePath.Value}";
        var serviceResult = await VirtualCardConnections.CreateServiceAsync(
            readerSpec,
            NullLogger<CardSessionCommands>.Instance,
            CancellationToken.None
        );
        Assert.That(serviceResult.IsSuccess, Is.True, () => serviceResult.Error.ToString());
        using var service = serviceResult.Value;

        byte[] command = [0x00, 0x82, 0x01, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0];
        var response = await service.SendCommandAsync(command, CancellationToken.None);

        Assert.That(response.IsSuccess, Is.True, () => response.Error.ToString());
        Assert.That(response.Value.StatusWord.Value, Is.EqualTo(0x6E00));
    }
}
