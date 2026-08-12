using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Gp4Net.CardEmulator.Tests.TestHelpers;
using Gp4Net.Core;
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
        var serviceResult = await VirtualCardConnectionService.CreateServiceAsync(
            readerSpec,
            NullLogger<SmartCardService>.Instance,
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

        var establishResult = await ScpService.Establishment.EstablishAsync(
            service,
            rawKeysetResult.Value,
            SecurityLevel.CMac,
            CancellationToken.None
        );

        Assert.That(establishResult.IsSuccess, Is.True, () => establishResult.Error.ToString());
        var session = establishResult.Value;
        Assert.That(
            session.State.ProtocolVersion,
            Is.EqualTo(Cryptography.CryptoService.ScpVersion.Scp03)
        );
        Assert.That(session.State.SecurityLevel.HasCMac(), Is.True);

        // SCP03 Amendment D v1.1.2, Sections 6.2.3 and 6.2.4.
        var secured = ScpService.Security.ApplyCommandSecurity(
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
        var serviceResult = await VirtualCardConnectionService.CreateServiceAsync(
            readerSpec,
            NullLogger<SmartCardService>.Instance,
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

        var establishResult = await ScpService.Establishment.EstablishAsync(
            service,
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

    // SCP03 Amendment D v1.1.2, Sections 6.2.3 and 7.1.2.
    [Test]
    public async Task Should_Reject_External_Authenticate_Without_CMac()
    {
        string readerSpec = $"virtual:{Scp03ProfilePath.Value}";
        var serviceResult = await VirtualCardConnectionService.CreateServiceAsync(
            readerSpec,
            NullLogger<SmartCardService>.Instance,
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
