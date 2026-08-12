using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Gp4Net.CardEmulator.Tests.TestHelpers;
using Gp4Net.Constants;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Services;
using Gp4Net.Tool.Services;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace Gp4Net.CardEmulator.Tests.Integration;

public class SecureChannelOperationsScp02Tests
{
    private static readonly Lazy<string> Scp02ProfilePath =
        new(
            () =>
                Path.Combine(
                    RepositoryPathLocator.FindRepositoryRoot(),
                    "src",
                    "Gp4Net.CardEmulator",
                    "Profiles",
                    "p71_card_1.json"
                )
        );

    [Test]
    public async Task Should_Autodetect_Scp02_Implementation_From_Card_Recognition_Data()
    {
        using var service = await CreateService();
        var rawKeyset = RawKeyset.Create(
            (byte[])GpTestKeys.GpTestKey.Clone(),
            (byte[])GpTestKeys.GpTestKey.Clone(),
            (byte[])GpTestKeys.GpTestKey.Clone(),
            keyVersion: 0x01
        );
        Assert.That(rawKeyset.IsSuccess, Is.True, () => rawKeyset.Error.ToString());

        var result = await ScpOperations.Establishment.EstablishAsync(
            service.SendCommandAsync,
            rawKeyset.Value,
            SecurityLevel.CMac,
            CancellationToken.None
        );

        Assert.That(result.IsSuccess, Is.True, () => result.Error.ToString());
        // GP Card Spec 2.3.1, Appendix H: tag 64 identifies {globalPlatform 4 scp i}.
        Assert.That(result.Value.ScpOption.Implementation, Is.EqualTo(0x55));
        // GP Card Spec 2.3.1, Table E-1: b5 enables C-MAC ICV encryption.
        Assert.That(
            ((ScpImplementation)result.Value.State.ImplementationParameter).HasIcvEncryption(),
            Is.True
        );
    }

    [Test]
    public async Task Should_Preserve_Explicit_Scp02_Implementation()
    {
        using var service = await CreateService();
        var keyset = Scp02KeySet.Create(
            (byte[])GpTestKeys.GpTestKey.Clone(),
            (byte[])GpTestKeys.GpTestKey.Clone(),
            (byte[])GpTestKeys.GpTestKey.Clone(),
            keyVersion: 0x01
        );
        Assert.That(keyset.IsSuccess, Is.True, () => keyset.Error.ToString());

        var result = await ScpOperations.Establishment.EstablishAsync(
            service.SendCommandAsync,
            keyset.Value,
            new ScpOperations.Types.ScpOption(
                Cryptography.CryptoOperations.ScpVersion.Scp02,
                (byte)ScpImplementation.Scp02I15
            ),
            SecurityLevel.CMac,
            CancellationToken.None
        );

        Assert.That(result.IsSuccess, Is.True, () => result.Error.ToString());
        // GP Card Spec 2.3.1, Table E-1: i=15 selects encrypted C-MAC ICVs.
        Assert.That(result.Value.State.ImplementationParameter, Is.EqualTo(0x15));
        Assert.That(
            ((ScpImplementation)result.Value.State.ImplementationParameter).HasIcvEncryption(),
            Is.True
        );
    }

    private static async Task<ICardSessionCommands> CreateService()
    {
        var result = await VirtualCardConnections.CreateServiceAsync(
            $"virtual:{Scp02ProfilePath.Value}",
            NullLogger<CardSessionCommands>.Instance,
            CancellationToken.None
        );
        Assert.That(result.IsSuccess, Is.True, () => result.Error.ToString());
        return result.Value;
    }
}
