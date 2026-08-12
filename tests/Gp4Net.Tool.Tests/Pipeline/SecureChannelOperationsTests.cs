using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Services;
using Gp4Net.Tool.Pipeline;
using Gp4Net.Tool.Services;
using Gp4Net.Tool.Tests.Support;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace Gp4Net.Tool.Tests.Pipeline;

public class SecureChannelOperationsTests
{
    private static readonly string ProfilePath = Path.Combine(
        SecurityTestData.RepositoryRoot,
        "src",
        "Gp4Net.CardEmulator",
        "Profiles",
        "p71_card_1.json"
    );

    private KeysetResolution resolver = new();

    [SetUp]
    public void SetUp()
    {
        resolver = new KeysetResolution();
    }

    [Test]
    public async Task Should_Establish_With_Explicit_Test_Keys()
    {
        using var service = await CreateSmartCardServiceAsync();

        var request = new SecureChannelRequest(
            Maybe<string>.None,
            Maybe<ExplicitKeys>.From(
                new ExplicitKeys(
                    (byte[])GpTestKeys.GpTestKey.Clone(),
                    (byte[])GpTestKeys.GpTestKey.Clone(),
                    (byte[])GpTestKeys.GpTestKey.Clone()
                )
            ),
            Maybe<Dictionary<string, string>>.None,
            SecurityLevel.CMac,
            Maybe<byte>.From(0x01)
        );

        var result = await SecureChannelOperations.EstablishFromRequestAsync(
            request,
            service,
            resolver,
            CancellationToken.None
        );

        Assert.That(result.IsSuccess, Is.True, () => result.Error.ToString());
        Assert.That(result.Value.SecureChannelState.SecurityLevel.HasCMac(), Is.True);
    }

    [Test]
    public async Task Should_Establish_With_Default_Keyset()
    {
        using var service = await CreateSmartCardServiceAsync();

        var request = new SecureChannelRequest(
            Maybe<string>.From("gp_test_keys"),
            Maybe<ExplicitKeys>.None,
            Maybe<Dictionary<string, string>>.None,
            SecurityLevel.CMac,
            Maybe<byte>.From(0x01)
        );

        var result = await SecureChannelOperations.EstablishFromRequestAsync(
            request,
            service,
            resolver,
            CancellationToken.None
        );

        Assert.That(result.IsSuccess, Is.True, () => result.Error.ToString());
        Assert.That(result.Value.SecureChannelState.SecurityLevel.HasCMac(), Is.True);
    }

    [Test]
    public async Task Should_Autodetect_Key_Version_When_Not_Explicit()
    {
        using var service = await CreateSmartCardServiceAsync();

        var request = new SecureChannelRequest(
            Maybe<string>.From("gp_test_keys"),
            Maybe<ExplicitKeys>.None,
            Maybe<Dictionary<string, string>>.None,
            SecurityLevel.CMac,
            Maybe<byte>.None
        );

        var result = await SecureChannelOperations.EstablishFromRequestAsync(
            request,
            service,
            resolver,
            CancellationToken.None
        );

        Assert.That(result.IsSuccess, Is.True, () => result.Error.ToString());
        Assert.That(result.Value.SecureChannelState.SecurityLevel.HasCMac(), Is.True);
    }

    [Test]
    public async Task Should_Fail_For_Unknown_Keyset()
    {
        using var service = await CreateSmartCardServiceAsync();

        var request = new SecureChannelRequest(
            Maybe<string>.From("unknown_keyset"),
            Maybe<ExplicitKeys>.None,
            Maybe<Dictionary<string, string>>.None,
            SecurityLevel.CMac,
            Maybe<byte>.From(0x01)
        );

        var result = await SecureChannelOperations.EstablishFromRequestAsync(
            request,
            service,
            resolver,
            CancellationToken.None
        );

        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.Error.Message, Does.Contain("Unknown keyset"));
    }

    private static async Task<ICardSessionCommands> CreateSmartCardServiceAsync()
    {
        string readerSpec = $"virtual:{ProfilePath}";
        var serviceResult = await VirtualCardConnections.CreateServiceAsync(
            readerSpec,
            NullLogger<CardSessionCommands>.Instance,
            CancellationToken.None
        );

        if (serviceResult.IsFailure)
        {
            throw new InvalidOperationException(serviceResult.Error.Message);
        }

        return serviceResult.Value;
    }
}
