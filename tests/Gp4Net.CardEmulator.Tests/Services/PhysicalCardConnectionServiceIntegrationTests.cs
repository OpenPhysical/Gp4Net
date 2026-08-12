using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Tests.TestHelpers;
using Gp4Net.Domain;
using Gp4Net.Services;
using Gp4Net.Tool.Services;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace Gp4Net.CardEmulator.Tests.Services;

public class PhysicalCardConnectionServiceIntegrationTests
{
    private static readonly Lazy<string> ProfilePath =
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
    public async Task Should_Create_Service_For_Virtual_Reader()
    {
        string readerSpec = $"virtual:{ProfilePath.Value}";

        var result = await PhysicalCardConnectionService.CreateServiceAsync(
            readerSpec,
            NullLogger<SmartCardService>.Instance,
            CancellationToken.None
        );

        Assert.That(result.IsSuccess, Is.True, () => result.Error.ToString());
        using var service = result.Value;

        var selectCommand = Gp4Net
            .Services.GlobalPlatform.Commands.CreateSelectIsdCommand()
            .Bind(cmd => cmd.ToCommandApdu())
            .Map(apdu => apdu.BinaryCommand);

        Assert.That(selectCommand.IsSuccess, Is.True, () => selectCommand.Error.ToString());
        var response = await service.SendCommandAsync(selectCommand.Value, CancellationToken.None);
        Assert.That(response.IsSuccess, Is.True, () => response.Error.ToString());
    }

    [Test]
    public async Task Should_Fail_When_Virtual_Profile_Is_Missing()
    {
        string readerSpec =
            $"virtual:{Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"))}.json";

        var result = await PhysicalCardConnectionService.CreateServiceAsync(
            readerSpec,
            NullLogger<SmartCardService>.Instance,
            CancellationToken.None
        );

        Assert.That(result.IsFailure, Is.True);
        Assert.That(result.Error.Code, Is.EqualTo("INVALID_ARGUMENT"));
    }
}
