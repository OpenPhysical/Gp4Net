using System;
using AwesomeAssertions;
using Gp4Net.Domain.CapFile;
using Gp4Net.Tool.Commands.Applet;
using NUnit.Framework;

namespace Gp4Net.Tool.Tests.Commands.Applet;

[TestFixture]
public sealed class LoadCommandTests
{
    [Test]
    public void Validate_AllowsOrdinaryLoadingWithoutDelegatedOptions()
    {
        var settings = new LoadCommand.Settings { CapFile = "sample.cap" };

        settings.Validate().Successful.Should().BeTrue();
        settings.MaxBlockSize.Should().Be(245);
    }

    [Test]
    public void Validate_AllowsPairedDapOptionsWithoutDelegatedToken()
    {
        var settings = new LoadCommand.Settings
        {
            CapFile = "sample.cap",
            DapSecurityDomain = Convert.FromHexString("A0000001515350D4"),
            DapKey = new byte[16],
        };

        settings.Validate().Successful.Should().BeTrue();
    }

    [Test]
    public void Validate_RequiresSecurityDomainForDelegatedLoading()
    {
        var settings = new LoadCommand.Settings
        {
            CapFile = "sample.cap",
            LoadTokenKey = new byte[16]
        };

        settings.Validate().Successful.Should().BeFalse();
    }

    [Test]
    public void CreateOptions_PreservesParametersAndUsesAesKeySource()
    {
        var settings = new LoadCommand.Settings
        {
            CapFile = "sample.cap",
            SecurityDomain = Convert.FromHexString("A000000151"),
            LoadTokenKey = new byte[16],
            LoadParameters = Convert.FromHexString("EF0100")
        };

        var result = LoadCommand.CreateOptions(settings);

        result.IsSuccess.Should().BeTrue();
        result.Value.TokenSource.Should().BeOfType<DelegatedLoadTokenSource.AesKey>();
        result.Value.LoadParameters.Should().Equal(Convert.FromHexString("EF0100"));
    }
}
