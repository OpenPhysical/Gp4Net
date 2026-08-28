using System;
using System.IO;
using AwesomeAssertions;
using Gp4Net.Domain.CapFile;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.CapFile;

[TestFixture]
public sealed class DelegatedLoadTests
{
    private static readonly byte[] Key = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");
    private static readonly byte[] Hash = Convert.FromHexString(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

    [Test]
    public void ComputeLoadToken_MatchesIndependentOpenSslVector()
    {
        var result = DelegatedLoadCryptography.ComputeLoadToken(
            Key, 0x02, 0x00,
            Convert.FromHexString("A000000001"),
            Convert.FromHexString("A000000151"),
            Hash,
            Convert.FromHexString("EF0100"));

        result.IsSuccess.Should().BeTrue();
        result.Value.Should().Equal(Convert.FromHexString("5B158ABE51333C2D99A163123329CE23"));
    }

    [Test]
    public void CreateDapBlock_EncodesSecurityDomainAndAesCmac()
    {
        var result = DelegatedLoadCryptography.CreateDapBlock(
            Convert.FromHexString("A000000151"), Key, Hash);

        result.IsSuccess.Should().BeTrue();
        result.Value.Should().Equal(Convert.FromHexString(
            "E2194F05A000000151C31073DBFAF8321B282A162D2BAC929FE7E7"));
    }

    [TestCase(15)]
    [TestCase(17)]
    [TestCase(31)]
    public void Create_RejectsUnsupportedAesKeyLengths(int length)
    {
        var result = DelegatedLoadOptions.Create(
            Convert.FromHexString("A000000151"),
            new DelegatedLoadTokenSource.AesKey(new byte[length]));

        result.IsFailure.Should().BeTrue();
    }

    [Test]
    public void Create_RequiresPairedDapInputs()
    {
        var result = DelegatedLoadOptions.Create(
            Convert.FromHexString("A000000151"),
            new DelegatedLoadTokenSource.AesKey(Key),
            dapSecurityDomainAid: Convert.FromHexString("A000000151"));

        result.IsFailure.Should().BeTrue();
    }

    [Test]
    public void Artifacts_AcceptsEquivalentPrecomputedToken()
    {
        string capPath = Path.GetFullPath(Path.Combine(
            TestContext.CurrentContext.TestDirectory,
            "../../../../applets/OpenFIPS201-v1_10_2.cap"));
        var cap = CapFileStructure.Parse(File.ReadAllBytes(capPath)).Value;
        byte[] securityDomain = Convert.FromHexString("A000000151000000");
        var keyed = DelegatedLoadArtifacts.Create(cap,
            DelegatedLoadOptions.Create(securityDomain,
                new DelegatedLoadTokenSource.AesKey(Key)).Value).Value;
        var supplied = DelegatedLoadArtifacts.Create(cap,
            DelegatedLoadOptions.Create(securityDomain,
                new DelegatedLoadTokenSource.Precomputed(keyed.LoadToken)).Value).Value;

        supplied.LoadToken.Should().Equal(keyed.LoadToken);
        supplied.LoadFileDataBlockHash.Should().Equal(keyed.LoadFileDataBlockHash);
    }

    [Test]
    public void Artifacts_LfdbhExcludesDescriptorComponentLikePhysicalCards()
    {
        string capPath = Path.GetFullPath(Path.Combine(
            TestContext.CurrentContext.TestDirectory,
            "../../../../applets/OpenFIPS201-v1_10_2.cap"));
        var cap = CapFileStructure.Parse(File.ReadAllBytes(capPath)).Value;
        var artifacts = DelegatedLoadArtifacts.Create(
            cap,
            DelegatedLoadOptions.Create(
                Convert.FromHexString("A000000151000000"),
                new DelegatedLoadTokenSource.AesKey(Key)).Value).Value;

        artifacts.LoadFileDataBlockHash.Should().Equal(Convert.FromHexString(
            "D744D9210FB6B9430A563B70213CB420D1A17A52AD26C6088C502F56A7CB6994"));
        cap.GetLoadingComponents().Should().NotContain(component =>
            component.Tag == Constants.Constants.JavaCard.ComponentTags.DESCRIPTOR);
    }

    [Test]
    public void DapArtifacts_MatchPhysicalCardLoadVector()
    {
        string capPath = Path.GetFullPath(Path.Combine(
            TestContext.CurrentContext.TestDirectory,
            "../../../../applets/OpenFIPS201-v1_10_2.cap"));
        var cap = CapFileStructure.Parse(File.ReadAllBytes(capPath)).Value;
        byte[] dapSecurityDomain = Convert.FromHexString("A0000001515350D4");

        var artifacts = DapLoadArtifacts.Create(cap, dapSecurityDomain, Key).Value;

        artifacts.LoadFileDataBlockHash.Should().Equal(Convert.FromHexString(
            "D744D9210FB6B9430A563B70213CB420D1A17A52AD26C6088C502F56A7CB6994"));
        artifacts.InstallForLoad.Hash.Should().Equal(artifacts.LoadFileDataBlockHash);
        artifacts.LoadCommands[0].Data.Should().StartWith(Convert.FromHexString(
            "E21C4F08A0000001515350D4C31097F7F65D1A0E619B051B58E1B42268A6C4"));
        artifacts.LoadCommands.Should().OnlyContain(command => command.Data.Length <= 245,
            "SCP02 C-MAC needs room in a short APDU");
    }
}
