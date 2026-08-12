using System;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.CardEmulator.Persistence;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using NUnit.Framework;
using static Gp4Net.Constants.Constants.GlobalPlatform;

namespace Gp4Net.CardEmulator.Tests.Persistence;

[TestFixture]
public sealed class VirtualCardStateStoreTests
{
    private readonly CardConfiguration configuration = CardConfiguration.P71().Value;
    private readonly IRngContext rng = new TestRngContext();
    private string statePath = string.Empty;

    [SetUp]
    public void SetUp() =>
        statePath = Path.Combine(Path.GetTempPath(), $"gp4net-state-{Guid.NewGuid():N}.json");

    [TearDown]
    public void TearDown()
    {
        if (File.Exists(statePath))
            File.Delete(statePath);
    }

    [Test]
    public void Save_And_Load_Should_Preserve_Nonvolatile_State()
    {
        byte[] applicationAid = Convert.FromHexString("A0000001515350415050");
        byte[] moduleAid = Convert.FromHexString("A00000015153504D4F44");
        var application = new InstalledApplication(
            applicationAid,
            moduleAid,
            (byte)ApplicationLifecycleState.Selectable,
            Privilege.CardReset,
            ImmutableDictionary<string, byte[]>.Empty
        );
        var component = new StoredKeyComponent(
            0x88,
            ImmutableArray.Create<byte>(0x01, 0x02, 0x03),
            ImmutableArray.Create<byte>(0x04, 0x05, 0x06)
        );

        VirtualCard original = VirtualCard.Create(configuration, rng).Value;
        CardState state = original.CurrentState with
        {
            DataObjects = original.CurrentState.DataObjects.SetItem(0x0101, [0xCA, 0xFE]),
            Applications = original.CurrentState.Applications.SetItem(
                Convert.ToHexString(applicationAid),
                application
            ),
            InstalledKeyComponents = original.CurrentState.InstalledKeyComponents.SetItem(
                new KeyReference(0x20, 0x01),
                component
            ),
            CardLifecycleState = CardLifecycleState.Secured,
        };
        VirtualCard card = VirtualCard.Restore(configuration, rng, state).Value;
        byte[] rootKey = CreateRootKey(0x41);

        VirtualCardStateStore.Save(card, statePath, rootKey).IsSuccess.Should().BeTrue();
        var loaded = VirtualCardStateStore.Load(statePath, configuration, rootKey);

        loaded.IsSuccess.Should().BeTrue();
        loaded.Value.Uuid.Should().Be(state.Uuid);
        loaded.Value.DataObjects[0x0101].Should().Equal(0xCA, 0xFE);
        loaded.Value.Applications.Should().ContainKey(Convert.ToHexString(applicationAid));
        loaded.Value.InstalledKeyComponents.Should().ContainKey(new KeyReference(0x20, 0x01));
        loaded.Value.CardLifecycleState.Should().Be(CardLifecycleState.Secured);
        loaded.Value.SecureChannel.HasValue.Should().BeFalse();
        loaded.Value.PendingLoad.HasValue.Should().BeFalse();
        loaded.Value.PendingPutKey.HasValue.Should().BeFalse();
    }

    [Test]
    public void Load_With_Wrong_Root_Key_Should_Fail_Authentication()
    {
        VirtualCard card = VirtualCard.Create(configuration, rng).Value;
        VirtualCardStateStore
            .Save(card, statePath, CreateRootKey(0x41))
            .IsSuccess.Should()
            .BeTrue();

        var loaded = VirtualCardStateStore.Load(statePath, configuration, CreateRootKey(0x42));

        loaded.IsFailure.Should().BeTrue();
    }

    [Test]
    public void Load_After_Ciphertext_Tampering_Should_Fail_Authentication()
    {
        VirtualCard card = VirtualCard.Create(configuration, rng).Value;
        byte[] rootKey = CreateRootKey(0x41);
        VirtualCardStateStore.Save(card, statePath, rootKey).IsSuccess.Should().BeTrue();
        string envelope = File.ReadAllText(statePath);
        int ciphertextIndex = envelope.IndexOf("Ciphertext", StringComparison.Ordinal);
        int valueIndex = envelope.IndexOf(':', ciphertextIndex) + 2;
        char replacement = envelope[valueIndex] == 'A' ? 'B' : 'A';
        string tampered = envelope[..valueIndex] + replacement + envelope[(valueIndex + 1)..];
        File.WriteAllText(statePath, tampered);

        var loaded = VirtualCardStateStore.Load(statePath, configuration, rootKey);

        loaded.IsFailure.Should().BeTrue();
    }

    private static byte[] CreateRootKey(byte value) => Enumerable.Repeat(value, 32).ToArray();

    private sealed class TestRngContext : IRngContext
    {
        public Result<byte[], SmartCardError> GenerateBytes(int length) =>
            Result.Success<byte[], SmartCardError>(new byte[length]);

        public bool HasEnoughEntropy(int requiredBytes) => true;

        public Maybe<int> RemainingEntropy => Maybe<int>.None;
    }
}
