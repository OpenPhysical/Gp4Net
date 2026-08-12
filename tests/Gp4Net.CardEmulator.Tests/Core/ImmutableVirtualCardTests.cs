using System;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace Gp4Net.CardEmulator.Tests.Core;

/// <summary>
/// Tests for VirtualCard with immutable state management.
/// Validates that all state transitions use the ICardStateService properly.
/// </summary>
[TestFixture]
public class ImmutableVirtualCardTests
{
    private readonly CardConfiguration _config = CardConfiguration.P71().Value;
    private readonly IRngContext _rngContext = new TestRngContext();
    private readonly ILogger _logger = NullLogger.Instance;
    private readonly ICardStateService _stateService = new CardStateService(
        Maybe<ILogger>.From(NullLogger.Instance)
    );

    [Test]
    public void Create_WithStateService_Success_ReturnsValidVirtualCard()
    {
        var result = VirtualCard.Create(
            _config,
            _rngContext,
            Maybe<ILogger>.From(_logger),
            Maybe<CapFileServiceAdapter>.None,
            Maybe<ICardStateService>.From(_stateService)
        );

        result.IsSuccess.Should().BeTrue();
        result.Match(
            card =>
            {
                card.IsSelected.Should().BeTrue();
                card.IsSecureChannelEstablished.Should().BeFalse();
                card.Configuration.Should().Be(_config);
            },
            error => Assert.Fail($"Expected successful card creation: {error}")
        );
    }

    [Test]
    public void Create_WithoutStateService_Success_CreatesDefaultStateService()
    {
        var result = VirtualCard.Create(_config, _rngContext, Maybe<ILogger>.From(_logger));

        result.IsSuccess.Should().BeTrue();
        result.Match(
            card =>
            {
                card.IsSelected.Should().BeTrue();
                card.IsSecureChannelEstablished.Should().BeFalse();
            },
            error => Assert.Fail($"Expected successful card creation: {error}")
        );
    }

    [Test]
    public void Reset_WithImmutableState_Success_ReturnsNewCardInstance()
    {
        var cardResult = VirtualCard.Create(_config, _rngContext, Maybe<ILogger>.From(_logger));

        cardResult.Match(
            originalCard =>
            {
                var resetResult = originalCard.Reset();

                resetResult.IsSuccess.Should().BeTrue();
                resetResult.Match(
                    resetCard =>
                    {
                        Assert.That(resetCard, Is.Not.SameAs(originalCard));
                        resetCard.IsSelected.Should().BeTrue();
                        resetCard.IsSecureChannelEstablished.Should().BeFalse();
                    },
                    error => Assert.Fail($"Expected successful reset: {error}")
                );
            },
            error => Assert.Fail($"Expected valid original card: {error}")
        );
    }

    [Test]
    public void FunctionalReset_WithImmutableState_Success_ReturnsNewCardInstance()
    {
        var cardResult = VirtualCard.Create(_config, _rngContext, Maybe<ILogger>.From(_logger));

        cardResult.Match(
            originalCard =>
            {
                var functionalCard = (IVirtualCard)originalCard;
                var resetResult = functionalCard.Reset();

                resetResult.IsSuccess.Should().BeTrue();
                resetResult.Match(
                    resetCard =>
                    {
                        Assert.That(resetCard, Is.Not.SameAs(originalCard));
                        resetCard.IsSelected.Should().BeTrue();
                        resetCard.IsSecureChannelEstablished.Should().BeFalse();
                    },
                    error => Assert.Fail($"Expected successful functional reset: {error}")
                );
            },
            error => Assert.Fail($"Expected valid original card: {error}")
        );
    }

    [Test]
    public void ProcessCommand_ValidCommand_Success_ReturnsResponse()
    {
        var cardResult = VirtualCard.Create(_config, _rngContext, Maybe<ILogger>.From(_logger));

        cardResult.Match(
            card =>
            {
                var selectCommand = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 };
                var result = card.ProcessCommand(selectCommand);

                Assert.That(result.IsSuccess, Is.True);
                var (response, _) = result.Value;
                Assert.That(response, Is.Not.Null);
                Assert.That(response.Data, Is.Not.Null);
            },
            error => Assert.Fail($"Expected valid card: {error}")
        );
    }

    [Test]
    public void ProcessCommand_Functional_Success_ReturnsResponseAndNewCard()
    {
        var cardResult = VirtualCard.Create(_config, _rngContext, Maybe<ILogger>.From(_logger));

        cardResult.Match(
            card =>
            {
                var functionalCard = (IVirtualCard)card;
                var selectCommand = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 };
                var result = functionalCard.ProcessCommand(selectCommand);

                result.IsSuccess.Should().BeTrue();
                result.Match(
                    responseAndCard =>
                    {
                        var (response, updatedCard) = responseAndCard;

                        Assert.That(response, Is.Not.Null);
                        Assert.That(updatedCard, Is.Not.SameAs(card));
                        Assert.That(updatedCard, Is.Not.Null);
                    },
                    error => Assert.Fail($"Expected successful command processing: {error}")
                );
            },
            error => Assert.Fail($"Expected valid card: {error}")
        );
    }

    [Test]
    public void CurrentState_IsImmutable_DoesNotChangeAcrossOperations()
    {
        var cardResult = VirtualCard.Create(_config, _rngContext, Maybe<ILogger>.From(_logger));

        cardResult.Match(
            card =>
            {
                var originalState = card.CurrentState;
                var originalHashCode = originalState.GetHashCode();

                // Perform operations that should not mutate the original state
                var selectCommand = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 };
                card.ProcessCommand(selectCommand);
                card.Reset();

                // Original state should remain unchanged
                var currentState = card.CurrentState;
                currentState.GetHashCode().Should().Be(originalHashCode);
                Assert.That(currentState, Is.EqualTo(originalState));
            },
            error => Assert.Fail($"Expected valid card: {error}")
        );
    }

    #region Test Helpers

    private class TestRngContext : IRngContext
    {
        public Result<byte[], SmartCardError> GenerateBytes(int length) =>
            Result.Success<byte[], SmartCardError>(new byte[length]);

        public bool HasEnoughEntropy(int requiredBytes) => true;

        public Maybe<int> RemainingEntropy => Maybe<int>.None;
    }

    #endregion
}
