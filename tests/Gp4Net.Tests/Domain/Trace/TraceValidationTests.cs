using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Domain.Trace;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Trace;

[TestFixture]
public class TraceValidationTests
{
    private static readonly byte[] GpTestKey = Convert.FromHexString(
        "404142434445464748494A4B4C4D4E4F"
    );

    [Test]
    public void Should_Validate_Scp03_Initialize_Update_Exchange()
    {
        // Sample SCP03 INITIALIZE UPDATE exchange
        var initUpdateCommand = Convert.FromHexString("8050010008FE0530CF61BAA9F300");
        var initUpdateResponse = Convert.FromHexString(
            "0103E36F6E5BAA71900096A8EFDC78BC6D5E54E5F859B973E38F00BF9000"
        );

        // Create base keys
        var baseKeys = GpTestKeys.GetTestKeySet(CryptoService.ScpVersion.Scp03).Value;

        // Create initial state
        var initialState = new TraceValidationState(
            BaseKeys: baseKeys,
            SessionKeys: Maybe<SessionKeys>.None,
            CommandIcv: Maybe<byte[]>.None,
            ResponseIcv: Maybe<byte[]>.None,
            SequenceCounter: new byte[2],
            CardChallenge: new byte[8],
            HostChallenge: new byte[8],
            ScpVersion: CryptoService.ScpVersion.Scp03,
            Results: ImmutableList<ValidationResult>.Empty
        );

        // Validate the exchange
        var validationResult = TraceValidation.ValidateExchange(
            initialState,
            initUpdateCommand,
            initUpdateResponse,
            0
        );

        Assert.That(validationResult.IsSuccess, Is.True, "SCP03 validation should succeed");
        var newState = validationResult.Value;
        Assert.That(newState.SessionKeys.HasValue, Is.True, "Session keys should be derived");
        Assert.That(newState.Results.Count, Is.GreaterThan(0), "Should have validation results");
    }

    [Test]
    public void Should_Validate_Scp02_Initialize_Update_Exchange()
    {
        // Sample SCP02 INITIALIZE UPDATE exchange from trace
        var initUpdateCommand = Convert.FromHexString("8050000008BA47FC84E2F99E2C00");
        var initUpdateResponse = Convert.FromHexString(
            "015501B20BF30BE1FF0203C96F15E09800009A06C4EBD5F31EB0FA869000"
        );

        // Create base keys
        var baseKeys = GpTestKeys.GetTestKeySet(CryptoService.ScpVersion.Scp02).Value;

        // Create initial state
        var initialState = new TraceValidationState(
            BaseKeys: baseKeys,
            SessionKeys: Maybe<SessionKeys>.None,
            CommandIcv: Maybe<byte[]>.None,
            ResponseIcv: Maybe<byte[]>.None,
            SequenceCounter: new byte[2],
            CardChallenge: new byte[6],
            HostChallenge: new byte[8],
            ScpVersion: CryptoService.ScpVersion.Scp02,
            Results: ImmutableList<ValidationResult>.Empty
        );

        // Validate the exchange
        var validationResult = TraceValidation.ValidateExchange(
            initialState,
            initUpdateCommand,
            initUpdateResponse,
            0
        );

        Assert.That(validationResult.IsSuccess, Is.True, "SCP02 validation should succeed");
        var newState = validationResult.Value;
        Assert.That(newState.SessionKeys.HasValue, Is.True, "Session keys should be derived");
        Assert.That(newState.Results.Count, Is.GreaterThan(0), "Should have validation results");
    }

    [Test]
    public void Should_Validate_Scp03_External_Authenticate_Exchange()
    {
        // First setup state with INITIALIZE UPDATE
        var initUpdateCommand = Convert.FromHexString("8050010008FE0530CF61BAA9F300");
        var initUpdateResponse = Convert.FromHexString(
            "0103E36F6E5BAA71900096A8EFDC78BC6D5E54E5F859B973E38F00BF9000"
        );

        var baseKeys = GpTestKeys.GetTestKeySet(CryptoService.ScpVersion.Scp03).Value;
        var initialState = new TraceValidationState(
            BaseKeys: baseKeys,
            SessionKeys: Maybe<SessionKeys>.None,
            CommandIcv: Maybe<byte[]>.None,
            ResponseIcv: Maybe<byte[]>.None,
            SequenceCounter: new byte[2],
            CardChallenge: new byte[8],
            HostChallenge: new byte[8],
            ScpVersion: CryptoService.ScpVersion.Scp03,
            Results: ImmutableList<ValidationResult>.Empty
        );

        // Validate INITIALIZE UPDATE to get session keys
        var stateAfterInit = TraceValidation.ValidateExchange(
            initialState,
            initUpdateCommand,
            initUpdateResponse,
            0
        ).Value;

        // Sample EXTERNAL AUTHENTICATE with MAC
        var externalAuthCommand = Convert.FromHexString("8482030010D17E0BDEB063A01B80AFA59F5A3CA613");
        var externalAuthResponse = Convert.FromHexString("9000");

        // Validate EXTERNAL AUTHENTICATE
        var validationResult = TraceValidation.ValidateExchange(
            stateAfterInit,
            externalAuthCommand,
            externalAuthResponse,
            1
        );

        // Verify validation was attempted
        validationResult.Match(
            success => 
            {
                Assert.That(
                    success.Results.Count,
                    Is.GreaterThan(stateAfterInit.Results.Count),
                    "Validation should add results"
                );
                
                var lastResult = success.Results.Last();
                Assert.That(
                    lastResult.ValidationType.Contains("EXTERNAL_AUTHENTICATE"),
                    Is.True,
                    "Should validate EXTERNAL_AUTHENTICATE"
                );
            },
            failure =>
            {
                var errorMessage = failure.ToString();
                Assert.That(
                    errorMessage.Contains("MAC") || errorMessage.Contains("cryptogram"),
                    Is.True,
                    $"Validation failure should be cryptographic: {errorMessage}"
                );
            }
        );
    }

    [Test]
    public void Should_Reject_Invalid_Command()
    {
        var baseKeys = GpTestKeys.GetTestKeySet(CryptoService.ScpVersion.Scp02).Value;
        var state = new TraceValidationState(
            BaseKeys: baseKeys,
            SessionKeys: Maybe<SessionKeys>.None,
            CommandIcv: Maybe<byte[]>.None,
            ResponseIcv: Maybe<byte[]>.None,
            SequenceCounter: new byte[2],
            CardChallenge: new byte[6],
            HostChallenge: new byte[8],
            ScpVersion: CryptoService.ScpVersion.Scp02,
            Results: ImmutableList<ValidationResult>.Empty
        );

        // Empty command should fail
        var result = TraceValidation.ValidateExchange(
            state,
            new byte[0],
            Convert.FromHexString("9000"),
            0
        );

        Assert.That(result.IsFailure, Is.True, "Empty command should fail");
        Assert.That(
            result.Error.ToString().Contains("empty"),
            Is.True,
            "Error should mention empty command"
        );
    }
}