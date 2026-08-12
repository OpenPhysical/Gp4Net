using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using FsCheck;
using FsCheck.NUnit;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Tool.Services;
using Gp4Net.Transport;
using Microsoft.Extensions.Logging.Abstractions;

namespace Gp4Net.Tests.Tool.Services;

public class CardCompatibilityServicePropertyTests
{
    [Property]
    public Property Compatibility_Analysis_Is_Deterministic()
    {
        return Prop.ForAll(
            Arb.From<CardOperation>(),
            Arb.From<bool>(),
            (operation, isSafe) =>
            {
                var envValidation = new TestEnvironmentValidationService();
                envValidation.SetValidationResult(
                    new EnvironmentValidationResult(
                        isSafe: isSafe,
                        cardEnvironment: CardEnvironment.Test,
                        isTestKeySet: false,
                        message: "Test"
                    )
                );

                var serviceResult = CardCompatibility.Create(
                    NullLogger<CardCompatibility>.Instance,
                    envValidation
                );

                if (serviceResult.IsFailure)
                    return false;

                var service = serviceResult.Value;
                var testKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
                var keySet = Scp03KeySet.Create(testKey, testKey, testKey, 0x00).Value;
                var channel = new TestCardChannel();
                var transport = new TestApduTransport();

                var result1 = service
                    .CheckCompatibilityAsync(
                        operation,
                        keySet,
                        channel,
                        transport,
                        CancellationToken.None
                    )
                    .GetAwaiter()
                    .GetResult();

                var result2 = service
                    .CheckCompatibilityAsync(
                        operation,
                        keySet,
                        channel,
                        transport,
                        CancellationToken.None
                    )
                    .GetAwaiter()
                    .GetResult();

                return result1.IsSuccess == result2.IsSuccess
                    && (
                        result1.IsFailure
                        || (
                            result1.Value.IsCompatible == result2.Value.IsCompatible
                            && result1.Value.IsSafe == result2.Value.IsSafe
                        )
                    );
            }
        );
    }

    [Property]
    public Property All_Card_Types_Have_Defined_Compatibility()
    {
        return Prop.ForAll(
            Arb.From<CardOperation>(),
            operation =>
            {
                var envValidation = new TestEnvironmentValidationService();
                envValidation.SetValidationResult(
                    new EnvironmentValidationResult(
                        isSafe: true,
                        cardEnvironment: CardEnvironment.Test,
                        isTestKeySet: false,
                        message: "Test"
                    )
                );

                var serviceResult = CardCompatibility.Create(
                    NullLogger<CardCompatibility>.Instance,
                    envValidation
                );

                if (serviceResult.IsFailure)
                    return false;

                var service = serviceResult.Value;
                var testKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
                var keySet = Scp03KeySet.Create(testKey, testKey, testKey, 0x00).Value;
                var channel = new TestCardChannel();
                var transport = new TestApduTransport();

                var result = service
                    .CheckCompatibilityAsync(
                        operation,
                        keySet,
                        channel,
                        transport,
                        CancellationToken.None
                    )
                    .GetAwaiter()
                    .GetResult();

                return result.IsSuccess;
            }
        );
    }

    [Property]
    public Property Unsafe_Environment_Always_Results_In_Unsafe_Compatibility()
    {
        return Prop.ForAll(
            Arb.From<CardOperation>(),
            operation =>
            {
                var envValidation = new TestEnvironmentValidationService();
                envValidation.SetValidationResult(
                    new EnvironmentValidationResult(
                        isSafe: false,
                        cardEnvironment: CardEnvironment.Production,
                        isTestKeySet: true,
                        message: "Unsafe",
                        warnings: "Warning"
                    )
                );

                var serviceResult = CardCompatibility.Create(
                    NullLogger<CardCompatibility>.Instance,
                    envValidation
                );

                if (serviceResult.IsFailure)
                    return false;

                var service = serviceResult.Value;
                var testKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
                var keySet = Scp03KeySet.Create(testKey, testKey, testKey, 0x00).Value;
                var channel = new TestCardChannel();
                var transport = new TestApduTransport();

                var result = service
                    .CheckCompatibilityAsync(
                        operation,
                        keySet,
                        channel,
                        transport,
                        CancellationToken.None
                    )
                    .GetAwaiter()
                    .GetResult();

                return result.IsSuccess && !result.Value.IsSafe;
            }
        );
    }
}
