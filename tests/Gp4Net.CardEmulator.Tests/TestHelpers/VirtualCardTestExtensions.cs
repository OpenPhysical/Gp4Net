using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.Core;
using NUnit.Framework;

namespace Gp4Net.CardEmulator.Tests.TestHelpers;

/// <summary>
/// Extension methods to simplify test assertions for virtual card responses.
/// </summary>
public static class VirtualCardTestExtensions
{
    /// <summary>
    /// Executes a command and returns the response, failing the test if the command fails.
    /// </summary>
    public static ApduResponse ExecuteCommand(this IVirtualCard card, byte[] command)
    {
        var result = card.ProcessCommand(command);
        return result.Match(
            success => success.Response,
            error =>
            {
                Assert.Fail($"Command execution failed: {error}");
                return new ApduResponse([], 0x6F00); // Never reached
            }
        );
    }

    /// <summary>
    /// Executes a command and returns the response and updated card, failing the test if the command fails.
    /// </summary>
    public static (ApduResponse Response, IVirtualCard UpdatedCard) ExecuteCommandWithCard(
        this IVirtualCard card,
        byte[] command)
    {
        var result = card.ProcessCommand(command);
        return result.Match(
            success => success,
            error =>
            {
                Assert.Fail($"Command execution failed: {error}");
                return (new ApduResponse([], 0x6F00), card); // Never reached
            }
        );
    }

    /// <summary>
    /// Asserts that a command executes successfully and returns the response.
    /// </summary>
    public static void AssertCommandSucceeds(
        this Result<(ApduResponse Response, IVirtualCard UpdatedCard), SmartCardError> result,
        System.Action<ApduResponse> assertions)
    {
        result.Match(
            success =>
            {
                var (response, _) = success;
                assertions(response);
            },
            error => Assert.Fail($"Command failed: {error}")
        );
    }
}