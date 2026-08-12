using System;
using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using static Gp4Net.Constants.Constants.GlobalPlatform;

namespace Gp4Net.CardEmulator.Applications;

/// <summary>
/// Execution boundary for a future Java Card VM. GlobalPlatform owns selection and lifecycle;
/// the runtime owns only applet-specific command execution.
/// </summary>
public interface IAppletRuntime
{
    Result<(CardState State, ApduResponse Response), SmartCardError> Process(
        ManagedApplication application,
        byte[] command,
        CardState cardState,
        IRngContext rngContext
    );
}

/// <summary>An installed application whose executable code may be supplied by an applet runtime.</summary>
public sealed record ManagedApplication(
    ImmutableArray<byte> Aid,
    ImmutableArray<byte> ExecutableModuleAid,
    byte LifecycleState,
    Privilege Privileges,
    ImmutableArray<byte> AssociatedSecurityDomainAid,
    Maybe<IAppletRuntime> Runtime
) : IApplication
{
    public string Name => $"Application {Convert.ToHexString(Aid.AsSpan())}";

    public Result<ApplicationCommandResult, SmartCardError> ProcessCommand(
        byte[] command,
        CardState cardState,
        CardConfiguration config,
        IRngContext rngContext
    ) =>
        Runtime.Match(
            runtime =>
                runtime
                    .Process(this, command, cardState, rngContext)
                    .Map(result => new ApplicationCommandResult(
                        this,
                        result.State,
                        result.Response
                    )),
            () =>
                Result.Success<ApplicationCommandResult, SmartCardError>(
                    new ApplicationCommandResult(
                        this,
                        cardState,
                        ApduResponse.InstructionNotSupported()
                    )
                )
        );

    public bool SupportsInstruction(byte instruction) => Runtime.HasValue;

    public Maybe<Privilege> GetRequiredPrivileges(byte instruction) => Maybe<Privilege>.None;

    public Result<IApplication, SmartCardError> WithLifecycleState(byte newState) =>
        GlobalPlatformLifecycle.IsApplicationState(newState)
            ? Result.Success<IApplication, SmartCardError>(this with { LifecycleState = newState })
            : Result.Failure<IApplication, SmartCardError>(SmartCardError.ConditionsNotSatisfied());

    public IApplication WithPrivileges(Privilege newPrivileges) =>
        this with
        {
            Privileges = newPrivileges
        };
}
