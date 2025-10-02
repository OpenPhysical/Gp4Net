using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Pipeline;
using Gp4Net.Services;
using Gp4Net.Tool.Commands;
using WSCT.ISO7816;

namespace Gp4Net.Tool.Extensions;

/// <summary>
/// Extension methods for SmartCardService to support CLI logging configuration.
/// </summary>
public static class SmartCardServiceExtensions
{
    /// <summary>
    /// Creates a command executor function with logging settings from command settings.
    /// </summary>
    /// <param name="service">The smart card service.</param>
    /// <param name="settings">The command settings containing logging configuration.</param>
    /// <param name="useSecureChannel">Whether to use secure channel.</param>
    /// <returns>A function that can be used with higher-level services.</returns>
    public static Func<
        CommandAPDU,
        CancellationToken,
        Task<Result<CommandResponse, SmartCardError>>
    > CreateExecutor(
        this ISmartCardService service,
        StandardCommandSettings settings,
        bool useSecureChannel = false
    )
    {
        var options = settings.GetCommandOptions();
        var finalOptions = options with { UseSecureChannel = useSecureChannel };

        return (command, ct) => service.ExecuteCommandAsync(command, finalOptions, ct);
    }

    /// <summary>
    /// Creates a command executor function with logging settings from card command settings.
    /// </summary>
    /// <param name="service">The smart card service.</param>
    /// <param name="settings">The card command settings containing logging configuration.</param>
    /// <param name="useSecureChannel">Whether to use secure channel.</param>
    /// <returns>A function that can be used with higher-level services.</returns>
    public static Func<
        CommandAPDU,
        CancellationToken,
        Task<Result<CommandResponse, SmartCardError>>
    > CreateExecutor(
        this ISmartCardService service,
        CardCommandSettings settings,
        bool useSecureChannel = false
    )
    {
        var options = settings.GetCommandOptions(useSecureChannel);

        return (command, ct) => service.ExecuteCommandAsync(command, options, ct);
    }

    /// <summary>
    /// Creates a command executor function with logging settings from secure command settings.
    /// </summary>
    /// <param name="service">The smart card service.</param>
    /// <param name="settings">The secure command settings containing logging configuration.</param>
    /// <param name="useSecureChannel">Whether to use secure channel.</param>
    /// <returns>A function that can be used with higher-level services.</returns>
    public static Func<
        CommandAPDU,
        CancellationToken,
        Task<Result<CommandResponse, SmartCardError>>
    > CreateExecutor(
        this ISmartCardService service,
        SecureCommandSettings settings,
        bool useSecureChannel = true
    )
    {
        var options = settings.GetCommandOptions(useSecureChannel);

        return (command, ct) => service.ExecuteCommandAsync(command, options, ct);
    }
}
