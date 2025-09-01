using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;

namespace Gp4Net.Tool.Pipeline;

/// <summary>
/// Service for automatically registering commands with the CommandHandler attribute.
/// </summary>
[PublicAPI]
public static class CommandRegistrationService
{
    /// <summary>
    /// Registers all commands marked with CommandHandler attribute from the specified assembly.
    /// </summary>
    public static void RegisterCommandHandlers(this IServiceCollection services, Assembly assembly)
    {
        List<Type> commandTypes = [.. assembly
            .GetTypes()
            .Where(type => type.GetCustomAttribute<CommandHandlerAttribute>() != null)
            .Where(type => !type.IsAbstract && !type.IsInterface)];

        foreach (Type commandType in commandTypes)
        {
            // Find the ICommand<TSettings> interface
            Type commandInterface = commandType
                .GetInterfaces()
                .FirstOrDefault(i =>
                    i.IsGenericType && i.GetGenericTypeDefinition() == typeof(IPipelineCommand<>)
                );

            if (commandInterface == null)
            {
                continue;
            }

            Type settingsType = commandInterface.GetGenericArguments()[0];

            // Register the command implementation
            _ = services.AddTransient(commandInterface, commandType);

            // Create and register the pipeline command adapter
            Type pipelineCommandType = typeof(PipelineCommand<>).MakeGenericType(settingsType);
            _ = services.AddTransient(pipelineCommandType);
        }
    }

    /// <summary>
    /// Gets information about all command handlers in the assembly.
    /// </summary>
    public static IEnumerable<CommandHandlerInfo> GetCommandHandlers(Assembly assembly)
    {
        List<Type> commandTypes = [.. assembly
            .GetTypes()
            .Where(type => type.GetCustomAttribute<CommandHandlerAttribute>() != null)
            .Where(type => !type.IsAbstract && !type.IsInterface)];

        foreach (Type commandType in commandTypes)
        {
            CommandHandlerAttribute attribute =
                commandType.GetCustomAttribute<CommandHandlerAttribute>()!;
            Type commandInterface = commandType
                .GetInterfaces()
                .FirstOrDefault(i =>
                    i.IsGenericType && i.GetGenericTypeDefinition() == typeof(IPipelineCommand<>)
                );

            if (commandInterface == null)
            {
                continue;
            }

            Type settingsType = commandInterface.GetGenericArguments()[0];
            Type pipelineCommandType = typeof(PipelineCommand<>).MakeGenericType(settingsType);

            // Derive command name from class name if not specified
            string commandName = attribute.CommandName ?? DeriveCommandName(commandType.Name);

            yield return new CommandHandlerInfo
            {
                CommandName = commandName,
                Description = attribute.Description,
                CommandType = commandType,
                SettingsType = settingsType,
                PipelineCommandType = pipelineCommandType,
            };
        }
    }

    private static string DeriveCommandName(string className)
    {
        // Convert "ListReadersCommand" to "list-readers"
        if (className.EndsWith("Command"))
        {
            className = className[..^7]; // Remove "Command" suffix
        }

        string result = "";
        for (int i = 0; i < className.Length; i++)
        {
            if (i > 0 && char.IsUpper(className[i]))
            {
                result += "-";
            }
            result += char.ToLower(className[i]);
        }

        return result;
    }
}

/// <summary>
/// Information about a command handler.
/// </summary>
[PublicAPI]
public class CommandHandlerInfo
{
    /// <summary>
    /// Gets or sets the command name.
    /// </summary>
    public string CommandName { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the command description.
    /// </summary>
    public string Description { get; set; }

    /// <summary>
    /// Gets or sets the command implementation type.
    /// </summary>
    public Type CommandType { get; set; } = null!;

    /// <summary>
    /// Gets or sets the settings type.
    /// </summary>
    public Type SettingsType { get; set; } = null!;

    /// <summary>
    /// Gets or sets the pipeline command adapter type.
    /// </summary>
    public Type PipelineCommandType { get; set; } = null!;
}
