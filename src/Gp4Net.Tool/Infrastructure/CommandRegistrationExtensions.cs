using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Gp4Net.Tool.Pipeline;
using Microsoft.Extensions.DependencyInjection;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Infrastructure;

/// <summary>
/// Extension methods for CLI command registration.
/// </summary>
public static class CommandRegistrationExtensions
{
    /// <summary>
    /// Automatically discovers and registers all CLI commands marked with CliCommandAttribute.
    /// </summary>
    public static void RegisterCliCommands(this IConfigurator config, IServiceCollection services)
    {
        Assembly assembly = Assembly.GetExecutingAssembly();
        List<Type> commandTypes = [.. assembly
            .GetTypes()
            .Where(t => t.IsClass && !t.IsAbstract)
            .Where(t => t.GetCustomAttributes<CliCommandAttribute>().Any())];

        // Group commands by branch
        Dictionary<string, List<(Type Type, CliCommandAttribute Attr)>> branches =
            new Dictionary<string, List<(Type Type, CliCommandAttribute Attr)>>();
        List<(Type Type, CliCommandAttribute Attr)> rootCommands = [];

        foreach (Type commandType in commandTypes)
        {
            List<CliCommandAttribute> attrs = [.. commandType.GetCustomAttributes<CliCommandAttribute>()];

            foreach (CliCommandAttribute attr in attrs)
            {
                if (string.IsNullOrEmpty(attr.Branch))
                {
                    rootCommands.Add((commandType, attr));
                }
                else
                {
                    if (!branches.ContainsKey(attr.Branch))
                    {
                        branches[attr.Branch] = [];
                    }
                    branches[attr.Branch].Add((commandType, attr));
                }
            }
        }

        // Register root commands
        foreach ((Type type, CliCommandAttribute attr) in rootCommands)
        {
            RegisterCommand(config, services, type, attr);
        }

        // Register branches with their commands
        foreach (
            (string branchName, List<(Type Type, CliCommandAttribute Attr)> commands) in branches
        )
        {
            _ = config.AddBranch(
                branchName,
                branch =>
                {
                    // Set branch description based on name
                    branch.SetDescription(GetBranchDescription(branchName));

                    foreach ((Type type, CliCommandAttribute attr) in commands)
                    {
                        RegisterCommand(branch, services, type, attr);
                    }
                }
            );
        }
    }

    private static void RegisterCommand(
        object config,
        IServiceCollection services,
        Type commandType,
        CliCommandAttribute attr
    )
    {
        // Check if the command implements IPipelineCommand<TSettings>
        Type pipelineInterface = commandType
            .GetInterfaces()
            .FirstOrDefault(i =>
                i.IsGenericType && i.GetGenericTypeDefinition() == typeof(IPipelineCommand<>)
            );

        Type registrationType;
        if (pipelineInterface != null)
        {
            // This is a pipeline command, wrap it with PipelineCommand<TSettings>
            Type settingsType = pipelineInterface.GetGenericArguments()[0];
            registrationType = typeof(PipelineCommand<>).MakeGenericType(settingsType);

            // Register the original command implementation for DI
            _ = services.AddTransient(pipelineInterface, commandType);
        }
        else
        {
            // This is a regular Spectre.Console.Cli command
            registrationType = commandType;
        }

        // Get the generic AddCommand method
        MethodInfo addCommandMethod = config
            .GetType()
            .GetMethods()
            .FirstOrDefault(m =>
                m.Name == "AddCommand"
                && m.IsGenericMethodDefinition
                && m.GetParameters().Length == 1
            );

        if (addCommandMethod != null)
        {
            MethodInfo genericMethod = addCommandMethod.MakeGenericMethod(registrationType);
            object commandConfig = genericMethod.Invoke(config, [attr.Name]);

            // Set description
            MethodInfo withDescriptionMethod = commandConfig
                ?.GetType()
                .GetMethod("WithDescription");
            _ = withDescriptionMethod?.Invoke(commandConfig, [attr.Description]);
        }
    }

    private static string GetBranchDescription(string branchName) =>
        branchName.ToLowerInvariant() switch
        {
            "card" => "Smart card operations (connect, info, etc.)",
            "applet" => "Applet management operations",
            "script" => "Lua scripting operations",
            "package" => "Package and CAP file operations",
            "trace" => "Trace file operations",
            _ => $"{branchName} operations",
        };
}
