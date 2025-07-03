using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Infrastructure
{
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
            var assembly = Assembly.GetExecutingAssembly();
            var commandTypes = assembly.GetTypes()
                .Where(t => t.IsClass && !t.IsAbstract)
                .Where(t => t.GetCustomAttributes<CliCommandAttribute>().Any())
                .ToList();

            // Group commands by branch
            var branches = new Dictionary<string, List<(Type Type, CliCommandAttribute Attr)>>();
            var rootCommands = new List<(Type Type, CliCommandAttribute Attr)>();

            foreach (var commandType in commandTypes)
            {
                var attrs = commandType.GetCustomAttributes<CliCommandAttribute>().ToList();
                
                foreach (var attr in attrs)
                {
                    if (string.IsNullOrEmpty(attr.Branch))
                    {
                        rootCommands.Add((commandType, attr));
                    }
                    else
                    {
                        if (!branches.ContainsKey(attr.Branch))
                        {
                            branches[attr.Branch] = new List<(Type, CliCommandAttribute)>();
                        }
                        branches[attr.Branch].Add((commandType, attr));
                    }
                }
            }

            // Register root commands
            foreach (var (type, attr) in rootCommands)
            {
                RegisterCommand(config, type, attr);
            }

            // Register branches with their commands
            foreach (var (branchName, commands) in branches)
            {
                config.AddBranch(branchName, branch =>
                {
                    // Set branch description based on name
                    branch.SetDescription(GetBranchDescription(branchName));
                    
                    foreach (var (type, attr) in commands)
                    {
                        RegisterCommand(branch, type, attr);
                    }
                });
            }
        }

        private static void RegisterCommand(object config, Type commandType, CliCommandAttribute attr)
        {
            // Get the generic AddCommand method
            var addCommandMethod = config.GetType()
                .GetMethods()
                .FirstOrDefault(m => m.Name == "AddCommand" && 
                                   m.IsGenericMethodDefinition && 
                                   m.GetParameters().Length == 1);

            if (addCommandMethod != null)
            {
                var genericMethod = addCommandMethod.MakeGenericMethod(commandType);
                var commandConfig = genericMethod.Invoke(config, new object[] { attr.Name });
                
                // Set description
                var withDescriptionMethod = commandConfig?.GetType().GetMethod("WithDescription");
                withDescriptionMethod?.Invoke(commandConfig, new object[] { attr.Description });
            }
        }

        private static string GetBranchDescription(string branchName) => branchName.ToLowerInvariant() switch
        {
            "card" => "Smart card operations (connect, info, etc.)",
            "applet" => "Applet management operations",
            "script" => "Lua scripting operations",
            "package" => "Package and CAP file operations",
            "trace" => "Trace file operations",
            _ => $"{branchName} operations"
        };
    }
}