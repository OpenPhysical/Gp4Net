using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Gp4Net.Tool.Commands.Applet;
using Gp4Net.Tool.Commands.Card;
using Gp4Net.Tool.Pipeline;
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
    public static void RegisterCliCommands(this IConfigurator config, TypeRegistrar registrar)
    {
        var branches = new Dictionary<string, List<CommandCatalog.Entry>>();
        List<CommandCatalog.Entry> rootCommands = [];

        foreach (var entry in CommandCatalog.All)
        {
            if (entry.Branch.Length == 0)
            {
                rootCommands.Add(entry);
            }
            else
            {
                if (!branches.TryGetValue(entry.Branch, out var commands))
                {
                    commands = [];
                    branches[entry.Branch] = commands;
                }
                commands.Add(entry);
            }
        }

        // Register root commands
        foreach (var entry in rootCommands)
        {
            RegisterCommand(config, registrar, entry);
        }

        // Register branches with their commands
        foreach ((string branchName, var commands) in branches)
        {
            _ = config.AddBranch(
                branchName,
                branch =>
                {
                    // Set branch description based on name
                    branch.SetDescription(GetBranchDescription(branchName));

                    foreach (var entry in commands)
                    {
                        RegisterCommand(branch, registrar, entry);
                    }
                }
            );
        }
    }

    private static void RegisterCommand(
        object config,
        TypeRegistrar registrar,
        CommandCatalog.Entry entry
    )
    {
        Type commandType = entry.CommandType;
        // Check if the command implements IPipelineCommand<TSettings>
        var pipelineInterfaces = commandType
            .GetInterfaces()
            .Where(i =>
                i.IsGenericType && i.GetGenericTypeDefinition() == typeof(IPipelineCommand<>)
            )
            .ToArray();

        Type registrationType;
        if (pipelineInterfaces.Length > 0)
        {
            // This is a pipeline command, wrap it with PipelineCommand<TSettings>
            var pipelineInterface = pipelineInterfaces[0];
            var settingsType = pipelineInterface.GetGenericArguments()[0];
            registrationType = typeof(PipelineCommand<>).MakeGenericType(settingsType);

            registrar.Register(pipelineInterface, commandType);
        }
        else
        {
            // This is a regular Spectre.Console.Cli command
            registrationType = commandType;
        }

        // Get the generic AddCommand method
        var addCommandMethods = config
            .GetType()
            .GetMethods()
            .Where(m =>
                m.Name == "AddCommand"
                && m.IsGenericMethodDefinition
                && m.GetParameters().Length == 1
            )
            .ToArray();

        if (addCommandMethods.Length == 0)
        {
            throw new InvalidOperationException("Spectre command registration API was not found");
        }

        var genericMethod = addCommandMethods[0].MakeGenericMethod(registrationType);
        if (genericMethod.Invoke(config, [entry.Name]) is not object commandConfig)
        {
            throw new InvalidOperationException($"Unable to register command {entry.Name}");
        }

        var descriptionMethods = commandConfig
            .GetType()
            .GetMethods()
            .Where(method => method.Name == "WithDescription")
            .ToArray();
        if (descriptionMethods.Length > 0)
        {
            _ = descriptionMethods[0].Invoke(commandConfig, [entry.Description]);
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

/// <summary>
/// The explicit, immutable set of commands exposed by the CLI.
/// </summary>
public static class CommandCatalog
{
    public sealed record Entry(Type CommandType, string Name, string Description, string Branch);

    public static IReadOnlyList<Entry> All { get; } =
        [
            new(typeof(ListReadersCommand), "list-readers", "List available card readers", "card"),
            new(typeof(ConnectCommand), "connect", "Connect to a smart card", "card"),
            new(typeof(InfoCommand), "info", "Display detailed card information", "card"),
            new(
                typeof(TestSecureChannelCommand),
                "test-sc",
                "Test secure channel establishment with GP test keys",
                "card"
            ),
            new(
                typeof(KeysChangeCommand),
                "change-keys",
                "Change cryptographic keys on the card",
                "card"
            ),
            new(
                typeof(GetIsdDataCommand),
                "get-data",
                "Retrieve data objects from the card",
                "card"
            ),
            new(typeof(PutIsdDataCommand), "put-data", "Write data objects to the card", "card"),
            new(
                typeof(InstantiateCliCommand),
                "instantiate",
                "Instantiate an applet from a loaded package",
                "applet"
            ),
            new(typeof(InstallCliCommand), "install", "Install a CAP file on the card", "applet"),
            new(typeof(LoadCommand), "load", "Load a package onto the card", "applet"),
            new(typeof(StatusCommand), "status", "List card content and lifecycle state", "applet"),
            new(
                typeof(LifecycleCommand),
                "lifecycle",
                "Change an application lifecycle state",
                "applet"
            ),
            new(typeof(DeleteCommand), "delete", "Delete an applet from the card", "applet"),
            new(typeof(DeleteCommand), "uninstall", "Uninstall an applet from the card", "applet"),
            new(typeof(ListCliCommand), "list", "List applications on the card", "applet"),
            new(
                typeof(ValidateCommand),
                "validate",
                "Validate a CAP file without installing it",
                "applet"
            ),
        ];

    public static string DeriveCommandName(string className)
    {
        string baseName = className.EndsWith("Command", StringComparison.Ordinal)
            ? className[..^7]
            : className;
        return string.Concat(
            baseName.Select(
                (character, index) =>
                    index > 0 && char.IsUpper(character)
                        ? $"-{char.ToLowerInvariant(character)}"
                        : char.ToLowerInvariant(character).ToString()
            )
        );
    }
}
