using System;

namespace Gp4Net.Tool.Infrastructure;

/// <summary>
/// Attribute to mark CLI commands with metadata.
/// </summary>
[AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = true)]
public class CliCommandAttribute : Attribute
{
    /// <summary>
    /// Gets the command name.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// Gets the command description.
    /// </summary>
    public string Description { get; }

    /// <summary>
    /// Gets the parent branch name for nested commands.
    /// </summary>
    public string? Branch { get; }

    /// <summary>
    /// Gets whether this is an alias.
    /// </summary>
    public bool IsAlias { get; }

    /// <summary>
    /// Initializes a new instance of the CliCommandAttribute class.
    /// </summary>
    /// <param name="name">The command name.</param>
    /// <param name="description">The command description.</param>
    /// <param name="branch">The parent branch name (e.g., "card", "applet", "script").</param>
    /// <param name="isAlias">Whether this is an alias for another command.</param>
    public CliCommandAttribute(string name, string description, string? branch = null, bool isAlias = false)
    {
        Name = name ?? throw new ArgumentNullException(nameof(name));
        Description = description ?? throw new ArgumentNullException(nameof(description));
        Branch = branch;
        IsAlias = isAlias;
    }
}