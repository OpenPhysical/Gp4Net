using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text.Json;
using Gp4Net.Domain;
using Spectre.Console;
using static Gp4Net.Constants.Constants.GlobalPlatform;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Service for displaying application information consistently across commands.
/// </summary>
public class ApplicationDisplayService
{
    /// <summary>
    /// Gets the display name for an application type.
    /// </summary>
    /// <param name="type">The application type.</param>
    /// <returns>The display name.</returns>
    public static string GetTypeDisplayName(ApplicationType type)
    {
        return type switch
        {
            ApplicationType.IssuerSecurityDomain => "ISD",
            ApplicationType.SupplementarySecurityDomain => "SSD",
            ApplicationType.Application => "Applet",
            ApplicationType.LoadFile => "Load File",
            ApplicationType.ExecutableLoadFile => "Executable Load File",
            _ => "Unknown",
        };
    }

    /// <summary>
    /// Gets the colored display string for an application type.
    /// </summary>
    /// <param name="type">The application type.</param>
    /// <returns>The colored display string.</returns>
    public static string GetTypeDisplay(ApplicationType type)
    {
        return type switch
        {
            ApplicationType.IssuerSecurityDomain => "[red]ISD[/]",
            ApplicationType.SupplementarySecurityDomain => "[yellow]SSD[/]",
            ApplicationType.Application => "[green]App[/]",
            ApplicationType.LoadFile => "[blue]Pkg[/]",
            ApplicationType.ExecutableLoadFile => "[blue]Exec[/]",
            _ => type.ToString(),
        };
    }

    /// <summary>
    /// Gets the color for an application type.
    /// </summary>
    /// <param name="type">The application type.</param>
    /// <returns>The color name.</returns>
    public static string GetTypeColor(ApplicationType type)
    {
        return type switch
        {
            ApplicationType.IssuerSecurityDomain => "blue",
            ApplicationType.SupplementarySecurityDomain => "purple",
            ApplicationType.Application => "green",
            ApplicationType.LoadFile => "yellow",
            ApplicationType.ExecutableLoadFile => "yellow",
            _ => "white",
        };
    }

    /// <summary>
    /// Gets the colored display string for a lifecycle state.
    /// </summary>
    /// <param name="state">The lifecycle state.</param>
    /// <returns>The colored display string.</returns>
    public static string GetStateDisplay(LifecycleState state)
    {
        return state switch
        {
            LifecycleState.Selectable => "[green]Selectable[/]",
            LifecycleState.Personalized => "[blue]Personalized[/]",
            LifecycleState.Locked => "[red]Locked[/]",
            LifecycleState.Installed => "[cyan]Installed[/]",
            LifecycleState.Terminated => "[red]Terminated[/]",
            _ => state.ToString(),
        };
    }

    /// <summary>
    /// Gets the color for a lifecycle state.
    /// </summary>
    /// <param name="state">The lifecycle state.</param>
    /// <returns>The color name.</returns>
    public static string GetStateColor(LifecycleState state)
    {
        return state switch
        {
            LifecycleState.Selectable => "green",
            LifecycleState.Personalized => "cyan",
            LifecycleState.Locked => "red",
            LifecycleState.Installed => "cyan",
            LifecycleState.Terminated => "red",
            _ => "yellow",
        };
    }

    /// <summary>
    /// Gets the display string for privileges.
    /// </summary>
    /// <param name="privileges">The privileges.</param>
    /// <param name="maxDisplayCount">Maximum number of privileges to display before truncating.</param>
    /// <returns>The display string.</returns>
    public static string GetPrivilegesDisplay(
        ImmutableList<Privilege> privileges,
        int maxDisplayCount = 3
    )
    {
        if (privileges.Count == 0)
        {
            return "[dim]-[/]";
        }

        if (privileges.Count <= maxDisplayCount)
        {
            return string.Join(", ", privileges.Select(p => p.ToString()));
        }

        return $"{string.Join(", ", privileges.Take(maxDisplayCount - 1).Select(p => p.ToString()))}, [dim]+{privileges.Count - (maxDisplayCount - 1)} more[/]";
    }

    /// <summary>
    /// Gets the simple privileges display string without markup.
    /// </summary>
    /// <param name="privileges">The privileges.</param>
    /// <returns>The display string.</returns>
    public static string GetPrivilegesDisplaySimple(ImmutableList<Privilege> privileges)
    {
        return privileges.Count > 0
            ? string.Join(", ", privileges.Select(p => p.ToString()))
            : "None";
    }

    /// <summary>
    /// Creates a table for displaying applications.
    /// </summary>
    /// <param name="extended">Whether to include extended columns.</param>
    /// <returns>A configured table.</returns>
    public static Table CreateApplicationTable(bool extended = false)
    {
        var table = new Table();

        // Basic columns
        _ = table.AddColumn("Type");
        _ = table.AddColumn("AID");
        _ = table.AddColumn("State");
        _ = table.AddColumn("Privileges");

        // Extended columns
        if (extended)
        {
            _ = table.AddColumn("Version");
            _ = table.AddColumn("Assoc. SD");
        }

        return table;
    }

    /// <summary>
    /// Adds an application row to a table.
    /// </summary>
    /// <param name="table">The table to add to.</param>
    /// <param name="app">The application info.</param>
    /// <param name="extended">Whether to include extended columns.</param>
    public static void AddApplicationRow(Table table, ApplicationInfo app, bool extended = false)
    {
        List<string> row =
        [
            GetTypeDisplay(app.Type),
            $"[cyan]{Convert.ToHexString(app.Aid)}[/]",
            GetStateDisplay(app.LifecycleState),
            GetPrivilegesDisplay(app.Privileges),
        ];

        if (extended)
        {
            row.Add(app.Version.GetValueOrDefault("-"));
            row.Add(
                app.AssociatedSecurityDomain.HasValue
                    ? Convert.ToHexString(app.AssociatedSecurityDomain.Value)
                    : "-"
            );
        }

        _ = table.AddRow(row.ToArray());
    }

    /// <summary>
    /// Displays applications in table format.
    /// </summary>
    /// <param name="applications">The applications to display.</param>
    /// <param name="extended">Whether to show extended information.</param>
    public static void DisplayApplicationTable(
        IReadOnlyList<ApplicationInfo> applications,
        bool extended = false
    )
    {
        var table = CreateApplicationTable(extended);

        foreach (var app in applications)
        {
            AddApplicationRow(table, app, extended);
        }

        AnsiConsole.Write(table);
    }

    /// <summary>
    /// Displays applications in JSON format.
    /// </summary>
    /// <param name="applications">The applications to display.</param>
    public static void DisplayApplicationsJson(IReadOnlyList<ApplicationInfo> applications)
    {
        string json = JsonSerializer.Serialize(
            applications.Select(a => new
            {
                type = a.Type.ToString(),
                aid = Convert.ToHexString(a.Aid),
                state = a.LifecycleState.ToString(),
                privileges = a.Privileges.Select(p => p.ToString()).ToArray(),
                version = a.Version,
                associatedSD = a.AssociatedSecurityDomain.HasValue
                    ? Convert.ToHexString(a.AssociatedSecurityDomain.Value)
                    : null,
            }),
            new JsonSerializerOptions { WriteIndented = true }
        );

        Console.WriteLine(json);
    }

    /// <summary>
    /// Displays applications in CSV format.
    /// </summary>
    /// <param name="applications">The applications to display.</param>
    public static void DisplayApplicationsCsv(IReadOnlyList<ApplicationInfo> applications)
    {
        Console.WriteLine("Type,AID,State,Privileges,Version,AssociatedSD");

        foreach (var app in applications)
        {
            Console.WriteLine(
                $"{app.Type},"
                    + $"{Convert.ToHexString(app.Aid)},"
                    + $"{app.LifecycleState},"
                    + $"\"{string.Join(";", app.Privileges.Select(p => p.ToString()))}\","
                    + $"{app.Version.GetValueOrDefault("")},"
                    + $"{(app.AssociatedSecurityDomain.HasValue ? Convert.ToHexString(app.AssociatedSecurityDomain.Value) : "")}"
            );
        }
    }

    /// <summary>
    /// Displays detailed information about applications.
    /// </summary>
    /// <param name="applications">The applications to display.</param>
    public static void DisplayDetailedInformation(IReadOnlyList<ApplicationInfo> applications)
    {
        var groups = applications.GroupBy(a => a.Type);

        foreach (var group in groups)
        {
            AnsiConsole.MarkupLine($"[bold]{group.Key}s:[/]");

            foreach (var app in group)
            {
                var panel = new Panel(
                    $"[dim]AID:[/] {Convert.ToHexString(app.Aid)}\n"
                        + $"[dim]State:[/] {app.LifecycleState}\n"
                        + $"[dim]Privileges:[/] {GetPrivilegesDisplaySimple(app.Privileges)}"
                )
                {
                    Header = new PanelHeader($"[bold]{GetTypeDisplayName(app.Type)}[/]"),
                };

                AnsiConsole.Write(panel);
            }

            AnsiConsole.WriteLine();
        }
    }

    /// <summary>
    /// Filters applications by type.
    /// </summary>
    /// <param name="applications">The applications to filter.</param>
    /// <param name="filter">The filter type.</param>
    /// <returns>The filtered applications.</returns>
    public static IReadOnlyList<ApplicationInfo> FilterApplications(
        IReadOnlyList<ApplicationInfo> applications,
        string filter
    )
    {
        return filter.ToLowerInvariant() switch
        {
            "isd"
                => applications.Where(a => a.Type == ApplicationType.IssuerSecurityDomain).ToList(),
            "apps"
            or "applets"
                => applications.Where(a => a.Type == ApplicationType.Application).ToList(),
            "packages" => applications.Where(a => a.Type == ApplicationType.LoadFile).ToList(),
            "ssd"
                => applications
                    .Where(a => a.Type == ApplicationType.SupplementarySecurityDomain)
                    .ToList(),
            _ => applications,
        };
    }
}
