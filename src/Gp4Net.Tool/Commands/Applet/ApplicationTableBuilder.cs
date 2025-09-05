using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using CSharpFunctionalExtensions;
using Gp4Net.Domain;
using Gp4Net.Tool.Common;
using static Gp4Net.Constants.Constants.GlobalPlatform;

namespace Gp4Net.Tool.Commands.Applet;

/// <summary>
/// Pure functional table builder for application information display.
/// Uses semantic row types and functional composition per CLAUDE.md patterns.
/// Eliminates imperative table building and ensures consistent formatting.
/// </summary>
public static class ApplicationTableBuilder
{
    /// <summary>
    /// Base type for all application display rows, inheriting from semantic row system.
    /// </summary>
    public abstract record ApplicationRow : SemanticTableBuilder.SemanticRow;

    /// <summary>
    /// Row displaying application information with standard columns.
    /// </summary>
    public record ApplicationDataRow(
        string Type,
        string Aid,
        string State,
        string Privileges,
        Maybe<string> Version = default,
        Maybe<string> AssociatedSecurityDomain = default
    ) : ApplicationRow;

    /// <summary>
    /// Header row for application sections.
    /// </summary>
    public record SectionHeaderRow(string Title) : ApplicationRow;

    /// <summary>
    /// Summary information row for application listing.
    /// </summary>
    public record SummaryRow(string Message) : ApplicationRow;

    /// <summary>
    /// Warning or informational message row for applications.
    /// </summary>
    public record InfoRow(string Message, string Severity = "info") : ApplicationRow;

    /// <summary>
    /// Main entry point to build all application information rows using functional composition.
    /// Returns semantic row types that can be rendered by any UI framework.
    /// </summary>
    /// <param name="applications">List of applications to display</param>
    /// <param name="showExtended">Whether to include extended columns</param>
    /// <param name="showSummary">Whether to include summary information</param>
    /// <param name="filter">Optional filter string applied to applications</param>
    /// <returns>Sequence of semantic application rows</returns>
    public static IEnumerable<ApplicationRow> BuildApplicationRows(
        IReadOnlyList<ApplicationInfo> applications,
        bool showExtended = false,
        bool showSummary = false,
        string filter = null
    )
    {
        IReadOnlyList<ApplicationInfo> filteredApps =
            string.IsNullOrEmpty(filter) || filter == "all"
                ? applications
                : FilterApplications(applications, filter);

        if (filteredApps.Count == 0)
        {
            yield return new InfoRow("No applications found", "warning");
            yield break;
        }

        // Group applications by type for better organization
        IOrderedEnumerable<IGrouping<ApplicationType, ApplicationInfo>> grouped = filteredApps
            .GroupBy(a => a.Type)
            .OrderBy(g => GetTypePriority(g.Key));

        foreach (IGrouping<ApplicationType, ApplicationInfo> group in grouped)
        {
            if (grouped.Count() > 1)
            {
                yield return new SectionHeaderRow(GetTypeDisplayName(group.Key) + "s");
            }

            foreach (ApplicationInfo app in group.OrderBy(a => Convert.ToHexString(a.Aid)))
            {
                yield return BuildApplicationDataRow(app, showExtended);
            }
        }

        if (showSummary)
        {
            yield return new SummaryRow($"Total: {filteredApps.Count} application(s)");
        }
    }

    /// <summary>
    /// Builds a single application data row with appropriate formatting.
    /// </summary>
    private static ApplicationDataRow BuildApplicationDataRow(
        ApplicationInfo app,
        bool showExtended
    )
    {
        return new ApplicationDataRow(
            Type: GetTypeDisplay(app.Type),
            Aid: $"[cyan]{Convert.ToHexString(app.Aid)}[/]",
            State: GetStateDisplay(app.LifecycleState),
            Privileges: GetPrivilegesDisplay(app.Privileges),
            Version: showExtended
                ? Maybe<string>.From(app.Version.GetValueOrDefault("-"))
                : Maybe<string>.None,
            AssociatedSecurityDomain: showExtended && app.AssociatedSecurityDomain.HasValue
                ? Maybe<string>.From(Convert.ToHexString(app.AssociatedSecurityDomain.Value))
                : Maybe<string>.From("-")
        );
    }

    /// <summary>
    /// Exports applications to JSON format using pure functions.
    /// </summary>
    public static string ToJson(IReadOnlyList<ApplicationInfo> applications)
    {
        var data = applications.Select(a => new
        {
            type = a.Type.ToString(),
            aid = Convert.ToHexString(a.Aid),
            state = a.LifecycleState.ToString(),
            privileges = a.Privileges.Select(p => p.ToString()).ToArray(),
            version = a.Version.GetValueOrDefault(),
            associatedSD = a.AssociatedSecurityDomain.HasValue
                ? Convert.ToHexString(a.AssociatedSecurityDomain.Value)
                : null,
        });

        return JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>
    /// Exports applications to CSV format using pure functions.
    /// </summary>
    public static string ToCsv(IReadOnlyList<ApplicationInfo> applications)
    {
        List<string> lines = ["Type,AID,State,Privileges,Version,AssociatedSD"];

        lines.AddRange(
            applications.Select(app =>
                $"{app.Type},"
                + $"{Convert.ToHexString(app.Aid)},"
                + $"{app.LifecycleState},"
                + $"\"{string.Join(";", app.Privileges.Select(p => p.ToString()))}\","
                + $"{app.Version.GetValueOrDefault("")},"
                + $"{(app.AssociatedSecurityDomain.HasValue ? Convert.ToHexString(app.AssociatedSecurityDomain.Value) : "")}"
            )
        );

        return string.Join(Environment.NewLine, lines);
    }

    /// <summary>
    /// Filters applications based on filter criteria using pure functions.
    /// </summary>
    private static IReadOnlyList<ApplicationInfo> FilterApplications(
        IReadOnlyList<ApplicationInfo> applications,
        string filter
    )
    {
        return filter.ToLowerInvariant() switch
        {
            "isd" => applications
                .Where(a => a.Type == ApplicationType.IssuerSecurityDomain)
                .ToList(),
            "ssd" => applications
                .Where(a => a.Type == ApplicationType.SupplementarySecurityDomain)
                .ToList(),
            "app" or "applet" => applications
                .Where(a => a.Type == ApplicationType.Application)
                .ToList(),
            "pkg" or "package" => applications
                .Where(a => a.Type == ApplicationType.LoadFile)
                .ToList(),
            "selectable" => applications
                .Where(a => a.LifecycleState == LifecycleState.Selectable)
                .ToList(),
            "locked" => applications.Where(a => a.LifecycleState == LifecycleState.Locked).ToList(),
            "installed" => applications
                .Where(a => a.LifecycleState == LifecycleState.Installed)
                .ToList(),
            _ when filter.Length >= 6 => applications
                .Where(a =>
                    Convert
                        .ToHexString(a.Aid)
                        .Contains(filter.ToUpperInvariant(), StringComparison.OrdinalIgnoreCase)
                )
                .ToList(),
            _ => applications,
        };
    }

    /// <summary>
    /// Gets the display name for an application type.
    /// </summary>
    private static string GetTypeDisplayName(ApplicationType type)
    {
        return type switch
        {
            ApplicationType.IssuerSecurityDomain => "Issuer Security Domain",
            ApplicationType.SupplementarySecurityDomain => "Supplementary Security Domain",
            ApplicationType.Application => "Application",
            ApplicationType.LoadFile => "Load File",
            ApplicationType.ExecutableLoadFile => "Executable Load File",
            _ => "Unknown",
        };
    }

    /// <summary>
    /// Gets the colored display string for an application type.
    /// </summary>
    private static string GetTypeDisplay(ApplicationType type)
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
    /// Gets the colored display string for a lifecycle state.
    /// </summary>
    private static string GetStateDisplay(LifecycleState state)
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
    /// Gets the display string for privileges.
    /// </summary>
    private static string GetPrivilegesDisplay(
        IReadOnlyList<Privilege> privileges,
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
    /// Gets the priority for ordering application types.
    /// </summary>
    private static int GetTypePriority(ApplicationType type)
    {
        return type switch
        {
            ApplicationType.IssuerSecurityDomain => 1,
            ApplicationType.SupplementarySecurityDomain => 2,
            ApplicationType.Application => 3,
            ApplicationType.LoadFile => 4,
            ApplicationType.ExecutableLoadFile => 5,
            _ => 99,
        };
    }
}
