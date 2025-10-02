using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;

namespace Gp4Net.Tool.Common;

/// <summary>
/// Base semantic table builder providing common row types and patterns.
/// Eliminates DRY violations in table building across different CLI commands.
/// Uses functional composition and type-safe row handling.
/// </summary>
public static class SemanticTableBuilder
{
    /// <summary>
    /// Base type for all semantic display rows enabling type-safe composition.
    /// </summary>
    public abstract record SemanticRow;

    /// <summary>
    /// Header row indicating the start of a section.
    /// </summary>
    /// <param name="Title">The section title to display.</param>
    public record SectionHeaderRow(string Title) : SemanticRow;

    /// <summary>
    /// Summary information row for displaying counts, totals, or conclusions.
    /// </summary>
    /// <param name="Message">The summary message to display.</param>
    public record SummaryRow(string Message) : SemanticRow;

    /// <summary>
    /// Informational message row with optional severity indicator.
    /// </summary>
    /// <param name="Message">The information message to display.</param>
    /// <param name="Severity">The severity level (info, warning, error).</param>
    public record InfoRow(string Message, string Severity = "info") : SemanticRow;

    /// <summary>
    /// Empty row for visual spacing in output.
    /// </summary>
    public record EmptyRow : SemanticRow;

    /// <summary>
    /// Generic data row with key-value pairs.
    /// </summary>
    /// <param name="Data">Dictionary of column names to values.</param>
    public record DataRow(IReadOnlyDictionary<string, string> Data) : SemanticRow;

    /// <summary>
    /// Functional composition helper for building row collections.
    /// </summary>
    /// <param name="rows">The collection of rows to compose.</param>
    /// <returns>A composed collection ready for display.</returns>
    public static IEnumerable<T> ComposeRows<T>(params IEnumerable<T>[] rows)
        where T : SemanticRow => rows.SelectMany(rowCollection => rowCollection);

    /// <summary>
    /// Adds section header and empty row for visual separation.
    /// </summary>
    /// <param name="title">The section title.</param>
    /// <param name="content">The content rows for this section.</param>
    /// <returns>Section with header and content.</returns>
    public static IEnumerable<T> CreateSection<T>(string title, IEnumerable<T> content)
        where T : SemanticRow
    {
        IEnumerable<T> headerRows =
            typeof(T).IsAssignableFrom(typeof(SectionHeaderRow))
            && typeof(T).IsAssignableFrom(typeof(EmptyRow))
                ? [(T)(SemanticRow)new SectionHeaderRow(title), (T)(SemanticRow)new EmptyRow()]
                : [];

        return headerRows.Concat(content);
    }

    /// <summary>
    /// Safely converts a semantic row to a specific type.
    /// </summary>
    /// <typeparam name="T">The target row type.</typeparam>
    /// <param name="row">The semantic row to convert.</param>
    /// <returns>Maybe containing the converted row if successful.</returns>
    public static Maybe<T> AsRowType<T>(this SemanticRow row)
        where T : SemanticRow => row is T specificRow ? Maybe<T>.From(specificRow) : Maybe<T>.None;

    /// <summary>
    /// Creates a data row from key-value pairs.
    /// </summary>
    /// <param name="data">The data pairs to include.</param>
    /// <returns>A data row containing the specified information.</returns>
    public static DataRow CreateDataRow(params (string key, string value)[] data)
    {
        var dictionary = data.ToDictionary(pair => pair.key, pair => pair.value);
        return new DataRow(dictionary);
    }
}
