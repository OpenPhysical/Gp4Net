using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using Gp4Net.Tool.Services;
using Spectre.Console;

namespace Gp4Net.Tool.Infrastructure
{
    /// <summary>
    /// Type converter for smart card reader names that supports:
    /// - Partial name matching (case-insensitive)
    /// - Auto-detection with user prompts
    /// - Intelligent error handling
    /// </summary>
    public class ReaderNameTypeConverter : TypeConverter
    {
        /// <inheritdoc />
        public override bool CanConvertFrom(ITypeDescriptorContext? context, Type sourceType)
        {
            return sourceType == typeof(string) || base.CanConvertFrom(context, sourceType);
        }

        /// <inheritdoc />
        public override object? ConvertFrom(
            ITypeDescriptorContext? context,
            CultureInfo? culture,
            object value
        )
        {
            if (value is string stringValue || value is null)
            {
                // Get the card service from the context
                var cardService = GetCardServiceFromContext(context);
                if (cardService == null)
                {
                    throw new InvalidOperationException(
                        "CardService not available in conversion context"
                    );
                }

                var inputValue = value as string ?? string.Empty;
                return ResolveReader(inputValue, cardService);
            }

            return base.ConvertFrom(context, culture, value);
        }

        /// <summary>
        /// Resolves a reader from the input string.
        /// </summary>
        /// <param name="input">The input reader specification.</param>
        /// <param name="cardService">The card service for reader enumeration.</param>
        /// <returns>The resolved reader.</returns>
        private static Reader ResolveReader(string input, ICardService cardService)
        {
            if (string.IsNullOrWhiteSpace(input))
            {
                input = "auto";
            }

            // Handle explicit JSON reader specification
            if (input.StartsWith("json:", StringComparison.OrdinalIgnoreCase))
            {
                // JSON readers are not discoverable, but can be explicitly used
                return new Reader(input);
            }

            // Get all available readers
            var allReaders = cardService.GetReaders();

            if (allReaders.Count == 0)
            {
                throw new ArgumentException(
                    "No card readers found. Please ensure a card reader is connected and drivers are installed."
                );
            }

            // Handle "auto" mode
            if (string.Equals(input, "auto", StringComparison.OrdinalIgnoreCase))
            {
                return HandleAutoDetection(allReaders);
            }

            // Try exact match first (case-insensitive)
            var exactMatch = allReaders.FirstOrDefault(r =>
                string.Equals(r, input, StringComparison.OrdinalIgnoreCase)
            );

            if (exactMatch != null)
            {
                return new Reader(exactMatch);
            }

            // Try partial match (case-insensitive)
            var partialMatches = allReaders
                .Where(r => r.Contains(input, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (partialMatches.Count == 1)
            {
                var selectedReader = partialMatches[0];
                AnsiConsole.MarkupLine(
                    $"[yellow]Using reader with partial match:[/] {selectedReader}"
                );
                return new Reader(selectedReader, isPartialMatch: true);
            }

            if (partialMatches.Count > 1)
            {
                AnsiConsole.MarkupLine($"[yellow]Multiple readers found matching '{input}':[/]");
                var selected = PromptUserToSelectReader(partialMatches);
                return new Reader(selected, isPartialMatch: true);
            }

            // No matches found
            AnsiConsole.MarkupLine($"[red]No reader found matching '{input}'.[/]");
            AnsiConsole.MarkupLine("[yellow]Available readers:[/]");

            foreach (var reader in allReaders)
            {
                AnsiConsole.MarkupLine($"  • {reader}");
            }

            throw new ArgumentException(
                $"Reader '{input}' not found. Use exact name, partial name, or 'auto' for automatic detection."
            );
        }

        /// <summary>
        /// Handles automatic reader detection.
        /// </summary>
        /// <param name="readers">List of available readers.</param>
        /// <returns>The selected reader.</returns>
        private static Reader HandleAutoDetection(IReadOnlyList<string> readers)
        {
            if (readers.Count == 1)
            {
                var selectedReader = readers[0];
                AnsiConsole.MarkupLine($"[green]Auto-detected reader:[/] {selectedReader}");
                return new Reader(selectedReader, isAutoDetected: true);
            }

            // Multiple readers found - prompt user to choose
            AnsiConsole.MarkupLine("[yellow]Multiple card readers detected:[/]");
            var selected = PromptUserToSelectReader(readers);
            return new Reader(selected, isAutoDetected: true);
        }

        /// <summary>
        /// Prompts the user to select a reader from the available options.
        /// </summary>
        /// <param name="readers">List of available readers.</param>
        /// <returns>The selected reader name.</returns>
        private static string PromptUserToSelectReader(IReadOnlyList<string> readers)
        {
            var prompt = new SelectionPrompt<string>()
                .Title("Please select a card reader:")
                .AddChoices(readers)
                .HighlightStyle(Style.Parse("bold cyan"));

            return AnsiConsole.Prompt(prompt);
        }

        /// <summary>
        /// Gets the card service from the conversion context.
        /// </summary>
        /// <param name="context">The type descriptor context.</param>
        /// <returns>The card service if available.</returns>
        private static ICardService? GetCardServiceFromContext(ITypeDescriptorContext? context)
        {
            try
            {
                return CardServiceProvider.GetCardService();
            }
            catch (InvalidOperationException)
            {
                return null;
            }
        }
    }
}
