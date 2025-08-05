using System.Collections.Generic;
using System.Linq;
using Spectre.Console.Cli;

namespace Gp4Net.Tests.Tool.Commands.Applet;

/// <summary>
/// Helper class to create test command context for Spectre.Console.Cli commands.
/// </summary>
internal static class DeleteCommandTestHelpers
{
    /// <summary>
    /// Creates a minimal command context for testing.
    /// </summary>
    public static CommandContext CreateTestContext()
    {
        // Create a minimal IRemainingArguments implementation
        var remaining = new TestRemainingArguments();
            
        // Create CommandContext with minimal required parameters
        var args = new List<string>();
        return new CommandContext(args, remaining, "test", null);
    }
        
    /// <summary>
    /// Test implementation of IRemainingArguments.
    /// </summary>
    private class TestRemainingArguments : IRemainingArguments
    {
        public ILookup<string, string?> Parsed
        {
            get
            {
                return new List<(string, string?)>().ToLookup(x => x.Item1, x => x.Item2);
            }
        }
        public IReadOnlyList<string> Raw
        {
            get
            {
                return new List<string>();
            }
        }
    }
}