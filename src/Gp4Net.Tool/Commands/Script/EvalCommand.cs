using System;
using System.ComponentModel;
using System.Threading.Tasks;
using Gp4Net.Tool.Scripting;
using JetBrains.Annotations;
using MoonSharp.Interpreter;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Script
{
    /// <summary>
    /// Command to evaluate a Lua expression.
    /// </summary>
    [PublicAPI]
    [Description("Evaluate a Lua expression")]
    public class EvalCommand : AsyncCommand<EvalCommand.Settings>
    {
        private readonly ScriptManager _scriptManager;

        /// <summary>
        /// Initializes a new instance of the EvalCommand class.
        /// </summary>
        public EvalCommand(ScriptManager scriptManager)
        {
            _scriptManager =
                scriptManager ?? throw new ArgumentNullException(nameof(scriptManager));
        }

        /// <inheritdoc />
        public override Task<int> ExecuteAsync(CommandContext context, Settings settings)
        {
            try
            {
                var result = _scriptManager.ExecuteExpression(settings.Expression);

                if (result.Type != DataType.Void && result.Type != DataType.Nil)
                {
                    Console.WriteLine(result.ToPrintString());
                }

                return Task.FromResult(0);
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Evaluation error:[/] {ex.Message}");
                if (settings.Verbose)
                {
                    AnsiConsole.WriteException(ex);
                }
                return Task.FromResult(1);
            }
        }

        /// <summary>
        /// Settings for the eval command.
        /// </summary>
        [PublicAPI]
        public class Settings : CommandSettings
        {
            /// <summary>
            /// Gets or sets the Lua expression to evaluate.
            /// </summary>
            [CommandArgument(0, "<EXPRESSION>")]
            [Description("Lua expression to evaluate")]
            public string Expression { get; set; } = string.Empty;

            /// <summary>
            /// Gets or sets whether to use verbose output.
            /// </summary>
            [CommandOption("-v|--verbose")]
            [Description("Enable verbose output")]
            public bool Verbose { get; set; }

            /// <inheritdoc />
            public override ValidationResult Validate()
            {
                if (string.IsNullOrWhiteSpace(Expression))
                {
                    return ValidationResult.Error("Expression is required");
                }

                return ValidationResult.Success();
            }
        }
    }
}
