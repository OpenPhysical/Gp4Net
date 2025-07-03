using System;
using System.ComponentModel;
using System.Threading.Tasks;
using Gp4Net.Tool.Scripting;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Script
{
    /// <summary>
    /// Command to execute a Lua script file.
    /// </summary>
    [PublicAPI]
    [Description("Execute a Lua script file")]
    public class ScriptCommand : AsyncCommand<ScriptCommand.Settings>
    {
        private readonly ScriptManager _scriptManager;

        /// <summary>
        /// Initializes a new instance of the ScriptCommand class.
        /// </summary>
        public ScriptCommand(ScriptManager scriptManager)
        {
            _scriptManager =
                scriptManager ?? throw new ArgumentNullException(nameof(scriptManager));
        }

        /// <inheritdoc />
        public override async Task<int> ExecuteAsync(CommandContext context, Settings settings)
        {
            try
            {
                AnsiConsole.MarkupLine($"[blue]Executing script:[/] {settings.ScriptFile}");

                _ = await _scriptManager.ExecuteScriptFileAsync(settings.ScriptFile);

                return 0;
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Script error:[/] {ex.Message}");
                if (settings.Verbose)
                {
                    AnsiConsole.WriteException(ex);
                }
                return 1;
            }
        }

        /// <summary>
        /// Settings for the script command.
        /// </summary>
        [PublicAPI]
        public class Settings : CommandSettings
        {
            /// <summary>
            /// Gets or sets the script file to execute.
            /// </summary>
            [CommandArgument(0, "<SCRIPT_FILE>")]
            [Description("Path to the Lua script file to execute")]
            public string ScriptFile { get; set; } = string.Empty;

            /// <summary>
            /// Gets or sets whether to use verbose output.
            /// </summary>
            [CommandOption("-v|--verbose")]
            [Description("Enable verbose output")]
            public bool Verbose { get; set; }

            /// <inheritdoc />
            public override ValidationResult Validate()
            {
                if (string.IsNullOrWhiteSpace(ScriptFile))
                {
                    return ValidationResult.Error("Script file path is required");
                }

                return ValidationResult.Success();
            }
        }
    }
}
