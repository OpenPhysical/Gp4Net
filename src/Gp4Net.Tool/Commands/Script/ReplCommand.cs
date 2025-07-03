using System;
using System.ComponentModel;
using System.Threading.Tasks;
using Gp4Net.Tool.Scripting;
using JetBrains.Annotations;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Script
{
    /// <summary>
    /// Command to start an interactive Lua REPL.
    /// </summary>
    [PublicAPI]
    [Description("Start an interactive Lua REPL (Read-Eval-Print Loop)")]
    public class ReplCommand : AsyncCommand<ReplCommand.Settings>
    {
        private readonly ScriptManager _scriptManager;

        /// <summary>
        /// Initializes a new instance of the ReplCommand class.
        /// </summary>
        public ReplCommand(ScriptManager scriptManager)
        {
            _scriptManager =
                scriptManager ?? throw new ArgumentNullException(nameof(scriptManager));
        }

        /// <inheritdoc />
        public override Task<int> ExecuteAsync(CommandContext context, Settings settings)
        {
            _scriptManager.StartRepl();
            return Task.FromResult(0);
        }

        /// <summary>
        /// Settings for the REPL command.
        /// </summary>
        [PublicAPI]
        public class Settings : CommandSettings { }
    }
}
