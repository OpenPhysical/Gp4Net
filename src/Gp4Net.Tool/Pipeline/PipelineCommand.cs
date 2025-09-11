using System;
using System.Reflection;
using System.Threading.Tasks;
using JetBrains.Annotations;
using log4net;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Pipeline;

/// <summary>
/// Adapter that bridges the new pipeline architecture with Spectre.Console.Cli.
/// </summary>
/// <typeparam name="TSettings">The settings type for the command.</typeparam>
[PublicAPI]
public class PipelineCommand<TSettings> : AsyncCommand<TSettings>
    where TSettings : CommandSettings
{
    private static readonly ILog Logger = LogManager.GetLogger(typeof(PipelineCommand<TSettings>));

    private readonly IPipelineCommand<TSettings> _command;
    private readonly ICliExecutionContext _context;

    public PipelineCommand(IPipelineCommand<TSettings> command, ICliExecutionContext context)
    {
        _command = command ?? throw new ArgumentNullException(nameof(command));
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    public override async Task<int> ExecuteAsync(CommandContext context, TSettings settings)
    {
        try
        {
            bool isVerbose = IsVerboseEnabled(settings);

            // Dynamically add console appender for verbose logging if needed
            VerboseLoggingHelper.EnableVerboseLogging(isVerbose);

            if (isVerbose)
            {
                Logger.Info($"Executing command: {_command.GetType().Name}");
            }

            return await _command.ExecuteAsync(_context, settings);
        }
        catch (Exception ex)
        {
            Logger.Error($"Command execution failed: {ex.Message}", ex);
            _context.Display.Exception(ex);
            return 1;
        }
    }

    /// <summary>
    /// Checks if verbose mode is enabled using reflection.
    /// </summary>
    private static bool IsVerboseEnabled(TSettings settings)
    {
        var verboseProperty = typeof(TSettings).GetProperty(
            "Verbose",
            BindingFlags.Public | BindingFlags.Instance
        );
        return verboseProperty?.GetValue(settings) as bool? == true;
    }
}
