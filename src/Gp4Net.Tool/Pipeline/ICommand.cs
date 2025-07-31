using System.Threading.Tasks;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Pipeline
{
    /// <summary>
    /// Interface for commands using the new pipeline architecture.
    /// </summary>
    /// <typeparam name="TSettings">The settings type for the command.</typeparam>
    public interface IPipelineCommand<TSettings>
        where TSettings : CommandSettings
    {
        /// <summary>
        /// Executes the command with the provided context and settings.
        /// </summary>
        Task<int> ExecuteAsync(ICliExecutionContext context, TSettings settings);
    }
}
