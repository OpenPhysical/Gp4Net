using System;
using System.Linq;
using System.Threading.Tasks;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Card
{
    /// <summary>
    /// Command to display detailed card information.
    /// </summary>
    [PublicAPI]
    public class InfoCommand : BaseCommand<InfoCommand.Settings>
    {
        /// <summary>
        /// Initializes a new instance of the InfoCommand class.
        /// </summary>
        public InfoCommand(ICardService cardService, IGlobalPlatformService globalPlatformService)
            : base(cardService, globalPlatformService)
        {
        }

        /// <inheritdoc />
        protected override Task<int> ExecuteCommandAsync(CommandContext context, Settings settings)
        {
            if (!EnsureCardConnection(settings))
            {
                return Task.FromResult(1);
            }

            try
            {
                var table = new Table()
                    .AddColumn("Property")
                    .AddColumn("Value");

                // Basic card information
                var atr = CardService.GetAtr();
                if (atr != null)
                {
                    table.AddRow("ATR", $"[dim]{Convert.ToHexString(atr)}[/]");
                    table.AddRow("ATR Length", $"{atr.Length} bytes");
                }

                // Try to get ISD information
                try
                {
                    var selectResponse = GlobalPlatformService.SelectIsd();
                    table.AddRow("ISD Status", "[green]✓ Available[/]");
                    
                    if (selectResponse.RawData != null && selectResponse.RawData.Length > 0)
                    {
                        table.AddRow("ISD Data", $"[dim]{Convert.ToHexString(selectResponse.RawData)}[/]");
                    }

                    // Get card applications summary
                    var applications = GlobalPlatformService.GetApplications();
                    var appCounts = applications.GroupBy(a => a.Type)
                        .ToDictionary(g => g.Key, g => g.Count());

                    table.AddRow("Total Applications", applications.Count.ToString());

                    if (appCounts.ContainsKey(ApplicationType.IssuerSecurityDomain))
                        table.AddRow("  - ISD", appCounts[ApplicationType.IssuerSecurityDomain].ToString());
                    
                    if (appCounts.ContainsKey(ApplicationType.SupplementarySecurityDomain))
                        table.AddRow("  - SSD", appCounts[ApplicationType.SupplementarySecurityDomain].ToString());
                    
                    if (appCounts.ContainsKey(ApplicationType.Applet))
                        table.AddRow("  - Applets", appCounts[ApplicationType.Applet].ToString());
                    
                    if (appCounts.ContainsKey(ApplicationType.LoadFile))
                        table.AddRow("  - Load Files", appCounts[ApplicationType.LoadFile].ToString());
                }
                catch (Exception ex)
                {
                    table.AddRow("ISD Status", $"[red]✗ Error: {ex.Message}[/]");
                }

                // Connection information
                table.AddRow("Connection Status", "[green]✓ Connected[/]");
                table.AddRow("Secure Channel", CardService.IsSecureChannelEstablished ? "[green]✓ Established[/]" : "[yellow]○ Not established[/]");

                AnsiConsole.Write(new Panel(table)
                    .Header("[bold]Card Information[/]")
                    .BorderColor(Color.Green));

                return Task.FromResult(0);
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Error getting card information: {ex.Message}[/]");
                if (settings.Verbose)
                {
                    AnsiConsole.WriteException(ex);
                }
                return Task.FromResult(1);
            }
        }

        /// <summary>
        /// Settings for the info command.
        /// </summary>
        public class Settings : BaseCommandSettings
        {
        }
    }
}