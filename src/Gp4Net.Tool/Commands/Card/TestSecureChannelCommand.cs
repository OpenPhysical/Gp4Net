using System;
using System.ComponentModel;
using System.Threading.Tasks;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Tool.Infrastructure;
using JetBrains.Annotations;
using log4net;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Card;

/// <summary>
/// Test command for establishing a secure channel with GP test keys.
/// </summary>
[PublicAPI]
/// <summary>
/// Command to test secure channel establishment with GlobalPlatform test keys.
/// </summary>
[Description("Test secure channel establishment with GP test keys")]
public class TestSecureChannelCommand : AsyncCommand<TestSecureChannelCommand.Settings>
{
    private static readonly ILog Logger = LogManager.GetLogger(
        typeof(TestSecureChannelCommand)
    );

    /// <summary>
    /// Command settings.
    /// </summary>
    [PublicAPI]
    public class Settings : BaseCommandSettings
    {
        /// <summary>
        /// Gets or sets whether to use SCP03.
        /// </summary>
        [CommandOption("--scp03")]
        [Description("Use SCP03 instead of SCP02")]
        public bool UseScp03 { get; set; }
    }

    /// <summary>
    /// Executes the test secure channel command to verify secure channel establishment.
    /// </summary>
    /// <param name="context">The command context.</param>
    /// <param name="settings">The command settings.</param>
    /// <returns>0 if successful, 1 if failed.</returns>
    public override Task<int> ExecuteAsync(CommandContext context, Settings settings)
    {
        var cardService = CardServiceProvider.GetCardService();

        if (!cardService.IsConnected)
        {
            AnsiConsole.MarkupLine(
                "[red]Error:[/] Not connected to card. Use 'card connect' first."
            );
            return Task.FromResult(1);
        }

        try
        {
            AnsiConsole.MarkupLine("[blue]Testing secure channel establishment...[/]");

            // Use GP test keys
            var testKeys = GpTestKeys.StandardTestKey;

            // Convert security level
            var secLevel = (SecurityLevel)settings.SecurityLevel;
            AnsiConsole.MarkupLine($"Security Level: {secLevel}");
            AnsiConsole.MarkupLine($"Protocol: {(settings.UseScp03 ? "SCP03" : "SCP02")}");

            // Establish secure channel
            var sw = new System.Diagnostics.Stopwatch();
            sw.Start();

            var success = cardService.EstablishSecureChannel(testKeys, settings.SecurityLevel);

            sw.Stop();

            if (success)
            {
                AnsiConsole.MarkupLine(
                    $"[green]✓[/] Secure channel established successfully in {sw.ElapsedMilliseconds}ms"
                );

                // Test sending a command through the secure channel
                AnsiConsole.MarkupLine("\n[blue]Testing secure messaging...[/]");

                // Send GET STATUS command through secure channel
                var getStatusApdu = new byte[]
                {
                    0x80,
                    0xF2,
                    0x80,
                    0x00,
                    0x02,
                    0x4F,
                    0x00,
                    0x00,
                };
                var response = cardService.SendCommand(getStatusApdu);

                if (response.IsSuccessful)
                {
                    AnsiConsole.MarkupLine("[green]✓[/] Secure messaging working correctly");
                    AnsiConsole.MarkupLine(
                        $"Response data length: {response.Data.Length} bytes"
                    );
                }
                else
                {
                    AnsiConsole.MarkupLine(
                        $"[yellow]![/] Command failed with SW: {response.StatusWord:X4}"
                    );
                }

                return Task.FromResult(0);
            }
            else
            {
                AnsiConsole.MarkupLine("[red]✗[/] Failed to establish secure channel");
                return Task.FromResult(1);
            }
        }
        catch (Exception ex)
        {
            Logger.Error("Error testing secure channel", ex);
            AnsiConsole.MarkupLine($"[red]Error:[/] {ex.Message}");
            return Task.FromResult(1);
        }
    }
}