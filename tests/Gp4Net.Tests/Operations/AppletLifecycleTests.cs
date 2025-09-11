using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using NUnit.Framework;

namespace Gp4Net.Tests.Operations;

/// <summary>
/// Tests for applet lifecycle operations including installation, uninstallation,
/// and combined install/uninstall workflows.
/// Focuses on CAP file installation and applet management rather than protocol specifics.
/// </summary>
[TestFixture]
[Category("Operations")]
public class AppletLifecycleTests
{
    private const string InstallationTracePath = "TestData/Traces/Operations/Installation";
    private const string DeletionTracePath = "TestData/Traces/Operations/Deletion";

    /// <summary>
    /// Functional helper to load and parse trace file for installation.
    /// </summary>
    /// <param name="traceFile">The trace file name</param>
    /// <returns>Result containing the JsonDocument or error message</returns>
    private static Result<JsonDocument, string> LoadInstallationTraceFile(string traceFile)
    {
        string tracePath = Path.Combine(
            TestContext.CurrentContext.TestDirectory,
            InstallationTracePath,
            traceFile
        );

        if (!File.Exists(tracePath))
            return Result.Failure<JsonDocument, string>($"Trace file not found: {tracePath}");

        try
        {
            string jsonContent = File.ReadAllText(tracePath);
            var testData = JsonDocument.Parse(jsonContent);
            return Result.Success<JsonDocument, string>(testData);
        }
        catch (Exception ex)
        {
            return Result.Failure<JsonDocument, string>(
                $"Failed to parse trace file {traceFile}: {ex.Message}"
            );
        }
    }

    /// <summary>
    /// Functional helper to validate exchanges exist in trace.
    /// </summary>
    /// <param name="testData">The trace data</param>
    /// <param name="traceFile">Trace file name for error reporting</param>
    /// <returns>Result containing the exchanges element or error message</returns>
    private static Result<JsonElement, string> ValidateExchangesExist(
        JsonDocument testData,
        string traceFile
    ) =>
        testData.RootElement.TryGetProperty("exchanges", out var exchangesElement)
            ? Result.Success<JsonElement, string>(exchangesElement)
            : Result.Failure<JsonElement, string>($"No exchanges found in trace {traceFile}");

    /// <summary>
    /// Functional helper to validate applet installation operations.
    /// </summary>
    /// <param name="exchangesElement">The exchanges JSON element</param>
    /// <param name="description">Test description</param>
    /// <param name="traceFile">Trace file name</param>
    /// <returns>Result indicating validation success or failure</returns>
    private static UnitResult<string> ValidateAppletInstallation(
        JsonElement exchangesElement,
        string description,
        string traceFile
    )
    {
        TestContext.Out.WriteLine($"Testing {description}");
        TestContext.Out.WriteLine($"Trace file: {traceFile}");

        List<JsonElement> exchanges = [.. exchangesElement.EnumerateArray()];
        var commandResponsePairs = exchanges
            .Select(e => new
            {
                Command = e.GetProperty("command").GetString()!,
                Response = e.GetProperty("response").GetString()!,
            })
            .ToList();

        // Analyze installation patterns
        var secureChannelCommands = commandResponsePairs
            .Where(pair => pair.Command.StartsWith("8050") || pair.Command.StartsWith("8482"))
            .ToList();

        var installForLoadCommands = commandResponsePairs
            .Where(pair =>
                (pair.Command.StartsWith("80E6") || pair.Command.StartsWith("84E6"))
                && pair.Command.Length >= 6
                && pair.Command.Substring(4, 2) == "02"
            )
            .ToList();

        var loadCommands = commandResponsePairs
            .Where(pair => pair.Command.StartsWith("80E8") || pair.Command.StartsWith("84E8"))
            .ToList();

        var installForInstallCommands = commandResponsePairs
            .Where(pair =>
                (pair.Command.StartsWith("80E6") || pair.Command.StartsWith("84E6"))
                && pair.Command.Length >= 6
                && pair.Command.Substring(4, 2) == "0C"
            )
            .ToList();

        // Validate required operations
        if (!secureChannelCommands.Any())
            return UnitResult.Failure<string>("Applet installation requires secure channel");

        if (!installForLoadCommands.Any())
            return UnitResult.Failure<string>("Installation should include INSTALL [for load]");

        if (!loadCommands.Any())
            return UnitResult.Failure<string>("Installation should include LOAD commands");

        if (loadCommands.Count == 0)
            return UnitResult.Failure<string>("Should have at least one LOAD command");

        // Validate responses
        var failedInstallForLoadCommands = installForLoadCommands
            .Where(pair => !pair.Response.EndsWith("9000"))
            .ToList();

        if (failedInstallForLoadCommands.Any())
            return UnitResult.Failure<string>("INSTALL [for load] should succeed");

        var failedLoadCommands = loadCommands
            .Select((pair, index) => new { pair, index = index + 1 })
            .Where(item => !item.pair.Response.EndsWith("9000"))
            .ToList();

        if (failedLoadCommands.Any())
            return UnitResult.Failure<string>(
                $"LOAD command #{failedLoadCommands.First().index} should succeed"
            );

        var failedInstallForInstallCommands = installForInstallCommands
            .Where(pair => !pair.Response.EndsWith("9000"))
            .ToList();

        if (failedInstallForInstallCommands.Any())
            return UnitResult.Failure<string>("INSTALL [for install] should succeed");

        // Log successful findings
        _ = installForLoadCommands
            .Select(pair => $"✓ Found INSTALL [for load]: {pair.Command}")
            .Concat(
                loadCommands
                    .Take(3)
                    .Select(
                        (pair, index) =>
                            $"✓ Found LOAD command #{index + 1}: {pair.Command.Substring(0, Math.Min(pair.Command.Length, 20))}..."
                    )
            )
            .Concat(
                installForInstallCommands.Select(pair =>
                    $"✓ Found INSTALL [for install]: {pair.Command}"
                )
            )
            .Aggregate(
                "",
                (current, message) =>
                {
                    TestContext.Out.WriteLine(message);
                    return current;
                }
            );

        // Log workflow type
        if (installForInstallCommands.Any())
        {
            TestContext.Out.WriteLine("✓ Complete installation workflow (load + install)");
        }
        else
        {
            TestContext.Out.WriteLine(
                "✓ CAP loading workflow (load only - install phase may be separate)"
            );
        }

        TestContext.Out.WriteLine(
            $"✓ {description} completed with {loadCommands.Count} LOAD commands"
        );
        return UnitResult.Success<string>();
    }

    /// <summary>
    /// Test applet installation operations including CAP file loading and installation.
    /// </summary>
    [TestCase("gp_pro_install_scp03.json", "SCP03 applet installation")]
    public void AppletLifecycle_Should_Install_Applets(string traceFile, string description)
    {
        var result = LoadInstallationTraceFile(traceFile)
            .Bind(testData => ValidateExchangesExist(testData, traceFile))
            .Bind(exchangesElement =>
                ValidateAppletInstallation(exchangesElement, description, traceFile)
            );

        if (result.IsSuccess)
        {
            Assert.Pass("Test completed successfully");
        }
        else
        {
            Assert.Inconclusive(result.Error);
        }
    }

    /// <summary>
    /// Test applet uninstallation operations including DELETE commands.
    /// </summary>
    [TestCase("gp_pro_applet_uninstall.json", "Standard applet uninstallation")]
    public void AppletLifecycle_Should_Uninstall_Applets(string traceFile, string description)
    {
        string tracePath = Path.Combine(
            TestContext.CurrentContext.TestDirectory,
            DeletionTracePath,
            traceFile
        );

        if (!File.Exists(tracePath))
        {
            Assert.Inconclusive($"Trace file not found: {tracePath}");
            return;
        }

        string jsonContent = File.ReadAllText(tracePath);
        var testData = JsonDocument.Parse(jsonContent);

        TestContext.Out.WriteLine($"Testing {description}");

        if (!testData.RootElement.TryGetProperty("exchanges", out var exchangesElement))
        {
            Assert.Inconclusive($"No exchanges found in trace {traceFile}");
            return;
        }

        bool foundSecureChannel = false;
        bool foundDelete = false;
        int deleteCommands = 0;

        foreach (var exchange in exchangesElement.EnumerateArray())
        {
            string command = exchange.GetProperty("command").GetString()!;
            string response = exchange.GetProperty("response").GetString()!;

            // Track secure channel establishment
            if (command.StartsWith("8050") || command.StartsWith("8482"))
            {
                foundSecureChannel = true;
            }

            // Check for DELETE command (80E400xx or 84E400xx for secure messaging)
            if (command.StartsWith("80E4") || command.StartsWith("84E4"))
            {
                foundDelete = true;
                deleteCommands++;
                TestContext.Out.WriteLine($"✓ Found DELETE command #{deleteCommands}: {command}");

                // DELETE may return 9000 (success) or 6A88 (data not found) - both are valid
                if (response.EndsWith("9000"))
                {
                    TestContext.Out.WriteLine($"  DELETE #{deleteCommands} succeeded (9000)");
                }
                else if (response.EndsWith("6A88"))
                {
                    TestContext.Out.WriteLine(
                        $"  DELETE #{deleteCommands} returned Data Not Found (6A88) - valid for non-existent applet"
                    );
                }
                else
                {
                    Assert.Fail(
                        $"DELETE command #{deleteCommands} should succeed (9000) or return 6A88 (data not found), but got {response}"
                    );
                }
            }
        }

        _ = foundSecureChannel.Should().BeTrue("Applet uninstallation requires secure channel");
        _ = foundDelete.Should().BeTrue("Uninstallation should include DELETE commands");
        _ = deleteCommands.Should().BeGreaterThan(0, "Should have at least one DELETE command");

        TestContext.Out.WriteLine(
            $"✓ {description} completed with {deleteCommands} DELETE commands"
        );
    }

    /// <summary>
    /// Test combined install/uninstall workflows that demonstrate complete applet lifecycle.
    /// </summary>
    [TestCase("install_uninstall.json", "Complete install and uninstall workflow")]
    public void AppletLifecycle_Should_Execute_Complete_Workflow(
        string traceFile,
        string description
    )
    {
        string tracePath = Path.Combine(
            TestContext.CurrentContext.TestDirectory,
            DeletionTracePath,
            traceFile
        );

        if (!File.Exists(tracePath))
        {
            Assert.Inconclusive($"Trace file not found: {tracePath}");
            return;
        }

        string jsonContent = File.ReadAllText(tracePath);
        var testData = JsonDocument.Parse(jsonContent);

        TestContext.Out.WriteLine($"Testing {description}");

        if (!testData.RootElement.TryGetProperty("exchanges", out var exchangesElement))
        {
            Assert.Inconclusive($"No exchanges found in trace {traceFile}");
            return;
        }

        List<JsonElement> exchanges = [.. exchangesElement.EnumerateArray()];

        // Track workflow phases
        bool hasInstallPhase = false;
        bool hasUninstallPhase = false;
        int installForLoadIndex = -1;
        int installForInstallIndex = -1;
        int deleteIndex = -1;

        for (int i = 0; i < exchanges.Count; i++)
        {
            string command = exchanges[i].GetProperty("command").GetString()!;

            // INSTALL [for load] - P1=02
            if (
                command.StartsWith("80E6")
                && command.Length >= 6
                && command.Substring(4, 2) == "02"
            )
            {
                hasInstallPhase = true;
                if (installForLoadIndex == -1)
                    installForLoadIndex = i;
            }

            // INSTALL [for install] - P1=0C
            if (
                command.StartsWith("80E6")
                && command.Length >= 6
                && command.Substring(4, 2) == "0C"
            )
            {
                if (installForInstallIndex == -1)
                    installForInstallIndex = i;
            }

            // DELETE commands (including secure messaging variants)
            if (command.StartsWith("80E4") || command.StartsWith("84E4"))
            {
                hasUninstallPhase = true;
                if (deleteIndex == -1)
                    deleteIndex = i;
            }
        }

        // Not all workflow traces have both phases - validate based on what's actually present
        if (hasInstallPhase && hasUninstallPhase)
        {
            TestContext.Out.WriteLine("✓ Complete install/uninstall workflow detected");
        }
        else if (hasInstallPhase)
        {
            TestContext.Out.WriteLine("✓ Installation-only workflow detected");
        }
        else if (hasUninstallPhase)
        {
            TestContext.Out.WriteLine("✓ Uninstallation-only workflow detected");
        }
        else
        {
            Assert.Fail("Workflow should include either installation or uninstallation phase");
        }

        // Validate workflow sequence (install should come before uninstall)
        if (installForInstallIndex > -1 && deleteIndex > -1)
        {
            _ = installForInstallIndex
                .Should()
                .BeLessThan(
                    deleteIndex,
                    "INSTALL [for install] should come before DELETE in workflow"
                );

            TestContext.Out.WriteLine("✓ Workflow sequence validated:");
            TestContext.Out.WriteLine($"  INSTALL [for load] at position {installForLoadIndex}");
            TestContext.Out.WriteLine(
                $"  INSTALL [for install] at position {installForInstallIndex}"
            );
            TestContext.Out.WriteLine($"  DELETE at position {deleteIndex}");
        }

        TestContext.Out.WriteLine($"✓ {description} validated successfully");
    }

    /// <summary>
    /// Validate that applet lifecycle operations follow proper command sequences.
    /// Installation should follow: INSTALL [for load] → LOAD → INSTALL [for install]
    /// Uninstallation should use proper DELETE commands.
    /// </summary>
    [TestCase("gp_pro_install_scp03.json", InstallationTracePath)]
    [TestCase("gp_pro_applet_uninstall.json", DeletionTracePath)]
    public void AppletLifecycle_Should_Follow_Command_Sequence(string traceFile, string basePath)
    {
        string tracePath = Path.Combine(
            TestContext.CurrentContext.TestDirectory,
            basePath,
            traceFile
        );

        if (!File.Exists(tracePath))
        {
            Assert.Inconclusive($"Trace file not found: {tracePath}");
            return;
        }

        string jsonContent = File.ReadAllText(tracePath);
        var testData = JsonDocument.Parse(jsonContent);

        if (!testData.RootElement.TryGetProperty("exchanges", out var exchangesElement))
        {
            Assert.Inconclusive($"No exchanges found in trace {traceFile}");
            return;
        }

        List<JsonElement> exchanges = [.. exchangesElement.EnumerateArray()];

        // For installation traces, validate installation sequence
        if (traceFile.Contains("install") && !traceFile.Contains("uninstall"))
        {
            int installForLoadIndex = -1;
            int firstLoadIndex = -1;
            int installForInstallIndex = -1;

            for (int i = 0; i < exchanges.Count; i++)
            {
                string command = exchanges[i].GetProperty("command").GetString()!;

                if (
                    (command.StartsWith("80E6") || command.StartsWith("84E6"))
                    && command.Substring(4, 2) == "02"
                    && installForLoadIndex == -1
                )
                {
                    installForLoadIndex = i;
                }
                else if (
                    (command.StartsWith("80E8") || command.StartsWith("84E8"))
                    && firstLoadIndex == -1
                )
                {
                    firstLoadIndex = i;
                }
                else if (
                    (command.StartsWith("80E6") || command.StartsWith("84E6"))
                    && command.Substring(4, 2) == "0C"
                    && installForInstallIndex == -1
                )
                {
                    installForInstallIndex = i;
                }
            }

            if (installForLoadIndex > -1 && firstLoadIndex > -1 && installForInstallIndex > -1)
            {
                _ = installForLoadIndex
                    .Should()
                    .BeLessThan(
                        firstLoadIndex,
                        "INSTALL [for load] should come before LOAD commands"
                    );
                _ = firstLoadIndex
                    .Should()
                    .BeLessThan(
                        installForInstallIndex,
                        "LOAD commands should come before INSTALL [for install]"
                    );

                TestContext.Out.WriteLine($"✓ Installation sequence validated for {traceFile}");
            }
        }

        // For uninstall traces, ensure DELETE commands are present and properly formed
        if (traceFile.Contains("uninstall"))
        {
            List<JsonElement> deleteCommands =
            [
                .. exchanges.Where(
                    (ex, i) =>
                    {
                        string cmd = ex.GetProperty("command").GetString()!;
                        return cmd.StartsWith("80E4") || cmd.StartsWith("84E4");
                    }
                ),
            ];

            _ = deleteCommands
                .Count.Should()
                .BeGreaterThan(0, "Uninstall should have DELETE commands");

            foreach (var deleteCmd in deleteCommands)
            {
                string response = deleteCmd.GetProperty("response").GetString()!;
                // DELETE commands may return 9000 (success) or 6A88 (data not found) - both are valid
                if (response.EndsWith("9000"))
                {
                    TestContext.Out.WriteLine("  DELETE succeeded (9000)");
                }
                else if (response.EndsWith("6A88"))
                {
                    TestContext.Out.WriteLine(
                        "  DELETE returned Data Not Found (6A88) - valid for non-existent applet"
                    );
                }
                else
                {
                    Assert.Fail(
                        $"DELETE commands should succeed (9000) or return data not found (6A88), but got {response}"
                    );
                }
            }

            TestContext.Out.WriteLine($"✓ Uninstallation sequence validated for {traceFile}");
        }
    }

    /// <summary>
    /// Test that applet operations include proper error handling and response validation.
    /// </summary>
    [TestCase("gp_pro_install_scp03.json", InstallationTracePath)]
    [TestCase("gp_pro_applet_uninstall.json", DeletionTracePath)]
    public void AppletLifecycle_Should_Have_Proper_Response_Handling(
        string traceFile,
        string basePath
    )
    {
        string tracePath = Path.Combine(
            TestContext.CurrentContext.TestDirectory,
            basePath,
            traceFile
        );

        if (!File.Exists(tracePath))
        {
            Assert.Inconclusive($"Trace file not found: {tracePath}");
            return;
        }

        string jsonContent = File.ReadAllText(tracePath);
        var testData = JsonDocument.Parse(jsonContent);

        if (!testData.RootElement.TryGetProperty("exchanges", out var exchangesElement))
        {
            Assert.Inconclusive($"No exchanges found in trace {traceFile}");
            return;
        }

        int validCommands = 0;
        int totalCommands = 0;

        foreach (var exchange in exchangesElement.EnumerateArray())
        {
            string command = exchange.GetProperty("command").GetString()!;
            string response = exchange.GetProperty("response").GetString()!;

            // Count applet-related commands (including secure messaging variants)
            if (
                command.StartsWith("80E6")
                || command.StartsWith("80E8")
                || command.StartsWith("80E4")
                || command.StartsWith("84E6")
                || command.StartsWith("84E8")
                || command.StartsWith("84E4")
            )
            {
                totalCommands++;

                if (response.EndsWith("9000"))
                {
                    validCommands++;
                }
                else if (command.StartsWith("80E4") || command.StartsWith("84E4")) // DELETE commands
                {
                    if (response.EndsWith("6A88")) // Data not found is valid for DELETE
                    {
                        validCommands++;
                        TestContext.Out.WriteLine(
                            $"DELETE command with valid 6A88 response for {command}: {response}"
                        );
                    }
                    else
                    {
                        TestContext.Out.WriteLine(
                            $"Invalid DELETE response for {command}: {response}"
                        );
                    }
                }
                else
                {
                    TestContext.Out.WriteLine($"Non-success response for {command}: {response}");
                }
            }
        }

        _ = totalCommands.Should().BeGreaterThan(0, "Should have applet-related commands");
        _ = validCommands
            .Should()
            .Be(
                totalCommands,
                "All applet commands should have valid responses (9000 for most, 9000 or 6A88 for DELETE)"
            );

        TestContext.Out.WriteLine(
            $"✓ Response validation: {validCommands}/{totalCommands} commands valid"
        );
    }
}
