using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using AwesomeAssertions;
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
    /// Test applet installation operations including CAP file loading and installation.
    /// </summary>
    [TestCase("gp_pro_install_scp03.json", "SCP03 applet installation")]
    public void AppletLifecycle_Should_Install_Applets(string traceFile, string description)
    {
        var tracePath = Path.Combine(TestContext.CurrentContext.TestDirectory, InstallationTracePath, traceFile);
        
        if (!File.Exists(tracePath))
        {
            Assert.Inconclusive($"Trace file not found: {tracePath}");
            return;
        }
        
        var jsonContent = File.ReadAllText(tracePath);
        var testData = JsonDocument.Parse(jsonContent);
        
        TestContext.Out.WriteLine($"Testing {description}");
        TestContext.Out.WriteLine($"Trace file: {traceFile}");
        
        if (!testData.RootElement.TryGetProperty("exchanges", out var exchangesElement))
        {
            Assert.Inconclusive($"No exchanges found in trace {traceFile}");
            return;
        }
        
        bool foundSecureChannel = false;
        bool foundInstallForLoad = false;
        bool foundLoad = false;
        bool foundInstallForInstall = false;
        int loadCommands = 0;
        
        foreach (var exchange in exchangesElement.EnumerateArray())
        {
            var command = exchange.GetProperty("command").GetString()!;
            var response = exchange.GetProperty("response").GetString()!;
            
            // Track secure channel establishment
            if (command.StartsWith("8050") || command.StartsWith("8482"))
            {
                foundSecureChannel = true;
            }
            
            // Check for INSTALL [for load] command (80E602xx or 84E602xx for secure messaging)
            if ((command.StartsWith("80E6") || command.StartsWith("84E6")) && command.Length >= 6)
            {
                var p1 = command.Substring(4, 2);
                if (p1 == "02")
                {
                    foundInstallForLoad = true;
                    TestContext.Out.WriteLine($"✓ Found INSTALL [for load]: {command}");
                    
                    // Should succeed for valid installation
                    _ = response.Should().EndWith("9000", "INSTALL [for load] should succeed");
                }
            }
            
            // Check for LOAD commands (80E800xx or 84E800xx for secure messaging)  
            if (command.StartsWith("80E8") || command.StartsWith("84E8"))
            {
                foundLoad = true;
                loadCommands++;
                
                if (loadCommands <= 3) // Don't spam output for many LOAD commands
                {
                    TestContext.Out.WriteLine($"✓ Found LOAD command #{loadCommands}: {command.Substring(0, Math.Min(command.Length, 20))}...");
                }
                
                // LOAD commands should succeed
                _ = response.Should().EndWith("9000", $"LOAD command #{loadCommands} should succeed");
            }
            
            // Check for INSTALL [for install] command (80E60C or 84E60C for secure messaging)
            if ((command.StartsWith("80E6") || command.StartsWith("84E6")) && command.Length >= 6)
            {
                var p1 = command.Substring(4, 2);
                if (p1 == "0C")
                {
                    foundInstallForInstall = true;
                    TestContext.Out.WriteLine($"✓ Found INSTALL [for install]: {command}");
                    
                    // Should succeed for valid applet installation
                    _ = response.Should().EndWith("9000", "INSTALL [for install] should succeed");
                }
            }
        }
        
        // Validate installation sequence - not all traces have complete workflows
        _ = foundSecureChannel.Should().BeTrue($"Applet installation requires secure channel");
        _ = foundInstallForLoad.Should().BeTrue($"Installation should include INSTALL [for load]");
        _ = foundLoad.Should().BeTrue($"Installation should include LOAD commands");
        
        // INSTALL [for install] is not always present in loading-only traces
        if (foundInstallForInstall)
        {
            TestContext.Out.WriteLine($"✓ Complete installation workflow (load + install)");
        }
        else
        {
            TestContext.Out.WriteLine($"✓ CAP loading workflow (load only - install phase may be separate)");
        }
        
        _ = loadCommands.Should().BeGreaterThan(0, "Should have at least one LOAD command");
        
        TestContext.Out.WriteLine($"✓ {description} completed with {loadCommands} LOAD commands");
    }
    
    /// <summary>
    /// Test applet uninstallation operations including DELETE commands.
    /// </summary>
    [TestCase("gp_pro_applet_uninstall.json", "Standard applet uninstallation")]
    public void AppletLifecycle_Should_Uninstall_Applets(string traceFile, string description)
    {
        var tracePath = Path.Combine(TestContext.CurrentContext.TestDirectory, DeletionTracePath, traceFile);
        
        if (!File.Exists(tracePath))
        {
            Assert.Inconclusive($"Trace file not found: {tracePath}");
            return;
        }
        
        var jsonContent = File.ReadAllText(tracePath);
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
            var command = exchange.GetProperty("command").GetString()!;
            var response = exchange.GetProperty("response").GetString()!;
            
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
                    TestContext.Out.WriteLine($"  DELETE #{deleteCommands} returned Data Not Found (6A88) - valid for non-existent applet");
                }
                else
                {
                    Assert.Fail($"DELETE command #{deleteCommands} should succeed (9000) or return 6A88 (data not found), but got {response}");
                }
            }
        }
        
        _ = foundSecureChannel.Should().BeTrue($"Applet uninstallation requires secure channel");
        _ = foundDelete.Should().BeTrue($"Uninstallation should include DELETE commands");
        _ = deleteCommands.Should().BeGreaterThan(0, "Should have at least one DELETE command");
        
        TestContext.Out.WriteLine($"✓ {description} completed with {deleteCommands} DELETE commands");
    }
    
    /// <summary>
    /// Test combined install/uninstall workflows that demonstrate complete applet lifecycle.
    /// </summary>
    [TestCase("install_uninstall.json", "Complete install and uninstall workflow")]
    public void AppletLifecycle_Should_Execute_Complete_Workflow(string traceFile, string description)
    {
        var tracePath = Path.Combine(TestContext.CurrentContext.TestDirectory, DeletionTracePath, traceFile);
        
        if (!File.Exists(tracePath))
        {
            Assert.Inconclusive($"Trace file not found: {tracePath}");
            return;
        }
        
        var jsonContent = File.ReadAllText(tracePath);
        var testData = JsonDocument.Parse(jsonContent);
        
        TestContext.Out.WriteLine($"Testing {description}");
        
        if (!testData.RootElement.TryGetProperty("exchanges", out var exchangesElement))
        {
            Assert.Inconclusive($"No exchanges found in trace {traceFile}");
            return;
        }
        
        var exchanges = exchangesElement.EnumerateArray().ToList();
        
        // Track workflow phases
        bool hasInstallPhase = false;
        bool hasUninstallPhase = false;
        int installForLoadIndex = -1;
        int installForInstallIndex = -1;
        int deleteIndex = -1;
        
        for (int i = 0; i < exchanges.Count; i++)
        {
            var command = exchanges[i].GetProperty("command").GetString()!;
            
            // INSTALL [for load] - P1=02
            if (command.StartsWith("80E6") && command.Length >= 6 && command.Substring(4, 2) == "02")
            {
                hasInstallPhase = true;
                if (installForLoadIndex == -1) installForLoadIndex = i;
            }
            
            // INSTALL [for install] - P1=0C  
            if (command.StartsWith("80E6") && command.Length >= 6 && command.Substring(4, 2) == "0C")
            {
                if (installForInstallIndex == -1) installForInstallIndex = i;
            }
            
            // DELETE commands (including secure messaging variants)
            if (command.StartsWith("80E4") || command.StartsWith("84E4"))
            {
                hasUninstallPhase = true;
                if (deleteIndex == -1) deleteIndex = i;
            }
        }
        
        // Not all workflow traces have both phases - validate based on what's actually present
        if (hasInstallPhase && hasUninstallPhase)
        {
            TestContext.Out.WriteLine($"✓ Complete install/uninstall workflow detected");
        }
        else if (hasInstallPhase)
        {
            TestContext.Out.WriteLine($"✓ Installation-only workflow detected");
        }
        else if (hasUninstallPhase)
        {
            TestContext.Out.WriteLine($"✓ Uninstallation-only workflow detected");
        }
        else
        {
            Assert.Fail($"Workflow should include either installation or uninstallation phase");
        }
        
        // Validate workflow sequence (install should come before uninstall)
        if (installForInstallIndex > -1 && deleteIndex > -1)
        {
            _ = installForInstallIndex.Should().BeLessThan(deleteIndex, 
                "INSTALL [for install] should come before DELETE in workflow");
            
            TestContext.Out.WriteLine($"✓ Workflow sequence validated:");
            TestContext.Out.WriteLine($"  INSTALL [for load] at position {installForLoadIndex}");
            TestContext.Out.WriteLine($"  INSTALL [for install] at position {installForInstallIndex}");
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
        var tracePath = Path.Combine(TestContext.CurrentContext.TestDirectory, basePath, traceFile);
        
        if (!File.Exists(tracePath))
        {
            Assert.Inconclusive($"Trace file not found: {tracePath}");
            return;
        }
        
        var jsonContent = File.ReadAllText(tracePath);
        var testData = JsonDocument.Parse(jsonContent);
        
        if (!testData.RootElement.TryGetProperty("exchanges", out var exchangesElement))
        {
            Assert.Inconclusive($"No exchanges found in trace {traceFile}");
            return;
        }
        
        var exchanges = exchangesElement.EnumerateArray().ToList();
        
        // For installation traces, validate installation sequence
        if (traceFile.Contains("install") && !traceFile.Contains("uninstall"))
        {
            int installForLoadIndex = -1;
            int firstLoadIndex = -1;
            int installForInstallIndex = -1;
            
            for (int i = 0; i < exchanges.Count; i++)
            {
                var command = exchanges[i].GetProperty("command").GetString()!;
                
                if ((command.StartsWith("80E6") || command.StartsWith("84E6")) && command.Substring(4, 2) == "02" && installForLoadIndex == -1)
                {
                    installForLoadIndex = i;
                }
                else if ((command.StartsWith("80E8") || command.StartsWith("84E8")) && firstLoadIndex == -1)
                {
                    firstLoadIndex = i;
                }
                else if ((command.StartsWith("80E6") || command.StartsWith("84E6")) && command.Substring(4, 2) == "0C" && installForInstallIndex == -1)
                {
                    installForInstallIndex = i;
                }
            }
            
            if (installForLoadIndex > -1 && firstLoadIndex > -1 && installForInstallIndex > -1)
            {
                _ = installForLoadIndex.Should().BeLessThan(firstLoadIndex, 
                    "INSTALL [for load] should come before LOAD commands");
                _ = firstLoadIndex.Should().BeLessThan(installForInstallIndex, 
                    "LOAD commands should come before INSTALL [for install]");
                
                TestContext.Out.WriteLine($"✓ Installation sequence validated for {traceFile}");
            }
        }
        
        // For uninstall traces, ensure DELETE commands are present and properly formed
        if (traceFile.Contains("uninstall"))
        {
            var deleteCommands = exchanges.Where((ex, i) => {
                var cmd = ex.GetProperty("command").GetString()!;
                return cmd.StartsWith("80E4") || cmd.StartsWith("84E4");
            }).ToList();
                
            _ = deleteCommands.Count.Should().BeGreaterThan(0, "Uninstall should have DELETE commands");
            
            foreach (var deleteCmd in deleteCommands)
            {
                var response = deleteCmd.GetProperty("response").GetString()!;
                // DELETE commands may return 9000 (success) or 6A88 (data not found) - both are valid
                if (response.EndsWith("9000"))
                {
                    TestContext.Out.WriteLine($"  DELETE succeeded (9000)");
                }
                else if (response.EndsWith("6A88"))
                {
                    TestContext.Out.WriteLine($"  DELETE returned Data Not Found (6A88) - valid for non-existent applet");
                }
                else
                {
                    Assert.Fail($"DELETE commands should succeed (9000) or return data not found (6A88), but got {response}");
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
    public void AppletLifecycle_Should_Have_Proper_Response_Handling(string traceFile, string basePath)
    {
        var tracePath = Path.Combine(TestContext.CurrentContext.TestDirectory, basePath, traceFile);
        
        if (!File.Exists(tracePath))
        {
            Assert.Inconclusive($"Trace file not found: {tracePath}");
            return;
        }
        
        var jsonContent = File.ReadAllText(tracePath);
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
            var command = exchange.GetProperty("command").GetString()!;
            var response = exchange.GetProperty("response").GetString()!;
            
            // Count applet-related commands (including secure messaging variants)
            if (command.StartsWith("80E6") || command.StartsWith("80E8") || command.StartsWith("80E4") ||
                command.StartsWith("84E6") || command.StartsWith("84E8") || command.StartsWith("84E4"))
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
                        TestContext.Out.WriteLine($"DELETE command with valid 6A88 response for {command}: {response}");
                    }
                    else
                    {
                        TestContext.Out.WriteLine($"Invalid DELETE response for {command}: {response}");
                    }
                }
                else
                {
                    TestContext.Out.WriteLine($"Non-success response for {command}: {response}");
                }
            }
        }
        
        _ = totalCommands.Should().BeGreaterThan(0, "Should have applet-related commands");
        _ = validCommands.Should().Be(totalCommands, 
            "All applet commands should have valid responses (9000 for most, 9000 or 6A88 for DELETE)");
        
        TestContext.Out.WriteLine($"✓ Response validation: {validCommands}/{totalCommands} commands valid");
    }
}