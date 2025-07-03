using System;
using System.IO;
using Gp4Net.Tool.Services;
using Xunit;

namespace Gp4Net.Tests.Integration
{
    /// <summary>
    /// Base class for trace-based integration tests.
    /// Provides common functionality for testing with trace files.
    /// </summary>
    public abstract class TraceBasedTestBase : IDisposable
    {
        protected ICardService? CardService { get; private set; }
        protected string TracePath { get; }
        protected string ReaderName { get; private set; } = string.Empty;

        protected TraceBasedTestBase(string traceFileName, string? operations = null)
        {
            // Find trace file in test data directory
            TracePath = GetTraceFilePath(traceFileName);
            
            // Create reader name with optional operations filter
            ReaderName = TraceBasedCardServiceExtensions.CreateTraceReaderName(TracePath, operations);
        }

        /// <summary>
        /// Connects to the trace-based card service.
        /// </summary>
        protected void ConnectToTrace(string? operations = null)
        {
            if (!string.IsNullOrEmpty(operations))
            {
                ReaderName = TraceBasedCardServiceExtensions.CreateTraceReaderName(TracePath, operations);
            }

            // Create a trace-based card service directly
            var (tracePath, ops) = TraceBasedCardServiceExtensions.ParseTraceReaderName(ReaderName);
            var traceService = new TraceBasedCardService(tracePath, ops);
            
            CardService = traceService;
            
            var connected = CardService.Connect(ReaderName);
            Assert.True(connected, "Failed to connect to trace-based card service");
        }

        /// <summary>
        /// Gets the full path to a trace file.
        /// </summary>
        protected static string GetTraceFilePath(string fileName)
        {
            // Try multiple possible locations
            var possiblePaths = new[]
            {
                Path.Combine(TestContext.GetProjectRootDirectory(), "docs", "traces", fileName),
                Path.Combine(TestContext.GetProjectRootDirectory(), "tests", "traces", fileName),
                Path.Combine(TestContext.GetTestDataDirectory(), "traces", fileName),
                Path.Combine(Directory.GetCurrentDirectory(), "traces", fileName),
                fileName // Absolute path
            };

            foreach (var path in possiblePaths)
            {
                if (File.Exists(path))
                {
                    return Path.GetFullPath(path);
                }
            }

            throw new FileNotFoundException($"Trace file '{fileName}' not found in any expected location");
        }

        /// <summary>
        /// Asserts that a command succeeds with SW=9000.
        /// </summary>
        protected void AssertCommandSucceeds(byte[] command, string description = "")
        {
            Assert.NotNull(CardService);
            
            var response = CardService.SendCommand(command);
            
            Assert.NotNull(response);
            Assert.Equal(0x9000, response.StatusWord);
            
            if (!string.IsNullOrEmpty(description))
            {
                // Command succeeded
            }
        }

        /// <summary>
        /// Asserts that a command returns the expected status word.
        /// </summary>
        protected void AssertCommandReturns(byte[] command, ushort expectedSw, string description = "")
        {
            Assert.NotNull(CardService);
            
            var response = CardService.SendCommand(command);
            
            Assert.NotNull(response);
            Assert.Equal(expectedSw, response.StatusWord);
            
            if (!string.IsNullOrEmpty(description))
            {
                // Command returned expected SW
            }
        }

        /// <summary>
        /// Sends a command and returns the response.
        /// </summary>
        protected CardResponse SendCommand(byte[] command)
        {
            Assert.NotNull(CardService);
            return CardService.SendCommand(command);
        }

        public virtual void Dispose()
        {
            CardService?.Disconnect();
            CardService?.Dispose();
            CardService = null;
        }
    }

    /// <summary>
    /// Common trace files used in tests.
    /// </summary>
    public static class TraceFiles
    {
        public const string GpProCardInfo = "gp_pro_card_info.txt";
        public const string GpProCardInfoJson = "gp_pro_card_info.json";
        public const string GpShellInstall = "configure_gpshell_log.txt";
        public const string GpShellInstallJson = "configure_gpshell.json";
        public const string InstallUninstall = "install_uninstall.log";
        public const string Scp03Session = "gp_pro_p71_scp03.txt";
    }

    /// <summary>
    /// Common operations found in trace files.
    /// </summary>
    public static class TraceOperations
    {
        public const string CardInfo = "info";
        public const string SecureChannelEstablish = "secure_channel_establish";
        public const string InstallApplet = "install_applet";
        public const string Uninstall = "uninstall";
        public const string ListApps = "list";
    }
}