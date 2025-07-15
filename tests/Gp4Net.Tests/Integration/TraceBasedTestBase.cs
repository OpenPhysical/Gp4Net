using System;
using System.IO;
using System.Threading.Tasks;
using Gp4Net.Core;
using Gp4Net.Services;
using Gp4Net.Tool.Services;
using Gp4Net.Tests.Infrastructure;
using NUnit.Framework;

namespace Gp4Net.Tests.Integration
{
    /// <summary>
    /// Base class for trace-based integration tests.
    /// Provides common functionality for testing with trace files using functional architecture.
    /// </summary>
    [TestFixture]
    public abstract class TraceBasedTestBase : IDisposable
    {
        protected ICardService? CardService { get; private set; }
        protected IGlobalPlatformService? GlobalPlatformService { get; private set; }
        protected IDomainServiceFactory? ServiceFactory { get; private set; }
        protected string TracePath { get; }
        protected string ReaderName { get; private set; } = string.Empty;
        private bool _disposed;

        protected TraceBasedTestBase(string traceFileName, string? operations = null)
        {
            // Find trace file in test data directory
            TracePath = GetTraceFilePath(traceFileName);
            
            // Create reader name with optional operations filter
            ReaderName = TraceBasedCardServiceExtensions.CreateTraceReaderName(TracePath, operations);
        }

        /// <summary>
        /// Connects to the trace-based card service and sets up functional services.
        /// </summary>
        protected async Task ConnectToTraceAsync(string? operations = null)
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
            Assert.That(connected, Is.True, "Failed to connect to trace-based card service");

            // Create functional services using the factory pattern
            ServiceFactory = CreateTestServiceFactory();
            GlobalPlatformService = ServiceFactory.CreateGlobalPlatformService(CardService);
        }

        /// <summary>
        /// Synchronous wrapper for backward compatibility.
        /// </summary>
        protected void ConnectToTrace(string? operations = null)
        {
            ConnectToTraceAsync(operations).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Creates a test service factory for functional testing.
        /// </summary>
        protected virtual IDomainServiceFactory CreateTestServiceFactory()
        {
            // Create minimal functional dependencies for testing
            var pipeline = new TestCommandPipeline();
            var transportFactory = new TestApduTransportFactory();
            var secureChannelManager = new TestSecureChannelManager();
            
            return new DomainServiceFactory(pipeline, transportFactory, secureChannelManager);
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
            Assert.That(CardService, Is.Not.Null);
            
            var response = CardService.SendCommand(command);
            
            Assert.That(response, Is.Not.Null);
            Assert.That(response.StatusWord, Is.EqualTo(0x9000), 
                string.IsNullOrEmpty(description) ? "Command should succeed" : description);
        }

        /// <summary>
        /// Asserts that a command returns the expected status word.
        /// </summary>
        protected void AssertCommandReturns(byte[] command, ushort expectedSw, string description = "")
        {
            Assert.That(CardService, Is.Not.Null);
            
            var response = CardService.SendCommand(command);
            
            Assert.That(response, Is.Not.Null);
            Assert.That(response.StatusWord, Is.EqualTo(expectedSw),
                string.IsNullOrEmpty(description) ? $"Command should return SW={expectedSw:X4}" : description);
        }

        /// <summary>
        /// Sends a command and returns the response.
        /// </summary>
        protected CardResponse SendCommand(byte[] command)
        {
            Assert.That(CardService, Is.Not.Null);
            return CardService.SendCommand(command);
        }

        /// <summary>
        /// Executes a functional operation with proper Result handling.
        /// </summary>
        protected async Task<T> ExecuteAsync<T>(Func<IGlobalPlatformService, Task<Result<T, SmartCardError>>> operation, string operationName = "")
        {
            Assert.That(GlobalPlatformService, Is.Not.Null, "GlobalPlatformService must be initialized");
            
            var result = await operation(GlobalPlatformService);
            
            return await result.MatchAsync(
                async value => value,
                async error => 
                {
                    var message = string.IsNullOrEmpty(operationName) 
                        ? $"Operation failed: {error.Message}" 
                        : $"{operationName} failed: {error.Message}";
                    Assert.Fail(message);
                    return default(T)!; // This will never be reached
                });
        }

        /// <summary>
        /// Executes a functional operation and expects it to fail with a specific error.
        /// </summary>
        protected async Task<SmartCardError> ExecuteExpectingErrorAsync<T>(
            Func<IGlobalPlatformService, Task<Result<T, SmartCardError>>> operation, 
            string operationName = "")
        {
            Assert.That(GlobalPlatformService, Is.Not.Null, "GlobalPlatformService must be initialized");
            
            var result = await operation(GlobalPlatformService);
            
            return await result.MatchAsync(
                async value => 
                {
                    var message = string.IsNullOrEmpty(operationName) 
                        ? "Operation should have failed" 
                        : $"{operationName} should have failed";
                    Assert.Fail(message);
                    return default(SmartCardError)!; // This will never be reached
                },
                async error => error);
        }

        [TearDown]
        public virtual void TearDown()
        {
            Dispose();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    CardService?.Disconnect();
                    CardService?.Dispose();
                    CardService = null;
                }
                _disposed = true;
            }
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