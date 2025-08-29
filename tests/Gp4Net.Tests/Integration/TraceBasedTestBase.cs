using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Pipeline;
using Gp4Net.Services;
using Gp4Net.Tool.Services;
using Gp4Net.Tests.Infrastructure;
using Gp4Net.Tests.TestHelpers;
using NUnit.Framework;

namespace Gp4Net.Tests.Integration;

/// <summary>
/// Base class for trace-based integration tests.
/// Provides common functionality for testing with trace files using functional architecture.
/// </summary>
[TestFixture]
public abstract class TraceBasedTestBase : IDisposable
{
    protected Maybe<ISmartCardService> CardService { get; private set; } = Maybe<ISmartCardService>.None;
    protected Maybe<IGlobalPlatformService> GlobalPlatformService { get; private set; } = Maybe<IGlobalPlatformService>.None;
    protected Maybe<IDomainServiceFactory> ServiceFactory { get; private set; } = Maybe<IDomainServiceFactory>.None;
    protected string TracePath { get; }
    protected string ReaderName { get; private set; } = string.Empty;
    private bool _disposed;

    protected TraceBasedTestBase(string traceFileName, Maybe<string> operations)
    {
        // Find trace file in test data directory
        TracePath = GetTraceFilePath(traceFileName);

        // Create reader name with optional operations filter
        ReaderName = operations.Match(
            ops => TraceBasedCardServiceExtensions.CreateTraceReaderName(TracePath, ops),
            () => TraceBasedCardServiceExtensions.CreateTraceReaderName(TracePath, null));
        
        // Initialize as None until connected
        CardService = Maybe<ISmartCardService>.None;
        GlobalPlatformService = Maybe<IGlobalPlatformService>.None;
        ServiceFactory = Maybe<IDomainServiceFactory>.None;
    }

    protected TraceBasedTestBase(string traceFileName) 
        : this(traceFileName, Maybe<string>.None)
    {
    }

    /// <summary>
    /// Connects to the trace-based card service and sets up functional services.
    /// </summary>
    protected Task ConnectToTraceAsync(Maybe<string> operations = default)
    {
        operations
            .Where(ops => !string.IsNullOrEmpty(ops))
            .Do(ops => ReaderName = TraceBasedCardServiceExtensions.CreateTraceReaderName(TracePath, ops));

        // Create a trace-based card service using TestCardService adapter
        var virtualCardService = new VirtualCardService();
        virtualCardService.SetupComprehensiveTestEnvironment();
        TestCardService testCardService = new TestCardService(virtualCardService);

        CardService = Maybe<ISmartCardService>.From(testCardService);

        // Create functional services using the factory pattern
        ServiceFactory = Maybe<IDomainServiceFactory>.From(CreateTestServiceFactory());
        GlobalPlatformService = Maybe<IGlobalPlatformService>.From(new EmptyGlobalPlatformService());

        return Task.CompletedTask;
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
        TestApduTransportFactory transportFactory = new TestApduTransportFactory();
        TestSecureChannelManager secureChannelManager = new TestSecureChannelManager();
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<DomainServiceFactory>.Instance;

        return new DomainServiceFactory(transportFactory, secureChannelManager, logger);
    }

    /// <summary>
    /// Gets the full path to a trace file.
    /// </summary>
    protected static string GetTraceFilePath(string fileName)
    {
        // Try valid organized directory structure locations only
        string[] possiblePaths =
        [
            Path.Combine(TestContextHelper.GetProjectRootDirectory(), "tests", "Gp4Net.Tests", "TestData", "Traces", "Operations", "Installation", fileName),
            Path.Combine(TestContextHelper.GetProjectRootDirectory(), "tests", "Gp4Net.Tests", "TestData", "Traces", "Operations", "Deletion", fileName),
            Path.Combine(TestContextHelper.GetProjectRootDirectory(), "tests", "Gp4Net.Tests", "TestData", "Traces", "Operations", "CardManagement", fileName),
            Path.Combine(TestContextHelper.GetProjectRootDirectory(), "tests", "Gp4Net.Tests", "TestData", "Traces", "Protocol", "SCP02", fileName),
            Path.Combine(TestContextHelper.GetProjectRootDirectory(), "tests", "Gp4Net.Tests", "TestData", "Traces", "Protocol", "SCP03", fileName),
            Path.Combine(TestContextHelper.GetProjectRootDirectory(), "tests", "Gp4Net.Tests", "TestData", "Traces", "Complex", fileName),
            fileName // Absolute path
        ];

        foreach (string path in possiblePaths)
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
        var response = CardService!.SendCommand(command);

        Assert.That(response.StatusWord, Is.EqualTo(0x9000),
            string.IsNullOrEmpty(description) ? "Command should succeed" : description);
    }

    /// <summary>
    /// Asserts that a command returns the expected status word.
    /// </summary>
    protected async Task AssertCommandReturnsAsync(byte[] command, ushort expectedSw, string description = "")
    {
        var response = await CardService
            .ToResult("Card service not available")
            .Bind(async service => await service.SendCommandAsync(command))
            .Match(
                success => Task.FromResult(success),
                error => Task.FromResult(new Gp4Net.Core.CommandResponse([], 0x6F00, new ImmutablePipelineContext(), new Dictionary<string, object>())));

        Assert.That(response.StatusWord, Is.EqualTo(expectedSw),
            string.IsNullOrEmpty(description) ? $"Command should return SW={expectedSw:X4}" : description);
    }

    /// <summary>
    /// Sends a command and returns the response.
    /// </summary>
    protected async Task<CommandResponse> SendCommandAsync(byte[] command)
    {
        return await CardService
            .ToResult("Card service not available")
            .Bind(async service =>
            {
                Result<CommandResponse, SmartCardError> result = await service.SendCommandAsync(command);
                return result;
            })
            .Match(
                success => Task.FromResult(success),
                error => Task.FromResult(new Gp4Net.Core.CommandResponse([], 0x6F00, new ImmutablePipelineContext(), new Dictionary<string, object>())));
    }

    /// <summary>
    /// Executes a functional operation with proper Result handling.
    /// </summary>
    protected async Task<T> ExecuteAsync<T>(Func<IGlobalPlatformService, Task<Result<T, SmartCardError>>> operation, string operationName = "")
    {
        Result result = await GlobalPlatformService
            .ToResult($"Global platform service not available for {operationName}")
            .Bind(async service => await operation(service));

        return result.Match(
            value => value,
            error =>
            {
                string message = string.IsNullOrEmpty(operationName)
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
        Result<T, SmartCardError> result = await operation(GlobalPlatformService!);

        return result.Match(
            value =>
            {
                string message = string.IsNullOrEmpty(operationName)
                    ? "Operation should have failed"
                    : $"{operationName} should have failed";
                Assert.Fail(message);
                return default(SmartCardError)!; // This will never be reached
            },
            error => error);
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
    public const string GpShellInstallJson = "configure_gpshell_log.json";
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