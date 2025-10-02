using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using CSharpFunctionalExtensions;
using Gp4Net.Tests.TestInfrastructure;
using NUnit.Framework;

namespace Gp4Net.Tests.Operations;

/// <summary>
/// Tests for card management operations including authentication, key management,
/// lock/unlock operations, and card status retrieval.
/// Focuses on testing card lifecycle operations rather than protocol specifics.
/// </summary>
[TestFixture]
[Category("Operations")]
public class CardManagementOperationTests
{
    private const string TraceDataPath = "TestData/Traces/Operations/CardManagement";

    /// <summary>
    /// Functional helper to load and parse trace file.
    /// </summary>
    /// <param name="traceFile">The trace file name</param>
    /// <returns>Result containing the JsonDocument or error message</returns>
    private static Result<JsonDocument, string> LoadTraceFile(string traceFile)
    {
        var relativePath = Path.Combine("Traces/Operations/CardManagement", traceFile);
        var ensureResult = TraceTestDataRepository.EnsureTraceFile(relativePath);
        if (ensureResult.IsFailure)
        {
            return Result.Failure<JsonDocument, string>(ensureResult.Error);
        }

        return TraceTestDataRepository.LoadTraceDocument(relativePath);
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
    /// Functional helper to validate card information retrieval operations.
    /// </summary>
    /// <param name="exchangesElement">The exchanges JSON element</param>
    /// <param name="description">Test description</param>
    /// <param name="traceFile">Trace file name</param>
    /// <returns>Result indicating validation success or failure</returns>
    private static UnitResult<string> ValidateCardInformationRetrieval(
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

        // Analyze card information patterns
        var selectCommands = commandResponsePairs
            .Where(pair => pair.Command.StartsWith("00A4"))
            .ToList();
        var statusCommands = commandResponsePairs
            .Where(pair =>
                pair.Command.StartsWith("80F2")
                || pair.Command.StartsWith("84F2")
                || pair.Command.StartsWith("80CA")
                || pair.Command.StartsWith("84CA")
            )
            .ToList();

        if (!selectCommands.Any())
            return UnitResult.Failure<string>(
                $"Card info operation should include SELECT for {description}"
            );

        if (!statusCommands.Any())
            return UnitResult.Failure<string>(
                $"Card info operation should include card information commands for {description}"
            );

        // Validate SELECT responses and log findings
        List<string> selectValidation =
        [
            .. selectCommands
                .Where(pair => !pair.Response.EndsWith("9000"))
                .Select(pair => pair.Command),
        ];

        if (selectValidation.Any())
            return UnitResult.Failure<string>("SELECT command should succeed");

        // Log successful findings
        _ = selectCommands
            .Select(pair => $"✓ Found SELECT command: {pair.Command}")
            .Aggregate(
                "",
                (current, message) =>
                {
                    TestContext.Out.WriteLine(message);
                    return current;
                }
            );

        _ = statusCommands
            .Select(pair => new
            {
                pair.Command,
                pair.Response,
                IsSuccessful = pair.Response.EndsWith("9000"),
            })
            .Select(info =>
            {
                TestContext.Out.WriteLine($"✓ Found card info command: {info.Command}");
                if (info.IsSuccessful)
                {
                    string responsePreview = info.Response.Substring(
                        0,
                        Math.Min(info.Response.Length - 4, 40)
                    );
                    TestContext.Out.WriteLine($"  Status response: {responsePreview}...");
                }
                return info;
            })
            .Aggregate("", (current, _) => current);

        TestContext.Out.WriteLine($"✓ {description} validated successfully");
        return UnitResult.Success<string>();
    }

    /// <summary>
    /// Test card information retrieval operations.
    /// Validates that card status and information queries work correctly.
    /// </summary>
    [TestCase("gp_pro_card_info.json", "Card information retrieval")]
    public void CardManagement_Should_Retrieve_Card_Information(
        string traceFile,
        string description
    )
    {
        var result = LoadTraceFile(traceFile)
            .Bind(testData => ValidateExchangesExist(testData, traceFile))
            .Bind(exchangesElement =>
                ValidateCardInformationRetrieval(exchangesElement, description, traceFile)
            );

        result.Match(
            () => { /* Test passed */
            },
            failure => Assert.Fail($"Test failed: {failure}")
        );
    }

    /// <summary>
    /// Functional helper to validate lock operations.
    /// </summary>
    /// <param name="exchangesElement">The exchanges JSON element</param>
    /// <param name="description">Test description</param>
    /// <param name="traceFile">Trace file name</param>
    /// <returns>Result indicating validation success or failure</returns>
    private static UnitResult<string> ValidateLockOperations(
        JsonElement exchangesElement,
        string description,
        string traceFile
    )
    {
        TestContext.Out.WriteLine($"Testing {description}");

        List<JsonElement> exchanges = [.. exchangesElement.EnumerateArray()];
        var commandResponsePairs = exchanges
            .Select(e => new
            {
                Command = e.GetProperty("command").GetString()!,
                Response = e.GetProperty("response").GetString()!,
            })
            .ToList();

        // Analyze lock operation patterns
        var initUpdateCommands = commandResponsePairs
            .Where(pair => pair.Command.StartsWith("8050"))
            .ToList();
        var authCommands = commandResponsePairs
            .Where(pair => pair.Command.StartsWith("8482"))
            .ToList();
        var statusCommands = commandResponsePairs
            .Where(pair =>
                (pair.Command.StartsWith("80F0") || pair.Command.StartsWith("84F0"))
                && pair.Command.Length >= 6
            )
            .ToList();
        var managementCommands = commandResponsePairs
            .Where(pair => pair.Command.StartsWith("80D8") || pair.Command.StartsWith("84D8"))
            .ToList();

        var allManagementCommands = statusCommands.Concat(managementCommands).ToList();

        // Validate required operations
        if (!initUpdateCommands.Any())
            return UnitResult.Failure<string>(
                "Lock operation requires secure channel establishment"
            );

        if (!authCommands.Any())
            return UnitResult.Failure<string>("Lock operation requires authentication");

        if (!allManagementCommands.Any())
            return UnitResult.Failure<string>(
                "Management operation should include SET STATUS or management commands"
            );

        // Validate responses and log findings
        var failedStatusCommands = statusCommands
            .Where(pair => !pair.Response.EndsWith("9000"))
            .ToList();

        if (failedStatusCommands.Any())
            return UnitResult.Failure<string>("SET STATUS (lock) command should succeed");

        var failedManagementCommands = managementCommands
            .Where(pair => !pair.Response.EndsWith("9000"))
            .ToList();

        if (failedManagementCommands.Any())
            return UnitResult.Failure<string>("Management operation should succeed");

        // Log successful findings
        _ = initUpdateCommands
            .Select(_ => "✓ Found INITIALIZE UPDATE for lock operation")
            .Concat(authCommands.Select(_ => "✓ Found EXTERNAL AUTHENTICATE for lock operation"))
            .Concat(statusCommands.Select(pair => $"✓ Found SET STATUS command: {pair.Command}"))
            .Concat(
                managementCommands.Select(pair =>
                    $"✓ Found management operation (PUT KEY): {pair.Command}"
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

        TestContext.Out.WriteLine($"✓ {description} sequence validated");
        return UnitResult.Success<string>();
    }

    /// <summary>
    /// Test card lock operations including secure channel establishment and lock command execution.
    /// </summary>
    [TestCase("gp_pro_lock.json", "Card lock operation")]
    public void CardManagement_Should_Execute_Lock_Operations(string traceFile, string description)
    {
        var result = LoadTraceFile(traceFile)
            .Bind(testData => ValidateExchangesExist(testData, traceFile))
            .Bind(exchangesElement =>
                ValidateLockOperations(exchangesElement, description, traceFile)
            );

        result.Match(
            () => { /* Test passed */
            },
            failure => Assert.Fail($"Test failed: {failure}")
        );
    }

    /// <summary>
    /// Functional helper to validate unlock operations.
    /// </summary>
    /// <param name="exchangesElement">The exchanges JSON element</param>
    /// <param name="description">Test description</param>
    /// <param name="traceFile">Trace file name</param>
    /// <returns>Result indicating validation success or failure</returns>
    private static UnitResult<string> ValidateUnlockOperations(
        JsonElement exchangesElement,
        string description,
        string traceFile
    )
    {
        TestContext.Out.WriteLine($"Testing {description}");

        List<JsonElement> exchanges = [.. exchangesElement.EnumerateArray()];
        var commandResponsePairs = exchanges
            .Select(e => new
            {
                Command = e.GetProperty("command").GetString()!,
                Response = e.GetProperty("response").GetString()!,
            })
            .ToList();

        // Analyze unlock operation patterns
        var secureChannelCommands = commandResponsePairs
            .Where(pair => pair.Command.StartsWith("8050") || pair.Command.StartsWith("8482"))
            .ToList();

        var unlockCommands = commandResponsePairs
            .Where(pair =>
                pair.Command.StartsWith("80F0")
                || pair.Command.StartsWith("84F0")
                || // SET STATUS
                pair.Command.StartsWith("80D8")
                || pair.Command.StartsWith("84D8")
                || // PUT KEY / UNKNOWN D8
                pair.Command.StartsWith("84CA") && pair.Command.Contains("E008")
            ) // GET DATA with specific unlock parameters
            .ToList();

        // Check if this is a factory unlock by looking for specific unlock command patterns
        // Factory unlocks typically use PUT KEY with specific privileges/parameters
        bool isFactoryUnlock = commandResponsePairs.Any(pair =>
            pair.Command.StartsWith("84D4")
            || // PUT KEY command
            pair.Command.StartsWith("80D4")
        ); // PUT KEY (clear)

        // Validate factory unlock secure channel requirement
        if (isFactoryUnlock && !secureChannelCommands.Any())
            return UnitResult.Failure<string>("Factory unlock should establish secure channel");

        // Validate unlock commands present
        if (!unlockCommands.Any())
            return UnitResult.Failure<string>("Unlock operation should contain unlock commands");

        // Validate factory unlock responses - check if all unlock commands succeeded
        if (isFactoryUnlock)
        {
            var failedUnlockCommands = unlockCommands
                .Where(pair => !pair.Response.EndsWith("9000"))
                .ToList();

            if (failedUnlockCommands.Any())
                return UnitResult.Failure<string>("Factory unlock should succeed");
        }

        // Log successful findings
        _ = unlockCommands
            .Select(pair => $"✓ Found unlock command: {pair.Command}")
            .Aggregate(
                "",
                (current, message) =>
                {
                    TestContext.Out.WriteLine(message);
                    return current;
                }
            );

        TestContext.Out.WriteLine($"✓ {description} validated");
        return UnitResult.Success<string>();
    }

    /// <summary>
    /// Functional helper to validate key management operations.
    /// </summary>
    /// <param name="exchangesElement">The exchanges JSON element</param>
    /// <param name="description">Test description</param>
    /// <param name="traceFile">Trace file name</param>
    /// <returns>Result indicating validation success or failure</returns>
    private static UnitResult<string> ValidateKeyManagementOperations(
        JsonElement exchangesElement,
        string description,
        string traceFile
    )
    {
        TestContext.Out.WriteLine($"Testing {description}");

        List<JsonElement> exchanges = [.. exchangesElement.EnumerateArray()];
        var commandResponsePairs = exchanges
            .Select(e => new
            {
                Command = e.GetProperty("command").GetString()!,
                Response = e.GetProperty("response").GetString()!,
            })
            .ToList();

        // Analyze key management patterns
        var secureChannelCommands = commandResponsePairs
            .Where(pair => pair.Command.StartsWith("8050") || pair.Command.StartsWith("8482"))
            .ToList();

        var putKeyCommands = commandResponsePairs
            .Where(pair => pair.Command.StartsWith("80D8") || pair.Command.StartsWith("84D8"))
            .ToList();

        // Validate required operations
        if (!secureChannelCommands.Any())
            return UnitResult.Failure<string>(
                "Key management requires secure channel authentication"
            );

        if (!putKeyCommands.Any())
            return UnitResult.Failure<string>("Key management should contain PUT KEY commands");

        // Validate PUT KEY responses
        var failedPutKeyCommands = putKeyCommands
            .Where(pair => !pair.Response.EndsWith("9000"))
            .ToList();

        if (failedPutKeyCommands.Any())
            return UnitResult.Failure<string>("PUT KEY command should succeed");

        // Log successful findings
        _ = putKeyCommands
            .Select(pair => $"✓ Found PUT KEY command: {pair.Command}")
            .Aggregate(
                "",
                (current, message) =>
                {
                    TestContext.Out.WriteLine(message);
                    return current;
                }
            );

        TestContext.Out.WriteLine($"✓ {description} completed successfully");
        return UnitResult.Success<string>();
    }


    /// <summary>
    /// Functional helper to analyze authentication sequence.
    /// </summary>
    /// <param name="exchanges">List of exchanges</param>
    /// <returns>Result containing sequence indices or error message</returns>
    private static Result<
        (int initUpdate, int externalAuth, int privileged),
        string
    > AnalyzeAuthenticationSequence(List<JsonElement> exchanges)
    {
        var commandsWithIndices = exchanges
            .Select(
                (exchange, index) =>
                    new { Index = index, Command = exchange.GetProperty("command").GetString()! }
            )
            .ToList();

        var initUpdateCommands = commandsWithIndices
            .Where(item => item.Command.StartsWith("8050"))
            .ToList();
        var externalAuthCommands = commandsWithIndices
            .Where(item => item.Command.StartsWith("8482"))
            .ToList();
        var privilegedCommands = commandsWithIndices
            .Where(item => item.Command.StartsWith("80D8") || item.Command.StartsWith("80F0"))
            .ToList();

        int initUpdateIndex = initUpdateCommands.Any() ? initUpdateCommands.Last().Index : -1;
        int externalAuthIndex = externalAuthCommands.Any() ? externalAuthCommands.Last().Index : -1;
        int privilegedCommandIndex = privilegedCommands.Any()
            ? privilegedCommands.First().Index
            : -1;

        return Result.Success<(int, int, int), string>(
            (initUpdateIndex, externalAuthIndex, privilegedCommandIndex)
        );
    }

    /// <summary>
    /// Functional helper to validate authentication sequence order.
    /// </summary>
    /// <param name="sequenceIndices">The sequence indices tuple</param>
    /// <param name="traceFile">Trace file name</param>
    /// <returns>Result indicating validation success or failure</returns>
    private static UnitResult<string> ValidateAuthenticationSequence(
        (int initUpdate, int externalAuth, int privileged) sequenceIndices,
        string traceFile
    )
    {
        (int initUpdateIndex, int externalAuthIndex, int privilegedCommandIndex) = sequenceIndices;

        // Only validate if there are privileged commands
        if (privilegedCommandIndex == -1)
            return UnitResult.Success<string>();

        if (initUpdateIndex < 0)
            return UnitResult.Failure<string>(
                "Should have INITIALIZE UPDATE before privileged commands"
            );

        if (externalAuthIndex < 0)
            return UnitResult.Failure<string>(
                "Should have EXTERNAL AUTHENTICATE before privileged commands"
            );

        if (initUpdateIndex >= externalAuthIndex)
            return UnitResult.Failure<string>(
                "INITIALIZE UPDATE should come before EXTERNAL AUTHENTICATE"
            );

        if (externalAuthIndex >= privilegedCommandIndex)
            return UnitResult.Failure<string>(
                "EXTERNAL AUTHENTICATE should come before privileged commands"
            );

        // Log successful validation
        TestContext.Out.WriteLine($"✓ Authentication sequence validated for {traceFile}");
        TestContext.Out.WriteLine($"  INITIALIZE UPDATE at position {initUpdateIndex}");
        TestContext.Out.WriteLine($"  EXTERNAL AUTHENTICATE at position {externalAuthIndex}");
        TestContext.Out.WriteLine($"  Privileged command at position {privilegedCommandIndex}");

        return UnitResult.Success<string>();
    }

    /// <summary>
    /// Functional helper to validate complete authentication sequence.
    /// </summary>
    /// <param name="exchangesElement">The exchanges JSON element</param>
    /// <param name="traceFile">Trace file name</param>
    /// <returns>Result indicating validation success or failure</returns>
    private static UnitResult<string> ValidateCompleteAuthenticationSequence(
        JsonElement exchangesElement,
        string traceFile
    ) =>
        AnalyzeAuthenticationSequence([.. exchangesElement.EnumerateArray()])
            .Bind(sequenceIndices => ValidateAuthenticationSequence(sequenceIndices, traceFile));

    /// <summary>
    /// Validate that card management operations follow proper authentication sequences.
    /// All privileged operations should establish secure channels before execution.
    /// </summary>
    [TestCase("gp_pro_lock.json")]
    public void CardManagement_Should_Follow_Authentication_Sequence(string traceFile)
    {
        var result = LoadTraceFile(traceFile)
            .Bind(testData => ValidateExchangesExist(testData, traceFile))
            .Bind(exchangesElement =>
                ValidateCompleteAuthenticationSequence(exchangesElement, traceFile)
            );

        result.Match(
            () => { /* Test passed */
            },
            failure => Assert.Fail($"Test failed: {failure}")
        );
    }
}
