using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Transport;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Implementation of environment validation service that prevents dangerous key/card combinations.
/// </summary>
[PublicAPI]
public class EnvironmentValidationService : IEnvironmentValidationService
{
    private readonly ILogger<EnvironmentValidationService> _logger;

    /// <summary>
    /// Well-known test keys that should never be used on production cards.
    /// </summary>
    private static readonly byte[][] WellKnownTestKeys =
    [

        // Standard GP test key (404142434445464748494A4B4C4D4E4F)
        GpTestKeys.StandardTestKey,
        // Zero key
        GpTestKeys.ZeroTestKey,
        // All ones key
        GpTestKeys.AllOnesTestKey,
        // Other common test keys
        Convert.FromHexString("000102030405060708090A0B0C0D0E0F"), // Sequential
        Convert.FromHexString("DEADBEEFDEADBEEFDEADBEEFDEADBEEF") // DEADBEEF pattern
    ];

    /// <summary>
    /// Production card indicators in CPLC data.
    /// </summary>
    private static readonly string[] ProductionCardIndicators =
    [
        "NXP", "INFINEON", "SAMSUNG", "GEMALTO", "IDEMIA", "OBERTHUR", "GIESECKE",
        "MORPHO", "SAFENET", "SMARTCARD", "PRODUCTION", "COMMERCIAL"
    ];

    /// <summary>
    /// Test card indicators in CPLC data.
    /// </summary>
    private static readonly string[] TestCardIndicators =
    [
        "TEST", "DEVELOPMENT", "SAMPLE", "EVALUATION", "DEMO", "JCOP", "VIRTUAL"
    ];

    /// <summary>
    /// Initializes a new instance of EnvironmentValidationService.
    /// </summary>
    public EnvironmentValidationService(ILogger<EnvironmentValidationService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public async Task<Result<EnvironmentValidationResult, SmartCardError>> ValidateEnvironmentAsync(
        IKeySet keySet,
        ICardChannel channel,
        IApduTransport transport,
        CancellationToken cancellationToken = default
    )
    {
        ArgumentNullException.ThrowIfNull(keySet);
        ArgumentNullException.ThrowIfNull(channel);
        ArgumentNullException.ThrowIfNull(transport);

        try
        {
            // Detect card environment
            var cardEnvResult = await DetectCardEnvironmentAsync(channel, transport, cancellationToken);
            if (cardEnvResult.IsFailure)
            {
                return Result.Failure<EnvironmentValidationResult, SmartCardError>(cardEnvResult.Error);
            }

            var cardEnvironment = cardEnvResult.Value;
            var isTestKeySet = IsTestKeySet(keySet);

            // Analyze safety of the combination
            var (isSafe, message, warnings) = AnalyzeSafety(cardEnvironment, isTestKeySet);

            var result = new EnvironmentValidationResult(
                isSafe,
                cardEnvironment,
                isTestKeySet,
                message,
                warnings
            );

            _logger.LogInformation(
                "Environment validation: Card={CardEnvironment}, TestKeys={IsTestKeySet}, Safe={IsSafe}",
                cardEnvironment,
                isTestKeySet,
                isSafe
            );

            return Result.Success<EnvironmentValidationResult, SmartCardError>(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to validate environment");
            return Result.Failure<EnvironmentValidationResult, SmartCardError>(
                SmartCardError.UnexpectedError("Environment validation failed", ex)
            );
        }
    }

    /// <inheritdoc />
    public bool IsTestKeySet(IKeySet keySet)
    {
        ArgumentNullException.ThrowIfNull(keySet);

        // Check if any of the keys match well-known test keys
        var keyBytes = new[] { keySet.EncKey, keySet.MacKey, keySet.DekKey };
            
        foreach (var key in keyBytes)
        {
            if (key != null && WellKnownTestKeys.Any(testKey => testKey.SequenceEqual(key)))
            {
                return true;
            }
        }

        return false;
    }

    /// <inheritdoc />
    public async Task<Result<CardEnvironment, SmartCardError>> DetectCardEnvironmentAsync(
        ICardChannel channel,
        IApduTransport transport,
        CancellationToken cancellationToken = default
    )
    {
        ArgumentNullException.ThrowIfNull(channel);
        ArgumentNullException.ThrowIfNull(transport);

        try
        {
            // Check if this is a virtual/mock card
            if (IsVirtualCard(channel))
            {
                return Result.Success<CardEnvironment, SmartCardError>(CardEnvironment.Virtual);
            }

            // Try to get CPLC data to identify card type
            var cplcResult = await GetCplcDataAsync(channel, transport, cancellationToken);
            if (cplcResult.IsSuccess)
            {
                var environment = AnalyzeCplcData(cplcResult.Value);
                if (environment != CardEnvironment.Unknown)
                {
                    return Result.Success<CardEnvironment, SmartCardError>(environment);
                }
            }

            // Fallback: analyze card behavior patterns
            var behaviorEnvironment = await AnalyzeCardBehaviorAsync(channel, transport, cancellationToken);
            return Result.Success<CardEnvironment, SmartCardError>(behaviorEnvironment);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to detect card environment, defaulting to Unknown");
            return Result.Success<CardEnvironment, SmartCardError>(CardEnvironment.Unknown);
        }
    }

    private static bool IsVirtualCard(ICardChannel channel)
    {
        // Check if the channel implementation suggests a virtual card
        var channelType = channel.GetType().Name;
        return channelType.Contains("Virtual") || 
               channelType.Contains("Mock") || 
               channelType.Contains("Trace") ||
               channelType.Contains("Emulator");
    }

    private static async Task<Result<byte[], SmartCardError>> GetCplcDataAsync(
        ICardChannel channel,
        IApduTransport transport,
        CancellationToken cancellationToken
    )
    {
        try
        {
            // GET DATA for CPLC (Card Production Life Cycle) - tag 9F7F
            var commandResult = GetDataCommand.Create(GetDataCommand.DataObjects.CardProductionLifeCycle);
            if (commandResult.IsFailure)
            {
                return Result.Failure<byte[], SmartCardError>(commandResult.Error);
            }
                
            var response = await transport.TransmitAsync(commandResult.Value, channel, cancellationToken);

            if (response.IsSuccess && response.Data.Length > 0)
            {
                return Result.Success<byte[], SmartCardError>(response.Data);
            }

            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.CardError("CPLC data not available")
            );
        }
        catch (Exception ex)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.CommunicationError("Failed to retrieve CPLC data", ex)
            );
        }
    }

    private static CardEnvironment AnalyzeCplcData(byte[] cplcData)
    {
        try
        {
            // Convert CPLC data to string for analysis
            var cplcString = Convert.ToHexString(cplcData);
            var cplcText = System.Text.Encoding.ASCII.GetString(cplcData.Where(b => b is >= 32 and <= 126).ToArray());

            // Check for production indicators
            if (ProductionCardIndicators.Any(indicator => 
                    cplcString.Contains(indicator, StringComparison.OrdinalIgnoreCase) ||
                    cplcText.Contains(indicator, StringComparison.OrdinalIgnoreCase)))
            {
                return CardEnvironment.Production;
            }

            // Check for test indicators
            if (TestCardIndicators.Any(indicator => 
                    cplcString.Contains(indicator, StringComparison.OrdinalIgnoreCase) ||
                    cplcText.Contains(indicator, StringComparison.OrdinalIgnoreCase)))
            {
                return CardEnvironment.Test;
            }

            return CardEnvironment.Unknown;
        }
        catch
        {
            return CardEnvironment.Unknown;
        }
    }

    private static async Task<CardEnvironment> AnalyzeCardBehaviorAsync(
        ICardChannel channel,
        IApduTransport transport,
        CancellationToken cancellationToken
    )
    {
        try
        {
            // Try SELECT ISD (Issuer Security Domain)
            var selectResult = SelectCommand.Create(GpTestKeys.TestAids.IsdAid);
            if (selectResult.IsFailure)
            {
                return CardEnvironment.Test;
            }
                
            var selectCmd = selectResult.Value;
            var response = await transport.TransmitAsync(selectCmd, channel, cancellationToken);

            if (!response.IsSuccess)
            {
                // If basic commands fail, likely a test/development environment
                return CardEnvironment.Test;
            }

            // For now, default to unknown if we can't determine from behavior
            return CardEnvironment.Unknown;
        }
        catch
        {
            return CardEnvironment.Test; // Errors suggest test environment
        }
    }

    private static (bool IsSafe, string Message, string[] Warnings) AnalyzeSafety(
        CardEnvironment cardEnvironment,
        bool isTestKeySet
    )
    {
        return (cardEnvironment, isTestKeySet) switch
        {
            // Safe combinations
            (CardEnvironment.Test, true) => (
                true,
                "Safe: Test keys with test card",
                []
            ),
            (CardEnvironment.Virtual, true) => (
                true,
                "Safe: Test keys with virtual card",
                []
            ),
            (CardEnvironment.Production, false) => (
                true,
                "Safe: Production keys with production card",
                []
            ),

            // Dangerous combinations
            (CardEnvironment.Production, true) => (
                false,
                "DANGEROUS: Test keys should not be used with production cards",
                ["Using test keys on production cards may cause lockout", "Verify card type before proceeding"]
            ),

            // Questionable combinations
            (CardEnvironment.Test, false) => (
                true,
                "Questionable: Production keys with test card",
                ["Using production keys on test cards may reveal sensitive information"]
            ),

            // Unknown combinations - err on the side of caution
            (CardEnvironment.Unknown, true) => (
                true,
                "Caution: Test keys with unknown card type",
                ["Card type could not be determined", "Test keys are generally safer"]
            ),
            (CardEnvironment.Unknown, false) => (
                false,
                "CAUTION: Production keys with unknown card type",
                ["Card type could not be determined", "Production keys may be risky"]
            ),

            _ => (
                false,
                "Unknown combination",
                new[] { "Unable to assess safety" }
            )
        };
    }
}