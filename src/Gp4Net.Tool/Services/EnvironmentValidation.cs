using System;
using System.Linq;
using System.Text;
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
/// Validates that secure channel operations occur in a safe environment.
/// </summary>
/// <remarks>
/// The service cross-references key material with card provenance (ATR, CPLC, behavior heuristics)
/// to prevent production hardware from being used with well-known test keys, fulfilling GP 2.3.1
/// safety requirements.
/// </remarks>
[PublicAPI]
public class EnvironmentValidation : IEnvironmentValidation
{
    private readonly ILogger<EnvironmentValidation> _logger;

    /// <summary>
    /// Well-known test keys that should never be used on production cards.
    /// </summary>
    private static readonly byte[][] WellKnownTestKeys =
    [
        // Standard GP test key (404142434445464748494A4B4C4D4E4F)
        GpTestKeys.GpTestKey,
        // Zero key (common but not GP standard)
        Convert.FromHexString("00000000000000000000000000000000"),
        // All ones key (common but not GP standard)
        Convert.FromHexString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        // Other common test keys
        Convert.FromHexString("000102030405060708090A0B0C0D0E0F"), // Sequential
        Convert.FromHexString("DEADBEEFDEADBEEFDEADBEEFDEADBEEF"), // DEADBEEF pattern
    ];

    /// <summary>
    /// Production card indicators in CPLC data.
    /// </summary>
    private static readonly string[] ProductionCardIndicators =
    [
        "NXP",
        "INFINEON",
        "SAMSUNG",
        "GEMALTO",
        "IDEMIA",
        "OBERTHUR",
        "GIESECKE",
        "MORPHO",
        "SAFENET",
        "SMARTCARD",
        "PRODUCTION",
        "COMMERCIAL",
    ];

    /// <summary>
    /// Test card indicators in CPLC data.
    /// </summary>
    private static readonly string[] TestCardIndicators =
    [
        "TEST",
        "DEVELOPMENT",
        "SAMPLE",
        "EVALUATION",
        "DEMO",
        "JCOP",
        "VIRTUAL",
    ];

    /// <summary>
    /// Initializes a new instance of EnvironmentValidation.
    /// </summary>
    public EnvironmentValidation(ILogger<EnvironmentValidation> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Validates that the provided keyset and card environment satisfy safety rules.
    /// </summary>
    /// <param name="keySet">Secure channel keyset under evaluation.</param>
    /// <param name="channel">Logical card channel used for discovery.</param>
    /// <param name="transport">Transport responsible for APDU exchange.</param>
    /// <param name="cancellationToken">Token used to cancel the validation.</param>
    /// <returns>
    /// A <see cref="Result{TValue,TError}"/> containing an <see cref="EnvironmentValidationResult"/>
    /// that flags unsafe combinations, or a <see cref="SmartCardError"/> detailing why validation
    /// could not be completed.
    /// </returns>
    /// <remarks>
    /// Validation combines <see cref="IsTestKeySet"/> analysis with <see cref="DetectCardEnvironmentAsync"/>
    /// so that known test keys are never used against production hardware. The result embeds both
    /// warning messages and the inferred environment classification.
    /// </remarks>
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
            var cardEnvResult = await DetectCardEnvironmentAsync(
                channel,
                transport,
                cancellationToken
            );
            if (cardEnvResult.IsFailure)
            {
                return Result.Failure<EnvironmentValidationResult, SmartCardError>(
                    cardEnvResult.Error
                );
            }

            var cardEnvironment = cardEnvResult.Value;
            bool isTestKeySet = IsTestKeySet(keySet);

            // Analyze safety of the combination
            (bool isSafe, string message, string[] warnings) = AnalyzeSafety(
                cardEnvironment,
                isTestKeySet
            );

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

    /// <summary>
    /// Determines whether the supplied keyset matches well-known test patterns.
    /// </summary>
    /// <param name="keySet">Keyset to evaluate.</param>
    /// <returns>
    /// <see langword="true"/> when any component matches GP Appendix D defaults or other forbidden
    /// patterns (zero, all-<c>FF</c>, sequential, or <c>DEADBEEF</c>); otherwise
    /// <see langword="false"/>.
    /// </returns>
    /// <remarks>
    /// The detection list is restricted to the officially supported test patterns defined in
    /// <c>docs/coverage/coverage-playbook.md</c>, ensuring vendor-specific secrets are never
    /// hard-coded into the service.
    /// </remarks>
    public bool IsTestKeySet(IKeySet keySet)
    {
        ArgumentNullException.ThrowIfNull(keySet);

        // Check if any of the keys match well-known test keys using GpTestKeys.IsTestKey()
        byte[][] keyBytes = [keySet.EncKey, keySet.MacKey, keySet.DekKey];

        foreach (byte[] key in keyBytes)
        {
            if (
                key != null
                && (
                    GpTestKeys.IsTestKey(key)
                    || WellKnownTestKeys.Any(testKey => testKey.SequenceEqual(key))
                )
            )
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Detects the card environment (production, test, or virtual) using ATR, CPLC, and heuristics.
    /// </summary>
    /// <param name="channel">Logical card channel used for discovery.</param>
    /// <param name="transport">Transport responsible for APDU exchange.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>
    /// A <see cref="Result{TValue,TError}"/> containing the detected <see cref="CardEnvironment"/>
    /// or a <see cref="SmartCardError"/> describing why detection failed.
    /// </returns>
    /// <remarks>
    /// Detection first checks for virtual channels, then reads CPLC data, and finally inspects card
    /// behavior patterns, mirroring the safety sequence outlined in GP 2.3.1.
    /// </remarks>
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
            var behaviorEnvironment = await AnalyzeCardBehaviorAsync(
                channel,
                transport,
                cancellationToken
            );
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
        string channelType = channel.GetType().Name;
        return channelType.Contains("Virtual")
            || channelType.Contains("Mock")
            || channelType.Contains("Trace")
            || channelType.Contains("Emulator");
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
            return await GetDataCommand
                .Create(GetDataCommand.DataObjects.CardProductionLifeCycle)
                .Bind(command => transport.TransmitAsync(command, channel, cancellationToken))
                .Bind(response =>
                    response.IsSuccessful && response.Data.Length > 0
                        ? Result.Success<byte[], SmartCardError>(response.Data)
                        : Result.Failure<byte[], SmartCardError>(
                            SmartCardError.CardError("CPLC data not available")
                        )
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
            string cplcString = Convert.ToHexString(cplcData);
            string cplcText = Encoding.ASCII.GetString(
                [.. cplcData.Where(b => b is >= 32 and <= 126)]
            );

            // Check for production indicators
            if (
                ProductionCardIndicators.Any(indicator =>
                    cplcString.Contains(indicator, StringComparison.OrdinalIgnoreCase)
                    || cplcText.Contains(indicator, StringComparison.OrdinalIgnoreCase)
                )
            )
            {
                return CardEnvironment.Production;
            }

            // Check for test indicators
            if (
                TestCardIndicators.Any(indicator =>
                    cplcString.Contains(indicator, StringComparison.OrdinalIgnoreCase)
                    || cplcText.Contains(indicator, StringComparison.OrdinalIgnoreCase)
                )
            )
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
            return await SelectCommand
                .Create(GpTestKeys.TestAids.IsdAid)
                .Bind(command => transport.TransmitAsync(command, channel, cancellationToken))
                .Match(
                    response =>
                        response.IsSuccessful ? CardEnvironment.Unknown : CardEnvironment.Test,
                    error => CardEnvironment.Test
                ); // If basic commands fail, likely a test/development environment
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
            (CardEnvironment.Test, true) => (true, "Safe: Test keys with test card", []),
            (CardEnvironment.Virtual, true) => (true, "Safe: Test keys with virtual card", []),
            (CardEnvironment.Production, false)
                => (true, "Safe: Production keys with production card", []),

            // Dangerous combinations
            (CardEnvironment.Production, true)
                => (
                    false,
                    "DANGEROUS: Test keys should not be used with production cards",
                    [
                        "Using test keys on production cards may cause lockout",
                        "Verify card type before proceeding",
                    ]
                ),

            // Questionable combinations
            (CardEnvironment.Test, false)
                => (
                    true,
                    "Questionable: Production keys with test card",
                    ["Using production keys on test cards may reveal sensitive information"]
                ),

            // Unknown combinations - err on the side of caution
            (CardEnvironment.Unknown, true)
                => (
                    true,
                    "Caution: Test keys with unknown card type",
                    ["Card type could not be determined", "Test keys are generally safer"]
                ),
            (CardEnvironment.Unknown, false)
                => (
                    false,
                    "CAUTION: Production keys with unknown card type",
                    ["Card type could not be determined", "Production keys may be risky"]
                ),

            _ => (false, "Unknown combination", new[] { "Unable to assess safety" }),
        };
    }
}
