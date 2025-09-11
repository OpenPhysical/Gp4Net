using System;
using System.Collections.Generic;
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
/// Implementation of card compatibility service for safe real card testing.
/// </summary>
[PublicAPI]
public class CardCompatibilityService : ICardCompatibilityService
{
    private readonly ILogger<CardCompatibilityService> _logger;
    private readonly IEnvironmentValidationService _environmentValidation;

    /// <summary>
    /// Known card types and their characteristics.
    /// </summary>
    private static readonly Dictionary<string, CardTypeInfo> KnownCardTypes = new()
    {
        ["3BD518FF8191FE1FC38073C821100A"] = new CardTypeInfo(
            "NXP",
            "P71",
            "SmartMX3",
            isProduction: true,
            maxAuthenticationAttempts: 10,
            supportedProtocols: ["SCP02", "SCP03"],
            knownLimitations: ["Lockout after 10 failed auth attempts", "Requires GP Pro to reset"]
        ),
        ["3B7D94000080318065B08311C0A983009000"] = new CardTypeInfo(
            "Infineon",
            "SLE78",
            "CFlex",
            isProduction: true,
            maxAuthenticationAttempts: 10,
            supportedProtocols: ["SCP02", "SCP03"],
            knownLimitations: ["Permanent lockout possible", "Production fuses may be blown"]
        ),
        ["3B00"] = new CardTypeInfo(
            "Generic",
            "Virtual",
            "Test Card",
            isProduction: false,
            maxAuthenticationAttempts: Maybe<int>.None,
            supportedProtocols: ["SCP02", "SCP03"],
            knownLimitations: []
        ),
        ["3BD518008131FE45004A43"] = new CardTypeInfo(
            "JCOP",
            "JCOP3",
            "Development",
            isProduction: false,
            maxAuthenticationAttempts: 10,
            supportedProtocols: ["SCP02", "SCP03"],
            knownLimitations: ["Development card - may reset easily"]
        ),
    };

    /// <summary>
    /// CPLC manufacturer codes for identifying card vendors.
    /// </summary>
    private static readonly Dictionary<ushort, string> CplcManufacturers = new()
    {
        [0x4090] = "NXP",
        [0x4180] = "Infineon",
        [0x4250] = "Samsung",
        [0x4350] = "Gemalto",
        [0x4790] = "STMicroelectronics",
        [0x4440] = "Oberthur",
        [0x5353] = "Giesecke+Devrient",
    };

    /// <summary>
    /// Creates a new CardCompatibilityService with validated dependencies.
    /// </summary>
    public static Result<CardCompatibilityService, SmartCardError> Create(
        ILogger<CardCompatibilityService> logger,
        IEnvironmentValidationService environmentValidation
    )
    {
        return Maybe
            .From(logger)
            .ToResult(SmartCardError.InvalidArgument("Logger cannot be null"))
            .Bind(validLogger =>
                Maybe
                    .From(environmentValidation)
                    .ToResult(
                        SmartCardError.InvalidArgument(
                            "Environment validation service cannot be null"
                        )
                    )
                    .Map(validEnvValidation => new CardCompatibilityService(
                        validLogger,
                        validEnvValidation
                    ))
            );
    }

    private CardCompatibilityService(
        ILogger<CardCompatibilityService> logger,
        IEnvironmentValidationService environmentValidation
    )
    {
        _logger = logger;
        _environmentValidation = environmentValidation;
    }

    /// <inheritdoc />
    public async Task<Result<CardCompatibilityResult, SmartCardError>> CheckCompatibilityAsync(
        CardOperation operation,
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
            // Detect card type
            var cardTypeResult = await DetectCardTypeAsync(
                channel,
                transport,
                cancellationToken
            );
            if (cardTypeResult.IsFailure)
            {
                return Result.Failure<CardCompatibilityResult, SmartCardError>(
                    cardTypeResult.Error
                );
            }

            var cardType = cardTypeResult.Value;

            // Check environment validation
            var envResult =
                await _environmentValidation.ValidateEnvironmentAsync(
                    keySet,
                    channel,
                    transport,
                    cancellationToken
                );

            if (envResult.IsFailure)
            {
                return Result.Failure<CardCompatibilityResult, SmartCardError>(envResult.Error);
            }

            var envValidation = envResult.Value;

            // Analyze compatibility based on operation type and card characteristics
            (
                bool isCompatible,
                bool isSafe,
                string message,
                string[] warnings,
                string[] recommendations
            ) = AnalyzeCompatibility(operation, keySet, cardType, envValidation);

            var result = new CardCompatibilityResult(
                isCompatible,
                isSafe,
                cardType,
                message,
                warnings,
                recommendations
            );

            _logger.LogInformation(
                "Compatibility check: Operation={Operation}, Card={CardType}, Compatible={IsCompatible}, Safe={IsSafe}",
                operation,
                cardType.ToString(),
                isCompatible,
                isSafe
            );

            return Result.Success<CardCompatibilityResult, SmartCardError>(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to check card compatibility");
            return Result.Failure<CardCompatibilityResult, SmartCardError>(
                SmartCardError.UnexpectedError("Compatibility check failed", ex)
            );
        }
    }

    /// <inheritdoc />
    public async Task<Result<CardTypeInfo, SmartCardError>> DetectCardTypeAsync(
        ICardChannel channel,
        IApduTransport transport,
        CancellationToken cancellationToken = default
    )
    {
        ArgumentNullException.ThrowIfNull(channel);
        ArgumentNullException.ThrowIfNull(transport);

        try
        {
            // First, try to identify by ATR if available
            string atrHash = GetChannelIdentifier(channel);
            if (KnownCardTypes.TryGetValue(atrHash, out var knownType))
            {
                return Result.Success<CardTypeInfo, SmartCardError>(knownType);
            }

            // Try to get CPLC data for manufacturer identification
            var cplcResult = await GetCplcDataAsync(
                channel,
                transport,
                cancellationToken
            );
            if (cplcResult.IsSuccess)
            {
                var cardType = AnalyzeCplcForCardType(cplcResult.Value);
                if (cardType != null)
                {
                    return Result.Success<CardTypeInfo, SmartCardError>(cardType);
                }
            }

            // Fallback to generic unknown card
            var genericCard = new CardTypeInfo(
                "Unknown",
                "Unknown",
                null,
                isProduction: true, // Assume production for safety
                maxAuthenticationAttempts: 10, // Conservative estimate
                supportedProtocols: ["SCP02"],
                knownLimitations: ["Unknown card type - exercise extreme caution"]
            );

            return Result.Success<CardTypeInfo, SmartCardError>(genericCard);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to detect card type");
            return Result.Failure<CardTypeInfo, SmartCardError>(
                SmartCardError.UnexpectedError("Card type detection failed", ex)
            );
        }
    }

    /// <inheritdoc />
    public async Task<Result<int?, SmartCardError>> GetAuthenticationAttemptCountAsync(
        ICardChannel channel,
        IApduTransport transport,
        CancellationToken cancellationToken = default
    )
    {
        try
        {
            // Try to get card status or security status
            // This is card-specific and may not be available on all cards
            var commandResult = GetDataCommand.Create(
                GetDataCommand.DataObjects.ConfirmationCounter
            );
            if (commandResult.IsFailure)
            {
                return Result.Failure<int?, SmartCardError>(commandResult.Error);
            }

            var responseResult = await transport.TransmitAsync(
                commandResult.Value,
                channel,
                cancellationToken
            );

            return responseResult.Bind(response =>
                response.IsSuccessful && response.Data.Length > 0
                    ? GetDataResponse
                        .Parse(GetDataCommand.DataObjects.ConfirmationCounter, response.Data)
                        .Map(parsedResponse =>
                        {
                            var counter = parsedResponse.GetValueAsNumber();
                            return counter.HasValue ? (int?)counter.Value : null;
                        })
                    : Result.Success<int?, SmartCardError>(null)
            );
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not retrieve authentication attempt count");
            return Result.Success<int?, SmartCardError>(null);
        }
    }

    private static async Task<Result<byte[], SmartCardError>> GetCplcDataAsync(
        ICardChannel channel,
        IApduTransport transport,
        CancellationToken cancellationToken
    )
    {
        try
        {
            var commandResult = GetDataCommand.Create(
                GetDataCommand.DataObjects.CardProductionLifeCycle
            );
            if (commandResult.IsFailure)
            {
                return Result.Failure<byte[], SmartCardError>(commandResult.Error);
            }
            var getDataCmd = commandResult.Value;
            var responseResult = await transport.TransmitAsync(
                getDataCmd,
                channel,
                cancellationToken
            );

            return responseResult.Bind(response =>
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

    private static CardTypeInfo AnalyzeCplcForCardType(byte[] cplcData)
    {
        try
        {
            if (cplcData.Length < 10)
            {
                return null;
            }

            // Extract manufacturer code from CPLC (typically at offset 8-9)
            ushort manufacturerCode = (ushort)(cplcData[8] << 8 | cplcData[9]);

            if (CplcManufacturers.TryGetValue(manufacturerCode, out string manufacturer))
            {
                return new CardTypeInfo(
                    manufacturer,
                    "Unknown Family",
                    null,
                    isProduction: true, // CPLC indicates production card
                    maxAuthenticationAttempts: 10, // Conservative default
                    supportedProtocols: ["SCP02", "SCP03"],
                    knownLimitations: ["Production card - use caution with authentication"]
                );
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    private static string GetChannelIdentifier(ICardChannel channel)
    {
        // Generate a consistent identifier for the card
        // In a real implementation, this would use ATR or other unique data
        return channel.GetHashCode().ToString("X8");
    }

    private static (
        bool IsCompatible,
        bool IsSafe,
        string Message,
        string[] Warnings,
        string[] Recommendations
    ) AnalyzeCompatibility(
        CardOperation operation,
        IKeySet keySet,
        CardTypeInfo cardType,
        EnvironmentValidationResult envValidation
    )
    {
        List<string> warnings = [];
        List<string> recommendations = [];

        // If environment validation failed, operation is not safe
        if (!envValidation.IsSafe)
        {
            warnings.Add(envValidation.Message);
            warnings.AddRange(envValidation.Warnings);
            recommendations.Add("Use appropriate keyset for card environment");

            return (
                false,
                false,
                "Environment validation failed",
                warnings.ToArray(),
                recommendations.ToArray()
            );
        }

        // Check operation-specific compatibility
        (bool opCompatible, bool opSafe, string opMessage) = operation switch
        {
            CardOperation.Authentication => CheckAuthenticationCompatibility(
                keySet,
                cardType,
                envValidation
            ),
            CardOperation.KeyInstallation => CheckKeyInstallationCompatibility(cardType),
            CardOperation.ApplicationInstallation => CheckApplicationInstallationCompatibility(
                cardType
            ),
            CardOperation.ApplicationDeletion => CheckApplicationDeletionCompatibility(cardType),
            CardOperation.Personalization => CheckPersonalizationCompatibility(cardType),
            CardOperation.ReadOnly => (true, true, "Read-only operations are always safe"),
            _ => (false, false, "Unknown operation type"),
        };

        // Add card-specific warnings
        if (cardType.KnownLimitations.Length > 0)
        {
            warnings.AddRange(cardType.KnownLimitations);
        }

        // Add operation-specific recommendations
        if (
            operation == CardOperation.Authentication
            && cardType.MaxAuthenticationAttempts.HasValue
        )
        {
            recommendations.Add(
                cardType.MaxAuthenticationAttempts.Match(
                    attempts => $"Maximum {attempts} authentication attempts before lockout",
                    () => "Authentication attempts limit unknown"
                )
            );
            if (cardType.MaxAuthenticationAttempts.Match(attempts => attempts <= 3, () => false))
            {
                recommendations.Add(
                    "CRITICAL: Very few attempts allowed - verify keys before proceeding"
                );
            }
        }

        if (cardType.IsProduction && envValidation.IsTestKeySet)
        {
            recommendations.Add("Consider using production keysets for production cards");
        }

        return (opCompatible, opSafe, opMessage, warnings.ToArray(), recommendations.ToArray());
    }

    private static (bool Compatible, bool Safe, string Message) CheckAuthenticationCompatibility(
        IKeySet keySet,
        CardTypeInfo cardType,
        EnvironmentValidationResult envValidation
    )
    {
        // Authentication is generally compatible but safety depends on environment validation
        if (cardType.IsProduction && envValidation.IsTestKeySet)
        {
            return (true, false, "Test keys on production card - high risk of lockout");
        }

        if (cardType.MaxAuthenticationAttempts.Match(attempts => attempts <= 3, () => false))
        {
            return (true, false, "Card has very limited authentication attempts");
        }

        return (true, true, "Authentication appears safe with current keyset");
    }

    private static (bool Compatible, bool Safe, string Message) CheckKeyInstallationCompatibility(
        CardTypeInfo cardType
    )
    {
        if (cardType.IsProduction)
        {
            return (true, false, "Key installation on production cards is irreversible");
        }

        return (true, true, "Key installation should be safe on development cards");
    }

    private static (
        bool Compatible,
        bool Safe,
        string Message
    ) CheckApplicationInstallationCompatibility(CardTypeInfo cardType)
    {
        return (true, true, "Application installation is generally safe");
    }

    private static (
        bool Compatible,
        bool Safe,
        string Message
    ) CheckApplicationDeletionCompatibility(CardTypeInfo cardType)
    {
        if (cardType.IsProduction)
        {
            return (
                true,
                false,
                "Application deletion on production cards may affect other applications"
            );
        }

        return (true, true, "Application deletion should be safe on development cards");
    }

    private static (bool Compatible, bool Safe, string Message) CheckPersonalizationCompatibility(
        CardTypeInfo cardType
    )
    {
        if (cardType.IsProduction)
        {
            return (
                false,
                false,
                "Personalization operations should not be performed on production cards"
            );
        }

        return (true, true, "Personalization is safe on development cards");
    }
}
