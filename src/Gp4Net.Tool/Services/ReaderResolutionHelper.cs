using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Services;
using Gp4Net.Tool.Pipeline;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Helper functions for integrating smart reader resolution into CLI commands.
/// Provides composable functions for the resolution flow with user feedback.
/// </summary>
[PublicAPI]
public static class ReaderResolutionHelper
{
    /// <summary>
    /// Performs complete reader resolution and connection flow.
    /// Combines resolution, connection, and error handling in a single operation.
    /// </summary>
    /// <param name="explicitReader">Explicit reader specification from command line.</param>
    /// <param name="serviceFactory">Factory for creating card services.</param>
    /// <param name="resolutionService">Service for resolving readers.</param>
    /// <param name="displayService">Service for displaying progress/errors.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Connected smart card service or error.</returns>
    public static async Task<Result<ISmartCardService, SmartCardError>> ResolveAndConnectAsync(
        Maybe<string> explicitReader,
        ISmartCardServiceFactory serviceFactory,
        IReaderResolutionService resolutionService,
        IDisplayService displayService,
        CancellationToken cancellationToken = default)
    {
        // Resolve the reader
        var resolutionResult = await resolutionService.ResolveReaderAsync(explicitReader, cancellationToken);
        
        return await resolutionResult
            .Tap(resolution => DisplayResolutionInfo(resolution, displayService))
            .Bind(async resolution => 
            {
                // Connect to the resolved reader
                var connectionResult = await serviceFactory.CreateConnectedAsync(
                    resolution.ReaderName, 
                    cancellationToken);
                
                return connectionResult.Tap(service =>
                    displayService.Success($"Connected to {resolution.ReaderName}"));
            });
    }

    /// <summary>
    /// Displays reader resolution information to the user.
    /// Shows which resolution method was used and provides context.
    /// </summary>
    /// <param name="resolution">The resolved reader information.</param>
    /// <param name="displayService">Service for displaying information.</param>
    public static void DisplayResolutionInfo(
        ReaderResolution resolution,
        IDisplayService displayService)
    {
        var message = resolution.Method switch
        {
            ResolutionMethod.ExplicitFlag => 
                $"Using reader specified via --reader flag: {resolution.ReaderName}",
            
            ResolutionMethod.Environment => 
                $"Using reader from GP4NET_READER environment variable: {resolution.ReaderName}",
            
            ResolutionMethod.AutoDetection => 
                $"Auto-detected single reader with card present: {resolution.ReaderName}",
            
            _ => $"Using reader: {resolution.ReaderName}"
        };

        displayService.Info(message);
    }

    /// <summary>
    /// Formats reader resolution errors with helpful guidance.
    /// Provides actionable error messages for common scenarios.
    /// </summary>
    /// <param name="error">The error to format.</param>
    /// <returns>Formatted error message with guidance.</returns>
    public static string FormatResolutionError(SmartCardError error)
    {
        return error.Message switch
        {
            var msg when msg.Contains("No smart card readers found") =>
                "No smart card readers found on this system.\n" +
                "Please connect a smart card reader and try again.",
            
            var msg when msg.Contains("No smart cards detected") =>
                "No smart cards detected in any reader.\n" +
                "Please insert a smart card and try again.",
            
            var msg when msg.Contains("Multiple readers have cards") =>
                error.Message + "\n" +
                "Example: gp4net card info --reader \"Reader Name\"",
            
            var msg when msg.Contains("Multiple readers match") =>
                error.Message + "\n" +
                "Be more specific with the reader name or use the full name.",
            
            var msg when msg.Contains("environment variable") =>
                error.Message + "\n" +
                "You can also unset the environment variable to use auto-detection.",
            
            _ => error.Message
        };
    }

    /// <summary>
    /// Tries to resolve a reader from command settings using the resolution service.
    /// Helper for commands that need reader resolution.
    /// </summary>
    /// <param name="readerName">Reader name from command settings (may be empty).</param>
    /// <param name="resolutionService">Resolution service to use.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Resolved reader name or error.</returns>
    public static async Task<Result<string, SmartCardError>> ResolveReaderNameAsync(
        string readerName,
        IReaderResolutionService resolutionService,
        CancellationToken cancellationToken = default)
    {
        var explicitReader = string.IsNullOrWhiteSpace(readerName) 
            ? Maybe<string>.None 
            : Maybe<string>.From(readerName.Trim());

        var resolutionResult = await resolutionService.ResolveReaderAsync(explicitReader, cancellationToken);
        
        return resolutionResult.Map(resolution => resolution.ReaderName);
    }
}