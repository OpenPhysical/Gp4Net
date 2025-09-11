using CSharpFunctionalExtensions;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Service for accessing environment variables in a testable way.
/// Provides an abstraction boundary for environment dependencies.
/// </summary>
[PublicAPI]
public interface IEnvironmentService
{
    /// <summary>
    /// Gets the value of the GP4NET_READER environment variable.
    /// Used as fallback when no explicit reader is specified.
    /// </summary>
    /// <returns>Environment variable value or None if not set or empty.</returns>
    Maybe<string> GetGp4NetReaderVariable();
}