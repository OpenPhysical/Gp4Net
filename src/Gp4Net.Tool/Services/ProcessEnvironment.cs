using System;
using CSharpFunctionalExtensions;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Production implementation of IProcessEnvironment using System.Environment.
/// Provides access to environment variables for configuration.
/// </summary>
[PublicAPI]
public static class ProcessEnvironment
{
    /// <inheritdoc/>
    public static Maybe<string> GetGp4NetReaderVariable()
    {
        var value = Environment.GetEnvironmentVariable("GP4NET_READER");
        return string.IsNullOrWhiteSpace(value)
            ? Maybe<string>.None
            : Maybe<string>.From(value.Trim());
    }
}
