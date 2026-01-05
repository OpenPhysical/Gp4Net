using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;

namespace Gp4Net.Pipeline;

/// <summary>
/// An immutable implementation of IPipelineContext using CSharpFunctionalExtensions and persistent data structures.
/// </summary>
public sealed class ImmutablePipelineContext : IPipelineContext
{
    private readonly ImmutableDictionary<string, object> _values;

    /// <summary>
    /// Initializes a new instance of ImmutablePipelineContext.
    /// </summary>
    public ImmutablePipelineContext()
        : this(ImmutableDictionary<string, object>.Empty) { }

    /// <summary>
    /// Initializes a new instance of ImmutablePipelineContext with initial values.
    /// </summary>
    public ImmutablePipelineContext(ImmutableDictionary<string, object> initialValues)
    {
        ArgumentNullException.ThrowIfNull(initialValues);

        _values = initialValues
            .Where(kvp => kvp.Value is not null)
            .ToImmutableDictionary(kvp => kvp.Key, kvp => kvp.Value!);
    }

    /// <inheritdoc/>
    public Maybe<T> Get<T>(string key)
    {
        if (!_values.TryGetValue(key, out var value) || value is not T typedValue)
        {
            return Maybe<T>.None;
        }

        return Maybe<T>.From(typedValue);
    }

    /// <inheritdoc/>
    public IPipelineContext With<T>(string key, T value)
    {
        if (value is null)
        {
            throw new ArgumentNullException(nameof(value), "Pipeline context cannot store null values.");
        }

        return new ImmutablePipelineContext(_values.SetItem(key, value!));
    }

    /// <inheritdoc/>
    public IPipelineContext Without(string key)
    {
        return _values.ContainsKey(key) ? new ImmutablePipelineContext(_values.Remove(key)) : this;
    }

    /// <inheritdoc/>
    public ImmutableArray<string> Keys
    {
        get { return [.. _values.Keys]; }
    }

    /// <inheritdoc/>
    public IPipelineContext WithMany(ImmutableDictionary<string, object> values)
    {
        if (values.IsEmpty)
        {
            return this;
        }

        var builder = _values.ToBuilder();
        foreach (var kvp in values)
        {
            if (kvp.Value is null)
            {
                continue;
            }

            builder[kvp.Key] = kvp.Value!;
        }

        return new ImmutablePipelineContext(builder.ToImmutable());
    }

    /// <inheritdoc/>
    public ImmutableDictionary<string, object> ToImmutableDictionary()
    {
        return _values;
    }

    /// <summary>
    /// Creates an empty context.
    /// </summary>
    public static IPipelineContext Empty
    {
        get { return new ImmutablePipelineContext(); }
    }

    /// <summary>
    /// Creates a context with a single value.
    /// </summary>
    public static IPipelineContext Create<T>(string key, T value)
    {
        return Empty.With(key, value);
    }

    /// <summary>
    /// Creates a context from a dictionary of values.
    /// </summary>
    public static IPipelineContext Create(ImmutableDictionary<string, object> values)
    {
        return new ImmutablePipelineContext(values);
    }

    public override string ToString()
    {
        var items = _values.Select(kvp => $"{kvp.Key}: {kvp.Value?.GetType().Name ?? "null"}");
        return $"PipelineContext[{string.Join(", ", items)}]";
    }

    public override bool Equals(object? obj)
    {
        return obj is ImmutablePipelineContext other && _values.SequenceEqual(other._values);
    }

    public override int GetHashCode()
    {
        return _values.Aggregate(0, (hash, kvp) => HashCode.Combine(hash, kvp.Key, kvp.Value));
    }
}

/// <summary>
/// Extension methods for working with pipeline contexts.
/// </summary>
public static class PipelineContextExtensions
{
    /// <summary>
    /// Gets a required value from the context.
    /// </summary>
    /// <typeparam name="T">The type of value to retrieve.</typeparam>
    /// <param name="context">The pipeline context.</param>
    /// <param name="key">The key to look up.</param>
    /// <returns>A result containing the value or an error if not found.</returns>
    public static Result<T, SmartCardError> GetRequired<T>(
        this IPipelineContext context,
        string key
    )
    {
        return context
            .Get<T>(key)
            .Match(
                value => Result.Success<T, SmartCardError>(value),
                () =>
                    Result.Failure<T, SmartCardError>(
                        SmartCardError.InvalidArgument($"Required context value '{key}' not found.")
                    )
            );
    }

    /// <summary>
    /// Gets a value from the context or a default if not found.
    /// </summary>
    public static T GetOrDefault<T>(this IPipelineContext context, string key, T defaultValue)
    {
        return context.Get<T>(key).GetValueOrDefault(defaultValue);
    }

    /// <summary>
    /// Gets a value from the context or computes it if not found.
    /// </summary>
    public static T GetOrAdd<T>(this IPipelineContext context, string key, Func<T> factory)
    {
        return context.Get<T>(key).Match(value => value, factory);
    }

    /// <summary>
    /// Checks if a key exists in the context.
    /// </summary>
    public static bool Contains(this IPipelineContext context, string key)
    {
        return context.Keys.Contains(key);
    }

    /// <summary>
    /// Creates a new context by merging with another context.
    /// </summary>
    public static IPipelineContext Merge(this IPipelineContext context, IPipelineContext other)
    {
        return other.Keys.Aggregate(
            context,
            (current, key) =>
                other.Get<object>(key).Match(value => current.With(key, value), () => current)
        );
    }
}
