using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;

namespace Gp4Net.Pipeline
{
    /// <summary>
    /// An immutable implementation of ICommandContext using persistent data structures.
    /// </summary>
    public sealed class ImmutableCommandContext : ICommandContext
    {
        private readonly ImmutableDictionary<string, object> _values;

        /// <summary>
        /// Initializes a new instance of ImmutableCommandContext.
        /// </summary>
        public ImmutableCommandContext() : this(ImmutableDictionary<string, object>.Empty)
        {
        }

        /// <summary>
        /// Initializes a new instance of ImmutableCommandContext with initial values.
        /// </summary>
        public ImmutableCommandContext(IReadOnlyDictionary<string, object> initialValues)
            : this(initialValues.ToImmutableDictionary())
        {
        }

        private ImmutableCommandContext(ImmutableDictionary<string, object> values)
        {
            _values = values;
        }

        /// <inheritdoc/>
        public T? Get<T>(string key) where T : class
        {
            ArgumentNullException.ThrowIfNull(key);
            return _values.TryGetValue(key, out var value) ? value as T : null;
        }

        /// <inheritdoc/>
        public bool TryGet<T>(string key, out T? value) where T : class
        {
            ArgumentNullException.ThrowIfNull(key);
            value = Get<T>(key);
            return value != null;
        }

        /// <inheritdoc/>
        public ICommandContext With<T>(string key, T value)
        {
            ArgumentNullException.ThrowIfNull(key);
            if (value == null)
                throw new ArgumentNullException(nameof(value));
            
            return new ImmutableCommandContext(_values.SetItem(key, value));
        }

        /// <inheritdoc/>
        public ICommandContext Without(string key)
        {
            ArgumentNullException.ThrowIfNull(key);
            
            return _values.ContainsKey(key)
                ? new ImmutableCommandContext(_values.Remove(key))
                : this;
        }

        /// <inheritdoc/>
        public IEnumerable<string> Keys => _values.Keys;

        /// <inheritdoc/>
        public ICommandContext WithMany(IReadOnlyDictionary<string, object> values)
        {
            ArgumentNullException.ThrowIfNull(values);
            
            if (!values.Any())
                return this;

            var builder = _values.ToBuilder();
            foreach (var kvp in values)
            {
                builder[kvp.Key] = kvp.Value;
            }
            
            return new ImmutableCommandContext(builder.ToImmutable());
        }

        /// <summary>
        /// Creates an empty context.
        /// </summary>
        public static ICommandContext Empty => new ImmutableCommandContext();

        /// <summary>
        /// Creates a context with a single value.
        /// </summary>
        public static ICommandContext Create<T>(string key, T value) where T : class =>
            Empty.With(key, value);

        /// <summary>
        /// Creates a context from a dictionary of values.
        /// </summary>
        public static ICommandContext Create(IReadOnlyDictionary<string, object> values) =>
            new ImmutableCommandContext(values);

        public override string ToString()
        {
            var items = _values.Select(kvp => $"{kvp.Key}: {kvp.Value?.GetType().Name ?? "null"}");
            return $"Context[{string.Join(", ", items)}]";
        }

        public override bool Equals(object? obj) =>
            obj is ImmutableCommandContext other &&
            _values.SequenceEqual(other._values);

        public override int GetHashCode() =>
            _values.Aggregate(0, (hash, kvp) => HashCode.Combine(hash, kvp.Key, kvp.Value));
    }

    /// <summary>
    /// Extension methods for working with command contexts.
    /// </summary>
    public static class CommandContextExtensions
    {
        /// <summary>
        /// Gets a required value from the context, throwing if not found.
        /// </summary>
        public static T GetRequired<T>(this ICommandContext context, string key) where T : class
        {
            var value = context.Get<T>(key);
            if (value == null)
            {
                throw new InvalidOperationException($"Required context value '{key}' not found.");
            }
            return value;
        }

        /// <summary>
        /// Gets a value from the context or a default if not found.
        /// </summary>
        public static T GetOrDefault<T>(this ICommandContext context, string key, T defaultValue) where T : class =>
            context.Get<T>(key) ?? defaultValue;

        /// <summary>
        /// Gets a value from the context or computes it if not found.
        /// </summary>
        public static T GetOrAdd<T>(this ICommandContext context, string key, Func<T> factory) where T : class
        {
            var value = context.Get<T>(key);
            if (value != null)
                return value;

            value = factory();
            // Note: This doesn't modify the context, just returns the computed value
            // To actually add it, the caller would need to use With()
            return value;
        }

        /// <summary>
        /// Checks if a key exists in the context.
        /// </summary>
        public static bool Contains(this ICommandContext context, string key) =>
            context.Keys.Contains(key);

        /// <summary>
        /// Creates a new context by merging with another context.
        /// </summary>
        public static ICommandContext Merge(this ICommandContext context, ICommandContext other)
        {
            var result = context;
            foreach (var key in other.Keys)
            {
                var value = other.Get<object>(key);
                if (value != null)
                {
                    result = result.With(key, value);
                }
            }
            return result;
        }
    }
}