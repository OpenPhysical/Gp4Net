using System.Collections.Immutable;
using CSharpFunctionalExtensions;

namespace Gp4Net.Pipeline
{
    /// <summary>
    /// Represents an immutable context that flows through the command pipeline.
    /// Uses CSharpFunctionalExtensions types for proper functional programming.
    /// Acts as a typed immutable dictionary for pipeline data flow.
    /// </summary>
    public interface IPipelineContext
    {
        /// <summary>
        /// Gets a value from the context.
        /// </summary>
        /// <typeparam name="T">The type of the value.</typeparam>
        /// <param name="key">The key to look up.</param>
        /// <returns>Maybe containing the value if found, None otherwise.</returns>
        Maybe<T> Get<T>(string key);

        /// <summary>
        /// Creates a new context with an additional value.
        /// </summary>
        /// <typeparam name="T">The type of the value.</typeparam>
        /// <param name="key">The key to store the value under.</param>
        /// <param name="value">The value to store.</param>
        /// <returns>A new context containing the additional value.</returns>
        IPipelineContext With<T>(string key, T value);

        /// <summary>
        /// Creates a new context without the specified key.
        /// </summary>
        /// <param name="key">The key to remove.</param>
        /// <returns>A new context without the specified key.</returns>
        IPipelineContext Without(string key);

        /// <summary>
        /// Gets all keys in the context as an immutable sequence.
        /// </summary>
        ImmutableArray<string> Keys { get; }

        /// <summary>
        /// Creates a new context with multiple values.
        /// </summary>
        /// <param name="values">The values to add.</param>
        /// <returns>A new context containing the additional values.</returns>
        IPipelineContext WithMany(ImmutableDictionary<string, object> values);

        /// <summary>
        /// Gets the underlying dictionary for functional operations.
        /// </summary>
        ImmutableDictionary<string, object> ToImmutableDictionary();
    }
}