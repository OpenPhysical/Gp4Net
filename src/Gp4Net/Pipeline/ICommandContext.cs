using System.Collections.Generic;

namespace Gp4Net.Pipeline
{
    /// <summary>
    /// Represents an immutable context that flows through the command pipeline.
    /// </summary>
    public interface ICommandContext
    {
        /// <summary>
        /// Gets a value from the context.
        /// </summary>
        /// <typeparam name="T">The type of the value.</typeparam>
        /// <param name="key">The key to look up.</param>
        /// <returns>The value if found, otherwise null.</returns>
        T? Get<T>(string key) where T : class;

        /// <summary>
        /// Tries to get a value from the context.
        /// </summary>
        /// <typeparam name="T">The type of the value.</typeparam>
        /// <param name="key">The key to look up.</param>
        /// <param name="value">The value if found.</param>
        /// <returns>True if the value was found, otherwise false.</returns>
        bool TryGet<T>(string key, out T? value) where T : class;

        /// <summary>
        /// Creates a new context with an additional value.
        /// </summary>
        /// <typeparam name="T">The type of the value.</typeparam>
        /// <param name="key">The key to store the value under.</param>
        /// <param name="value">The value to store.</param>
        /// <returns>A new context containing the additional value.</returns>
        ICommandContext With<T>(string key, T value);

        /// <summary>
        /// Creates a new context without the specified key.
        /// </summary>
        /// <param name="key">The key to remove.</param>
        /// <returns>A new context without the specified key.</returns>
        ICommandContext Without(string key);

        /// <summary>
        /// Gets all keys in the context.
        /// </summary>
        IEnumerable<string> Keys { get; }

        /// <summary>
        /// Creates a new context with multiple values.
        /// </summary>
        /// <param name="values">The values to add.</param>
        /// <returns>A new context containing the additional values.</returns>
        ICommandContext WithMany(IReadOnlyDictionary<string, object> values);
    }

}