using System;

namespace Gp4Net.Tool.Infrastructure
{
    /// <summary>
    /// Represents a resolved smart card reader.
    /// </summary>
    public class Reader
    {
        /// <summary>
        /// Gets the reader name.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// Gets a value indicating whether this reader was auto-detected.
        /// </summary>
        public bool IsAutoDetected { get; }

        /// <summary>
        /// Gets a value indicating whether this reader was selected via partial match.
        /// </summary>
        public bool IsPartialMatch { get; }

        /// <summary>
        /// Initializes a new instance of the Reader class.
        /// </summary>
        /// <param name="name">The reader name.</param>
        /// <param name="isAutoDetected">Whether this reader was auto-detected.</param>
        /// <param name="isPartialMatch">Whether this reader was selected via partial match.</param>
        public Reader(string name, bool isAutoDetected = false, bool isPartialMatch = false)
        {
            Name = name ?? throw new ArgumentNullException(nameof(name));
            IsAutoDetected = isAutoDetected;
            IsPartialMatch = isPartialMatch;
        }

        /// <summary>
        /// Returns the reader name.
        /// </summary>
        /// <returns>The reader name.</returns>
        public override string ToString()
        {
            return Name;
        }

        /// <summary>
        /// Implicit conversion to string.
        /// </summary>
        /// <param name="reader">The reader.</param>
        public static implicit operator string(Reader reader)
        {
            return reader?.Name ?? string.Empty;
        }
    }
}
