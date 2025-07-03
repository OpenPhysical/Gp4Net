using System;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Pipeline
{
    /// <summary>
    /// Marks a class as a command handler for automatic registration.
    /// </summary>
    [PublicAPI]
    [AttributeUsage(AttributeTargets.Class)]
    public class CommandHandlerAttribute : Attribute
    {
        /// <summary>
        /// Gets or sets the command name. If not specified, derives from the class name.
        /// </summary>
        public string? CommandName { get; set; }

        /// <summary>
        /// Gets or sets the command description.
        /// </summary>
        public string? Description { get; set; }
    }
}
