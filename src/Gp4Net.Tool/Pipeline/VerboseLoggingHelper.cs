using System;
using System.Reflection;
using log4net;
using log4net.Appender;
using log4net.Core;
using log4net.Layout;
using log4net.Repository.Hierarchy;

namespace Gp4Net.Tool.Pipeline
{
    /// <summary>
    /// Helper class to dynamically enable verbose console logging.
    /// </summary>
    public static class VerboseLoggingHelper
    {
        private static ConsoleAppender? _verboseAppender;
        private static bool _isVerboseEnabled;

        /// <summary>
        /// Enables or disables verbose console logging.
        /// </summary>
        public static void EnableVerboseLogging(bool enable)
        {
            if (enable == _isVerboseEnabled)
            {
                return; // No change needed
            }

            var logRepository = LogManager.GetRepository(
                Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly()
            );

            if (logRepository is Hierarchy hierarchy)
            {
                if (enable && _verboseAppender == null)
                {
                    // Create and add console appender
                    _verboseAppender = new ConsoleAppender
                    {
                        Name = "VerboseConsoleAppender",
                        Layout = new PatternLayout(
                            "%date [%thread] %-5level %logger - %message%newline"
                        ),
                        Threshold = Level.Debug
                    };
                    _verboseAppender.ActivateOptions();

                    hierarchy.Root.AddAppender(_verboseAppender);
                    hierarchy.Configured = true;
                    hierarchy.RaiseConfigurationChanged(EventArgs.Empty);
                }
                else if (!enable && _verboseAppender != null)
                {
                    // Remove console appender
                    _ = hierarchy.Root.RemoveAppender(_verboseAppender);
                    _verboseAppender = null;
                    hierarchy.RaiseConfigurationChanged(EventArgs.Empty);
                }
            }

            _isVerboseEnabled = enable;
        }
    }
}
