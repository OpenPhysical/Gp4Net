using System;

namespace Gp4Net.Tool.Pipeline;

/// <summary>
/// Service for displaying information to the user.
/// </summary>
public interface IDisplayService
{
    /// <summary>
    /// Displays a success message.
    /// </summary>
    void Success(string message);

    /// <summary>
    /// Displays an error message.
    /// </summary>
    void Error(string message);

    /// <summary>
    /// Displays a warning message.
    /// </summary>
    void Warning(string message);

    /// <summary>
    /// Displays an informational message.
    /// </summary>
    void Info(string message);

    /// <summary>
    /// Displays verbose information if verbose mode is enabled.
    /// </summary>
    void Verbose(string message);

    /// <summary>
    /// Displays an exception with formatting.
    /// </summary>
    void Exception(Exception exception);

    /// <summary>
    /// Displays card information.
    /// </summary>
    void CardInfo(byte[] atr);

    /// <summary>
    /// Displays raw markup text.
    /// </summary>
    void Markup(string markup);
}