using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Scripting;

/// <summary>
/// Resolves script and configuration directories based on platform conventions.
/// </summary>
[PublicAPI]
public class ScriptDirectoryResolver
{
    private const string AppName = "gp4net";
    private const string ScriptsDirectory = "scripts";
    private const string ConfigFileName = "config.yaml";

    /// <summary>
    /// Gets the ordered list of directories to search for scripts.
    /// </summary>
    public IReadOnlyList<string> GetScriptSearchPaths()
    {
        var paths = new List<string>();

        // 1. Current directory
        var currentDirScripts = Path.Combine(Directory.GetCurrentDirectory(), ScriptsDirectory);
        paths.Add(currentDirScripts);

        // 2. User directory
        var userScriptsPath = GetUserScriptsPath();
        if (!string.IsNullOrEmpty(userScriptsPath))
        {
            paths.Add(userScriptsPath);
        }

        // 3. System directory
        var systemScriptsPath = GetSystemScriptsPath();
        if (!string.IsNullOrEmpty(systemScriptsPath))
        {
            paths.Add(systemScriptsPath);
        }

        return paths;
    }

    /// <summary>
    /// Gets the ordered list of paths to search for configuration files.
    /// </summary>
    public IReadOnlyList<string> GetConfigSearchPaths()
    {
        var paths = new List<string>
        {
            // 1. Current directory
            Path.Combine(Directory.GetCurrentDirectory(), ConfigFileName),
            Path.Combine(Directory.GetCurrentDirectory(), $"{AppName}.yaml")
        };

        // 2. User directory
        var userConfigPath = GetUserConfigPath();
        if (!string.IsNullOrEmpty(userConfigPath))
        {
            paths.Add(userConfigPath);
        }

        // 3. System directory
        var systemConfigPath = GetSystemConfigPath();
        if (!string.IsNullOrEmpty(systemConfigPath))
        {
            paths.Add(systemConfigPath);
        }

        return paths;
    }

    /// <summary>
    /// Finds a script file in the search paths.
    /// </summary>
    public string? FindScript(string scriptName)
    {
        // If it's already a full path, check if it exists
        if (Path.IsPathRooted(scriptName))
        {
            return File.Exists(scriptName) ? scriptName : null;
        }

        // Add .lua extension if not present
        if (!scriptName.EndsWith(".lua", StringComparison.OrdinalIgnoreCase))
        {
            scriptName += ".lua";
        }

        // Search in all script directories
        foreach (var searchPath in GetScriptSearchPaths())
        {
            var fullPath = Path.Combine(searchPath, scriptName);
            if (File.Exists(fullPath))
            {
                return fullPath;
            }
        }

        return null;
    }

    /// <summary>
    /// Finds the configuration file.
    /// </summary>
    public string? FindConfigFile()
    {
        foreach (var configPath in GetConfigSearchPaths())
        {
            if (File.Exists(configPath))
            {
                return configPath;
            }
        }

        return null;
    }

    /// <summary>
    /// Ensures the user directory structure exists.
    /// </summary>
    public void EnsureUserDirectories()
    {
        var userScriptsPath = GetUserScriptsPath();
        if (!string.IsNullOrEmpty(userScriptsPath))
        {
            _ = Directory.CreateDirectory(userScriptsPath);
        }

        var userConfigDir = Path.GetDirectoryName(GetUserConfigPath());
        if (!string.IsNullOrEmpty(userConfigDir))
        {
            _ = Directory.CreateDirectory(userConfigDir);
        }
    }

    private static string GetUserScriptsPath()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // Windows: %APPDATA%\gp4net\scripts
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            return Path.Combine(appData, AppName, ScriptsDirectory);
        }
        else
        {
            // Linux/macOS: ~/.gp4net/scripts
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            return Path.Combine(home, $".{AppName}", ScriptsDirectory);
        }
    }

    private static string GetUserConfigPath()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // Windows: %APPDATA%\gp4net\config.yaml
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            return Path.Combine(appData, AppName, ConfigFileName);
        }
        else
        {
            // Linux/macOS: ~/.gp4net/config.yaml
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            return Path.Combine(home, $".{AppName}", ConfigFileName);
        }
    }

    private static string GetSystemScriptsPath()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // Windows: %PROGRAMDATA%\gp4net\scripts
            var programData = Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData
            );
            return Path.Combine(programData, AppName, ScriptsDirectory);
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            // Linux: /usr/share/gp4net/scripts
            return Path.Combine("/usr/share", AppName, ScriptsDirectory);
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            // macOS: /usr/local/share/gp4net/scripts
            return Path.Combine("/usr/local/share", AppName, ScriptsDirectory);
        }
        else
        {
            return string.Empty;
        }
    }

    private static string GetSystemConfigPath()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // Windows: %PROGRAMDATA%\gp4net\config.yaml
            var programData = Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData
            );
            return Path.Combine(programData, AppName, ConfigFileName);
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            // Linux: /etc/gp4net/config.yaml
            return Path.Combine("/etc", AppName, ConfigFileName);
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            // macOS: /usr/local/etc/gp4net/config.yaml
            return Path.Combine("/usr/local/etc", AppName, ConfigFileName);
        }
        else
        {
            return string.Empty;
        }
    }
}