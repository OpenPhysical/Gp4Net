using System;
using System.IO;

namespace Gp4Net.Tests.TestHelpers;

/// <summary>
/// Test context utilities for finding project directories and test data.
/// </summary>
public static class TestContextHelper
{
    /// <summary>
    /// Gets the project root directory by navigating up from the test assembly.
    /// </summary>
    public static string GetProjectRootDirectory()
    {
        // Navigate up from test assembly to find project root
        string currentDir = Directory.GetCurrentDirectory();
        DirectoryInfo? dir = new DirectoryInfo(currentDir);

        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "Gp4Net.sln")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new InvalidOperationException("Could not find project root directory with Gp4Net.sln");
    }

    /// <summary>
    /// Gets the test data directory within the project.
    /// </summary>
    public static string GetTestDataDirectory()
    {
        return Path.Combine(GetProjectRootDirectory(), "tests");
    }
}