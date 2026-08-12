using System.IO;
using NUnit.Framework;

namespace Gp4Net.CardEmulator.Tests.TestHelpers;

internal static class RepositoryPathLocator
{
    public static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (
            directory is not null && !File.Exists(Path.Combine(directory.FullName, "Gp4Net.sln"))
        )
        {
            directory = directory.Parent;
        }

        if (directory is null)
        {
            throw new InvalidDataException(
                "Unable to locate repository root (Gp4Net.sln not found)."
            );
        }

        return directory.FullName;
    }
}
