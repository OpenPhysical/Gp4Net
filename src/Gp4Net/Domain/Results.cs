using System.Collections.Immutable;

namespace Gp4Net.Domain;

/// <summary>
/// Immutable result of an installation operation.
/// </summary>
public record InstallationResult(
    byte[] PackageAid,
    ImmutableList<byte[]> InstalledApplets,
    int ExecutedCommands = 0);

/// <summary>
/// Immutable result of a deletion operation.
/// </summary>
public record DeletionResult(
    bool IsSuccessful,
    string ErrorMessage = null,
    ImmutableList<byte[]> DeletedAids = null)
{
    /// <summary>
    /// Creates a successful deletion result.
    /// </summary>
    public static DeletionResult Success(ImmutableList<byte[]> deletedAids = null) =>
        new(true, null, deletedAids);

    /// <summary>
    /// Creates a failed deletion result.
    /// </summary>
    public static DeletionResult Failure(string errorMessage) =>
        new(false, errorMessage);
}

/// <summary>
/// Immutable result of a PUT KEY operation.
/// </summary>
public record PutKeyResult(
    bool IsSuccessful,
    string ErrorMessage = null,
    ImmutableList<byte[]> KeyCheckValues = null)
{
    /// <summary>
    /// Creates a successful PUT KEY result.
    /// </summary>
    public static PutKeyResult Success(ImmutableList<byte[]> keyCheckValues = null) =>
        new(true, null, keyCheckValues);

    /// <summary>
    /// Creates a failed PUT KEY result.
    /// </summary>
    public static PutKeyResult Failure(string errorMessage) =>
        new(false, errorMessage);
}