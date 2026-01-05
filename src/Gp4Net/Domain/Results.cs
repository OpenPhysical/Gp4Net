using System.Collections.Immutable;
using CSharpFunctionalExtensions;

namespace Gp4Net.Domain;

public static class Results
{
    /// <summary>
    /// Immutable result of an installation operation.
    /// </summary>
    public sealed record InstallationResult
    {
        public InstallationResult(
            byte[] packageAid,
            ImmutableList<byte[]>? installedApplets,
            int executedCommands = 0
        )
        {
            PackageAid = packageAid;
            InstalledApplets = installedApplets ?? ImmutableList<byte[]>.Empty;
            ExecutedCommands = executedCommands;
        }

        public byte[] PackageAid { get; }

        public ImmutableList<byte[]> InstalledApplets { get; }

        public int ExecutedCommands { get; }
    }

    /// <summary>
    /// Immutable result of a deletion operation.
    /// </summary>
    public sealed record DeletionResult
    {
        private DeletionResult(
            bool isSuccessful,
            Maybe<string> errorMessage,
            ImmutableList<byte[]> deletedAids
        )
        {
            IsSuccessful = isSuccessful;
            ErrorMessage = errorMessage;
            DeletedAids = deletedAids;
        }

        public bool IsSuccessful { get; }

        public Maybe<string> ErrorMessage { get; }

        public ImmutableList<byte[]> DeletedAids { get; }

        /// <summary>
        /// Creates a successful deletion result.
        /// </summary>
        public static DeletionResult Success(ImmutableList<byte[]>? deletedAids = null)
        {
            return new(true, Maybe<string>.None, deletedAids ?? ImmutableList<byte[]>.Empty);
        }

        /// <summary>
        /// Creates a failed deletion result.
        /// </summary>
        public static DeletionResult Failure(string errorMessage)
        {
            return new(false, Maybe<string>.From(errorMessage), ImmutableList<byte[]>.Empty);
        }
    }

    /// <summary>
    /// Immutable result of a PUT KEY operation.
    /// </summary>
    public sealed record PutKeyResult
    {
        private PutKeyResult(
            bool isSuccessful,
            Maybe<string> errorMessage,
            ImmutableList<byte[]> keyCheckValues
        )
        {
            IsSuccessful = isSuccessful;
            ErrorMessage = errorMessage;
            KeyCheckValues = keyCheckValues;
        }

        public bool IsSuccessful { get; }

        public Maybe<string> ErrorMessage { get; }

        public ImmutableList<byte[]> KeyCheckValues { get; }

        /// <summary>
        /// Creates a successful PUT KEY result.
        /// </summary>
        public static PutKeyResult Success(ImmutableList<byte[]>? keyCheckValues = null)
        {
            return new(true, Maybe<string>.None, keyCheckValues ?? ImmutableList<byte[]>.Empty);
        }

        /// <summary>
        /// Creates a failed PUT KEY result.
        /// </summary>
        public static PutKeyResult Failure(string errorMessage)
        {
            return new(false, Maybe<string>.From(errorMessage), ImmutableList<byte[]>.Empty);
        }
    }
}
