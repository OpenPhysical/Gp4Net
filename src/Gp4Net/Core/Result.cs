using System;
using System.Threading.Tasks;

namespace Gp4Net.Core
{
    /// <summary>
    /// Represents the result of an operation that can either succeed with a value or fail with an error.
    /// This type enforces explicit error handling and eliminates null reference exceptions.
    /// </summary>
    /// <typeparam name="TValue">The type of the success value.</typeparam>
    /// <typeparam name="TError">The type of the error.</typeparam>
    public abstract record Result<TValue, TError>
    {
        /// <summary>
        /// Represents a successful result containing a value.
        /// </summary>
        public sealed record Success(TValue Value) : Result<TValue, TError>;

        /// <summary>
        /// Represents a failed result containing an error.
        /// </summary>
        public sealed record Failure(TError Error) : Result<TValue, TError>;

        /// <summary>
        /// Gets a value indicating whether this result is successful.
        /// </summary>
        public bool IsSuccess => this is Success;

        /// <summary>
        /// Gets a value indicating whether this result is a failure.
        /// </summary>
        public bool IsFailure => this is Failure;

        /// <summary>
        /// Gets the value if this is a success, otherwise throws an exception.
        /// </summary>
        public TValue Value => this switch
        {
            Success s => s.Value,
            Failure => throw new InvalidOperationException("Cannot access Value on a failed result"),
            _ => throw new InvalidOperationException("Invalid result state")
        };

        /// <summary>
        /// Gets the error if this is a failure, otherwise throws an exception.
        /// </summary>
        public TError Error => this switch
        {
            Success => throw new InvalidOperationException("Cannot access Error on a successful result"),
            Failure f => f.Error,
            _ => throw new InvalidOperationException("Invalid result state")
        };

        /// <summary>
        /// Pattern matches on the result, executing the appropriate function based on success or failure.
        /// </summary>
        /// <typeparam name="TResult">The type of the result.</typeparam>
        /// <param name="success">Function to execute if the result is successful.</param>
        /// <param name="failure">Function to execute if the result is a failure.</param>
        /// <returns>The result of the executed function.</returns>
        public TResult Match<TResult>(
            Func<TValue, TResult> success,
            Func<TError, TResult> failure) =>
            this switch
            {
                Success s => success(s.Value),
                Failure f => failure(f.Error),
                _ => throw new InvalidOperationException("Invalid result state")
            };

        /// <summary>
        /// Pattern matches on the result with async functions.
        /// </summary>
        public Task<TResult> MatchAsync<TResult>(
            Func<TValue, Task<TResult>> success,
            Func<TError, Task<TResult>> failure) =>
            this switch
            {
                Success s => success(s.Value),
                Failure f => failure(f.Error),
                _ => throw new InvalidOperationException("Invalid result state")
            };

        /// <summary>
        /// Maps the success value to a new type, preserving failures.
        /// </summary>
        public Result<TNewValue, TError> Map<TNewValue>(
            Func<TValue, TNewValue> mapper) =>
            this switch
            {
                Success s => Result<TNewValue, TError>.Ok(mapper(s.Value)),
                Failure f => Result<TNewValue, TError>.Fail(f.Error),
                _ => throw new InvalidOperationException("Invalid result state")
            };

        /// <summary>
        /// Maps the error to a new type, preserving successes.
        /// </summary>
        public Result<TValue, TNewError> MapError<TNewError>(
            Func<TError, TNewError> mapper) =>
            this switch
            {
                Success s => Result<TValue, TNewError>.Ok(s.Value),
                Failure f => Result<TValue, TNewError>.Fail(mapper(f.Error)),
                _ => throw new InvalidOperationException("Invalid result state")
            };

        /// <summary>
        /// Flat maps the success value, allowing for chaining of operations that return Results.
        /// </summary>
        public Result<TNewValue, TError> Bind<TNewValue>(
            Func<TValue, Result<TNewValue, TError>> binder) =>
            this switch
            {
                Success s => binder(s.Value),
                Failure f => Result<TNewValue, TError>.Fail(f.Error),
                _ => throw new InvalidOperationException("Invalid result state")
            };

        /// <summary>
        /// Async version of Bind.
        /// </summary>
        public Task<Result<TNewValue, TError>> BindAsync<TNewValue>(
            Func<TValue, Task<Result<TNewValue, TError>>> binder) =>
            this switch
            {
                Success s => binder(s.Value),
                Failure f => Task.FromResult(Result<TNewValue, TError>.Fail(f.Error)),
                _ => throw new InvalidOperationException("Invalid result state")
            };

        /// <summary>
        /// Provides a default value if the result is a failure.
        /// </summary>
        public TValue GetOrDefault(TValue defaultValue) =>
            this switch
            {
                Success s => s.Value,
                Failure _ => defaultValue,
                _ => throw new InvalidOperationException("Invalid result state")
            };

        /// <summary>
        /// Provides a default value from a function if the result is a failure.
        /// </summary>
        public TValue GetOrElse(Func<TError, TValue> defaultProvider) =>
            this switch
            {
                Success s => s.Value,
                Failure f => defaultProvider(f.Error),
                _ => throw new InvalidOperationException("Invalid result state")
            };

        /// <summary>
        /// Throws an exception if the result is a failure.
        /// </summary>
        public TValue GetOrThrow(Func<TError, Exception> exceptionProvider) =>
            this switch
            {
                Success s => s.Value,
                Failure f => throw exceptionProvider(f.Error),
                _ => throw new InvalidOperationException("Invalid result state")
            };

        // Factory methods for easier creation
        public static Result<TValue, TError> Ok(TValue value) =>
            new Success(value);

        public static Result<TValue, TError> Fail(TError error) =>
            new Failure(error);

        // Implicit conversions for convenience
        public static implicit operator Result<TValue, TError>(TValue value) =>
            new Success(value);

        public static implicit operator Result<TValue, TError>(TError error) =>
            new Failure(error);
    }

    /// <summary>
    /// Extension methods for working with Results.
    /// </summary>
    public static class ResultExtensions
    {
        /// <summary>
        /// Converts a nullable value to a Result.
        /// </summary>
        public static Result<T, string> ToResult<T>(this T? value, string errorMessage = "Value was null")
            where T : class =>
            value is not null
                ? Result<T, string>.Ok(value)
                : Result<T, string>.Fail(errorMessage);

        /// <summary>
        /// Tries to execute a function and returns a Result.
        /// </summary>
        public static Result<T, Exception> Try<T>(Func<T> operation)
        {
            try
            {
                return Result<T, Exception>.Ok(operation());
            }
            catch (Exception ex)
            {
                return Result<T, Exception>.Fail(ex);
            }
        }

        /// <summary>
        /// Async version of Try.
        /// </summary>
        public static async Task<Result<T, Exception>> TryAsync<T>(Func<Task<T>> operation)
        {
            try
            {
                var result = await operation().ConfigureAwait(false);
                return Result<T, Exception>.Ok(result);
            }
            catch (Exception ex)
            {
                return Result<T, Exception>.Fail(ex);
            }
        }

        /// <summary>
        /// Combines multiple results into a single result containing a tuple.
        /// </summary>
        public static Result<(T1, T2), TError> Combine<T1, T2, TError>(
            Result<T1, TError> result1,
            Result<T2, TError> result2) =>
            (result1, result2) switch
            {
                (Result<T1, TError>.Success s1, Result<T2, TError>.Success s2) =>
                    Result<(T1, T2), TError>.Ok((s1.Value, s2.Value)),
                (Result<T1, TError>.Failure f, _) =>
                    Result<(T1, T2), TError>.Fail(f.Error),
                (_, Result<T2, TError>.Failure f) =>
                    Result<(T1, T2), TError>.Fail(f.Error),
                _ => throw new InvalidOperationException("Invalid result state")
            };
    }
}