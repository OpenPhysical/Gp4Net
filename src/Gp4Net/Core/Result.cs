using System;
using System.Threading.Tasks;

namespace Gp4Net.Core
{
    /// <summary>
    /// Represents a unit value - the functional programming equivalent of void.
    /// </summary>
    public sealed record Unit
    {
        /// <summary>
        /// The singleton instance of Unit.
        /// </summary>
        public static readonly Unit Value = new Unit();
        
        private Unit() { }
    }
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
        public sealed record Success(TValue SuccessValue) : Result<TValue, TError>;

        /// <summary>
        /// Represents a failed result containing an error.
        /// </summary>
        public sealed record Failure(TError FailureError) : Result<TValue, TError>;

        /// <summary>
        /// Gets a value indicating whether this result is successful.
        /// </summary>
        public bool IsSuccess => this is Success;

        /// <summary>
        /// Gets a value indicating whether this result is a failure.
        /// </summary>
        public bool IsFailure => this is Failure;

        /// <summary>
        /// Attempts to get the value if this is a success.
        /// Use Match() or TryGetValue() for safe access.
        /// </summary>
        [Obsolete("Use Match() or TryGetValue() for safe access to values")]
        public TValue Value => this switch
        {
            Success s => s.SuccessValue,
            Failure => default!,
            _ => default!
        };

        /// <summary>
        /// Attempts to get the error if this is a failure.
        /// Use Match() or TryGetError() for safe access.
        /// </summary>
        [Obsolete("Use Match() or TryGetError() for safe access to errors")]
        public TError Error => this switch
        {
            Success => default!,
            Failure f => f.FailureError,
            _ => default!
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
                Success s => success(s.SuccessValue),
                Failure f => failure(f.FailureError),
                _ => default!
            };

        /// <summary>
        /// Pattern matches on the result with async functions.
        /// </summary>
        public Task<TResult> MatchAsync<TResult>(
            Func<TValue, Task<TResult>> success,
            Func<TError, Task<TResult>> failure) =>
            this switch
            {
                Success s => success(s.SuccessValue),
                Failure f => failure(f.FailureError),
                _ => Task.FromResult(default(TResult)!)
            };

        /// <summary>
        /// Maps the success value to a new type, preserving failures.
        /// </summary>
        public Result<TNewValue, TError> Map<TNewValue>(
            Func<TValue, TNewValue> mapper) =>
            this switch
            {
                Success s => Result<TNewValue, TError>.Ok(mapper(s.SuccessValue)),
                Failure f => Result<TNewValue, TError>.Fail(f.FailureError),
                _ => Result<TNewValue, TError>.Fail(default(TError)!)
            };

        /// <summary>
        /// Maps the error to a new type, preserving successes.
        /// </summary>
        public Result<TValue, TNewError> MapError<TNewError>(
            Func<TError, TNewError> mapper) =>
            this switch
            {
                Success s => Result<TValue, TNewError>.Ok(s.SuccessValue),
                Failure f => Result<TValue, TNewError>.Fail(mapper(f.FailureError)),
                _ => Result<TValue, TNewError>.Fail(default(TNewError)!)
            };

        /// <summary>
        /// Flat maps the success value, allowing for chaining of operations that return Results.
        /// </summary>
        public Result<TNewValue, TError> Bind<TNewValue>(
            Func<TValue, Result<TNewValue, TError>> binder) =>
            this switch
            {
                Success s => binder(s.SuccessValue),
                Failure f => Result<TNewValue, TError>.Fail(f.FailureError),
                _ => Result<TNewValue, TError>.Fail(default(TError)!)
            };

        /// <summary>
        /// Async version of Bind.
        /// </summary>
        public Task<Result<TNewValue, TError>> BindAsync<TNewValue>(
            Func<TValue, Task<Result<TNewValue, TError>>> binder) =>
            this switch
            {
                Success s => binder(s.SuccessValue),
                Failure f => Task.FromResult(Result<TNewValue, TError>.Fail(f.FailureError)),
                _ => Task.FromResult(Result<TNewValue, TError>.Fail(default(TError)!))
            };

        /// <summary>
        /// Provides a default value if the result is a failure.
        /// </summary>
        public TValue GetOrDefault(TValue defaultValue) =>
            this switch
            {
                Success s => s.SuccessValue,
                Failure _ => defaultValue,
                _ => defaultValue
            };

        /// <summary>
        /// Provides a default value from a function if the result is a failure.
        /// </summary>
        public TValue GetOrElse(Func<TError, TValue> defaultProvider) =>
            this switch
            {
                Success s => s.SuccessValue,
                Failure f => defaultProvider(f.FailureError),
                _ => defaultProvider(default(TError)!)
            };

        /// <summary>
        /// Throws an exception if the result is a failure.
        /// </summary>
        public TValue GetOrThrow(Func<TError, Exception> exceptionProvider) =>
            this switch
            {
                Success s => s.SuccessValue,
                Failure f => throw exceptionProvider(f.FailureError),
                _ => throw new InvalidOperationException("Invalid result state")
            };

        /// <summary>
        /// Safely tries to get the value if this is a success.
        /// </summary>
        public bool TryGetValue(out TValue value)
        {
            switch (this)
            {
                case Success s:
                    value = s.SuccessValue;
                    return true;
                case Failure _:
                    value = default!;
                    return false;
                default:
                    value = default!;
                    return false;
            }
        }

        /// <summary>
        /// Safely tries to get the error if this is a failure.
        /// </summary>
        public bool TryGetError(out TError error)
        {
            switch (this)
            {
                case Success _:
                    error = default!;
                    return false;
                case Failure f:
                    error = f.FailureError;
                    return true;
                default:
                    error = default!;
                    return false;
            }
        }

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
        /// Converts an Option to a Result with a specified error for None.
        /// </summary>
        public static Result<T, TError> ToResult<T, TError>(this Option<T> option, TError error) =>
            option switch
            {
                Option<T>.Some s => Result<T, TError>.Ok(s.SomeValue),
                Option<T>.None => Result<T, TError>.Fail(error),
                _ => Result<T, TError>.Fail(error)
            };

        /// <summary>
        /// Converts an Option to a Result with a specified error function for None.
        /// </summary>
        public static Result<T, TError> ToResult<T, TError>(this Option<T> option, Func<TError> errorProvider) =>
            option switch
            {
                Option<T>.Some s => Result<T, TError>.Ok(s.SomeValue),
                Option<T>.None => Result<T, TError>.Fail(errorProvider()),
                _ => Result<T, TError>.Fail(errorProvider())
            };

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
                    Result<(T1, T2), TError>.Ok((s1.SuccessValue, s2.SuccessValue)),
                (Result<T1, TError>.Failure f, _) =>
                    Result<(T1, T2), TError>.Fail(f.FailureError),
                (_, Result<T2, TError>.Failure f) =>
                    Result<(T1, T2), TError>.Fail(f.FailureError),
                _ => Result<(T1, T2), TError>.Fail(default(TError)!)
            };
    }
}