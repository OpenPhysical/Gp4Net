using System;
using System.Threading.Tasks;

namespace Gp4Net.Core
{
    /// <summary>
    /// Represents an optional value that can either be some value or none.
    /// This type eliminates null reference exceptions and makes optional values explicit.
    /// </summary>
    /// <typeparam name="T">The type of the optional value.</typeparam>
    public abstract record Option<T>
    {
        /// <summary>
        /// Represents a value that is present.
        /// </summary>
        public sealed record Some(T SomeValue) : Option<T>;

        /// <summary>
        /// Represents an absent value.
        /// </summary>
        public sealed record None : Option<T>;

        /// <summary>
        /// Gets a value indicating whether this option has a value.
        /// </summary>
        public bool HasValue => this is Some;

        /// <summary>
        /// Gets a value indicating whether this option is empty.
        /// </summary>
        public bool IsEmpty => this is None;

        /// <summary>
        /// Safely tries to get the value if present.
        /// </summary>
        public bool TryGetValue(out T value)
        {
            switch (this)
            {
                case Some s:
                    value = s.SomeValue;
                    return true;
                case None:
                    value = default!;
                    return false;
                default:
                    value = default!;
                    return false;
            }
        }

        /// <summary>
        /// Pattern matches on the option, executing the appropriate function.
        /// </summary>
        /// <typeparam name="TResult">The type of the result.</typeparam>
        /// <param name="some">Function to execute if the option has a value.</param>
        /// <param name="none">Function to execute if the option is empty.</param>
        /// <returns>The result of the executed function.</returns>
        public TResult Match<TResult>(
            Func<T, TResult> some,
            Func<TResult> none) =>
            this switch
            {
                Some s => some(s.SomeValue),
                None => none(),
                _ => none()
            };

        /// <summary>
        /// Async pattern matching on the option.
        /// </summary>
        public Task<TResult> MatchAsync<TResult>(
            Func<T, Task<TResult>> some,
            Func<Task<TResult>> none) =>
            this switch
            {
                Some s => some(s.SomeValue),
                None => none(),
                _ => none()
            };

        /// <summary>
        /// Maps the value to a new type if present, preserving None.
        /// </summary>
        public Option<TResult> Map<TResult>(Func<T, TResult> mapper) =>
            this switch
            {
                Some s => Option<TResult>.Of(mapper(s.SomeValue)),
                None => Option<TResult>.Empty,
                _ => Option<TResult>.Empty
            };

        /// <summary>
        /// Flat maps the value, allowing for chaining of operations that return Options.
        /// </summary>
        public Option<TResult> Bind<TResult>(Func<T, Option<TResult>> binder) =>
            this switch
            {
                Some s => binder(s.SomeValue),
                None => Option<TResult>.Empty,
                _ => Option<TResult>.Empty
            };

        /// <summary>
        /// Filters the option based on a predicate.
        /// </summary>
        public Option<T> Filter(Func<T, bool> predicate) =>
            this switch
            {
                Some s when predicate(s.SomeValue) => this,
                Some _ => Option<T>.Empty,
                None => Option<T>.Empty,
                _ => Option<T>.Empty
            };

        /// <summary>
        /// Provides a default value if the option is empty.
        /// </summary>
        public T GetOrDefault(T defaultValue) =>
            this switch
            {
                Some s => s.SomeValue,
                None => defaultValue,
                _ => defaultValue
            };

        /// <summary>
        /// Provides a default value from a function if the option is empty.
        /// </summary>
        public T GetOrElse(Func<T> defaultProvider) =>
            this switch
            {
                Some s => s.SomeValue,
                None => defaultProvider(),
                _ => defaultProvider()
            };

        /// <summary>
        /// Converts the option to a Result with a specified error for None.
        /// </summary>
        public Result<T, TError> ToResult<TError>(TError error) =>
            this switch
            {
                Some s => Result<T, TError>.Ok(s.SomeValue),
                None => Result<T, TError>.Fail(error),
                _ => Result<T, TError>.Fail(error)
            };

        /// <summary>
        /// Converts the option to a Result with a specified error function for None.
        /// </summary>
        public Result<T, TError> ToResult<TError>(Func<TError> errorProvider) =>
            this switch
            {
                Some s => Result<T, TError>.Ok(s.SomeValue),
                None => Result<T, TError>.Fail(errorProvider()),
                _ => Result<T, TError>.Fail(errorProvider())
            };

        // Factory methods for easier creation
        public static Option<T> Of(T value) =>
            value is not null ? new Some(value) : new None();

        public static Option<T> Empty => new None();

        // Implicit conversions for convenience
        public static implicit operator Option<T>(T value) =>
            Of(value);
    }

    /// <summary>
    /// Extension methods for working with Options.
    /// </summary>
    public static class OptionExtensions
    {
        /// <summary>
        /// Converts a nullable value to an Option.
        /// </summary>
        public static Option<T> ToOption<T>(this T? value) where T : class =>
            value is not null ? Option<T>.Of(value) : Option<T>.Empty;

        /// <summary>
        /// Converts a nullable value type to an Option.
        /// </summary>
        public static Option<T> ToOption<T>(this T? value) where T : struct =>
            value.HasValue ? Option<T>.Of(value.Value) : Option<T>.Empty;

        /// <summary>
        /// Combines two options into a tuple option.
        /// </summary>
        public static Option<(T1, T2)> Combine<T1, T2>(
            Option<T1> option1,
            Option<T2> option2) =>
            (option1, option2) switch
            {
                (Option<T1>.Some s1, Option<T2>.Some s2) =>
                    Option<(T1, T2)>.Of((s1.SomeValue, s2.SomeValue)),
                _ => Option<(T1, T2)>.Empty
            };

        /// <summary>
        /// Converts a Result to an Option, discarding the error.
        /// </summary>
        public static Option<T> ToOption<T, TError>(this Result<T, TError> result) =>
            result switch
            {
                Result<T, TError>.Success s => Option<T>.Of(s.SuccessValue),
                Result<T, TError>.Failure _ => Option<T>.Empty,
                _ => Option<T>.Empty
            };

        /// <summary>
        /// Flattens a nested Option.
        /// </summary>
        public static Option<T> Flatten<T>(this Option<Option<T>> option) =>
            option switch
            {
                Option<Option<T>>.Some s => s.SomeValue,
                Option<Option<T>>.None => Option<T>.Empty,
                _ => Option<T>.Empty
            };
    }
}