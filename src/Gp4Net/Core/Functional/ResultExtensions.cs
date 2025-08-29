using System;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;

namespace Gp4Net.Core.Functional;

/// <summary>
/// Extension methods to enable LINQ query syntax with Result monads.
/// Provides functional composition patterns for railway-oriented programming.
/// </summary>
public static class ResultExtensions
{
    /// <summary>
    /// Enables LINQ Select for Result monad (functor map).
    /// </summary>
    public static Result<T2, E> Select<T1, T2, E>(
        this Result<T1, E> result,
        Func<T1, T2> selector)
    {
        return result.Map(selector);
    }

    /// <summary>
    /// Enables LINQ SelectMany for Result monad (monadic bind).
    /// </summary>
    public static Result<T2, E> SelectMany<T1, T2, E>(
        this Result<T1, E> result,
        Func<T1, Result<T2, E>> bind)
    {
        return result.Bind(bind);
    }

    /// <summary>
    /// Enables LINQ SelectMany with projection for Result monad.
    /// Required for multiple 'from' clauses in LINQ queries.
    /// </summary>
    public static Result<T3, E> SelectMany<T1, T2, T3, E>(
        this Result<T1, E> result,
        Func<T1, Result<T2, E>> bind,
        Func<T1, T2, T3> project)
    {
        return result.Bind(t1 => bind(t1).Map(t2 => project(t1, t2)));
    }

    /// <summary>
    /// Async version of Select for Task&lt;Result&lt;T, E&gt;&gt;.
    /// </summary>
    public static async Task<Result<T2, E>> Select<T1, T2, E>(
        this Task<Result<T1, E>> resultTask,
        Func<T1, T2> selector)
    {
        Result<T1, E> result = await resultTask;
        return result.Map(selector);
    }

    /// <summary>
    /// Async version of SelectMany for Task&lt;Result&lt;T, E&gt;&gt;.
    /// </summary>
    public static async Task<Result<T2, E>> SelectMany<T1, T2, E>(
        this Task<Result<T1, E>> resultTask,
        Func<T1, Task<Result<T2, E>>> bind)
    {
        Result<T1, E> result = await resultTask;
        return result.IsSuccess
            ? await bind(result.Value)
            : Result.Failure<T2, E>(result.Error);
    }

    /// <summary>
    /// Async version of SelectMany with projection for Task&lt;Result&lt;T, E&gt;&gt;.
    /// </summary>
    public static async Task<Result<T3, E>> SelectMany<T1, T2, T3, E>(
        this Task<Result<T1, E>> resultTask,
        Func<T1, Task<Result<T2, E>>> bind,
        Func<T1, T2, T3> project)
    {
        Result<T1, E> result = await resultTask;
        if (result.IsFailure)
            return Result.Failure<T3, E>(result.Error);

        T1 t1 = result.Value;
        Result<T2, E> result2 = await bind(t1);
        return result2.Map(t2 => project(t1, t2));
    }

    /// <summary>
    /// Wraps an operation that might throw in a Result.
    /// Converts exceptions to Result failures.
    /// </summary>
    public static async Task<Result<T, E>> TryAsync<T, E>(
        Func<Task<T>> operation,
        Func<Exception, E> onError)
    {
        try
        {
            T value = await operation();
            return Result.Success<T, E>(value);
        }
        catch (Exception ex)
        {
            return Result.Failure<T, E>(onError(ex));
        }
    }

    /// <summary>
    /// Synchronous version of Try for operations that might throw.
    /// </summary>
    public static Result<T, E> Try<T, E>(
        Func<T> operation,
        Func<Exception, E> onError)
    {
        try
        {
            T value = operation();
            return Result.Success<T, E>(value);
        }
        catch (Exception ex)
        {
            return Result.Failure<T, E>(onError(ex));
        }
    }

    /// <summary>
    /// Combines multiple Results into a single Result containing a tuple.
    /// Fails fast on first error.
    /// </summary>
    public static Result<(T1, T2), E> Combine<T1, T2, E>(
        this Result<T1, E> result1,
        Result<T2, E> result2)
    {
        return result1.Bind(t1 => result2.Map(t2 => (t1, t2)));
    }

    /// <summary>
    /// Combines multiple Results into a single Result containing a tuple.
    /// Fails fast on first error.
    /// </summary>
    public static Result<(T1, T2, T3), E> Combine<T1, T2, T3, E>(
        this Result<T1, E> result1,
        Result<T2, E> result2,
        Result<T3, E> result3)
    {
        return result1.Bind(t1 =>
            result2.Bind(t2 =>
                result3.Map(t3 => (t1, t2, t3))));
    }


    /// <summary>
    /// Converts Maybe&lt;T&gt; to Result&lt;T, E&gt; with specified error for None case.
    /// </summary>
    public static Result<T, E> ToResult<T, E>(
        this Maybe<T> maybe,
        E error)
    {
        return maybe.HasValue
            ? Result.Success<T, E>(maybe.Value)
            : Result.Failure<T, E>(error);
    }

    /// <summary>
    /// Converts Result&lt;T, E&gt; to Maybe&lt;T&gt;, discarding error information.
    /// </summary>
    public static Maybe<T> ToMaybe<T, E>(this Result<T, E> result)
    {
        return result.IsSuccess
            ? Maybe<T>.From(result.Value)
            : Maybe<T>.None;
    }

    /// <summary>
    /// Converts Result&lt;T, E&gt; to UnitResult&lt;E&gt;, discarding success value.
    /// </summary>
    public static UnitResult<E> ToUnitResult<T, E>(this Result<T, E> result)
    {
        return result.IsSuccess
            ? UnitResult.Success<E>()
            : UnitResult.Failure<E>(result.Error);
    }

    /// <summary>
    /// Identity function for UnitResult - returns the same UnitResult.
    /// Useful for pipeline consistency when ToUnitResult is called on already converted results.
    /// </summary>
    public static UnitResult<E> ToUnitResult<E>(this UnitResult<E> unitResult)
    {
        return unitResult;
    }

    /// <summary>
    /// Converts UnitResult&lt;E&gt; to Result&lt;bool, E&gt; for contexts requiring Result with value.
    /// Success becomes Result.Success(true), failure preserves error.
    /// </summary>
    public static Result<bool, E> ToResult<E>(this UnitResult<E> unitResult)
    {
        return unitResult.IsSuccess
            ? Result.Success<bool, E>(true)
            : Result.Failure<bool, E>(unitResult.Error);
    }

    /// <summary>
    /// Enables binding operations on UnitResult.
    /// </summary>
    public static UnitResult<E> Bind<E>(
        this UnitResult<E> unitResult,
        Func<UnitResult<E>> bind)
    {
        return unitResult.IsSuccess
            ? bind()
            : unitResult;
    }

    /// <summary>
    /// Enables binding operations on UnitResult with ignored parameter (for pipeline compatibility with lambdas).
    /// Commonly used with patterns like .Bind(_ => SomeValidation()).
    /// </summary>
    public static UnitResult<E> Bind<E>(
        this UnitResult<E> unitResult,
        Func<object, UnitResult<E>> bind)
    {
        return unitResult.IsSuccess
            ? bind(new object())
            : unitResult;
    }



    /// <summary>
    /// Enables async binding operations on UnitResult.
    /// </summary>
    public static async Task<UnitResult<E>> Bind<E>(
        this UnitResult<E> unitResult,
        Func<Task<UnitResult<E>>> bind)
    {
        return unitResult.IsSuccess
            ? await bind()
            : unitResult;
    }

    /// <summary>
    /// Enables async binding operations on UnitResult with parameter.
    /// </summary>
    public static async Task<UnitResult<E>> Bind<T, E>(
        this Task<Result<T, E>> resultTask,
        Func<T, Task<UnitResult<E>>> bind)
    {
        Result<T, E> result = await resultTask;
        return result.IsSuccess
            ? await bind(result.Value)
            : UnitResult.Failure<E>(result.Error);
    }

}