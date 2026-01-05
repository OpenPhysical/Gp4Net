using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;

namespace Gp4Net.Core.Functional;

/// <summary>
/// Functional combinators for common patterns in card operations.
/// Provides pure functional alternatives to loops and imperative patterns.
/// </summary>
public static class FunctionalCombinators
{
    /// <summary>
    /// Tries multiple operations sequentially until one succeeds.
    /// Returns the first successful result or the last failure.
    /// </summary>
    public static async Task<Result<T, E>> FirstSuccess<T, E>(
        this IEnumerable<Func<Task<Result<T, E>>>> operations
    )
    {
        List<Func<Task<Result<T, E>>>> operationsList = [.. operations];
        if (!operationsList.Any())
            return Result.Failure<T, E>(
                (E)(object)SmartCardError.InvalidArgument("No operations provided")
            );

        var lastFailure = Maybe<Result<T, E>>.None;

        foreach (var operation in operationsList)
        {
            var result = await operation();
            if (result.IsSuccess)
                return result;
            lastFailure = Maybe<Result<T, E>>.From(result);
        }

        return lastFailure.GetValueOrDefault(
            Result.Failure<T, E>(
                (E)(object)SmartCardError.InvalidArgument("No operations executed")
            )
        );
    }

    /// <summary>
    /// Tries multiple operations in parallel and returns the first successful result.
    /// </summary>
    public static async Task<Result<T, E>> FirstSuccessParallel<T, E>(
        this IEnumerable<Func<Task<Result<T, E>>>> operations
    )
    {
        List<Task<Result<T, E>>> tasks = [.. operations.Select(op => op())];
        if (!tasks.Any())
            return Result.Failure<T, E>(
                (E)(object)SmartCardError.InvalidArgument("No operations provided")
            );

        var results = await Task.WhenAll(tasks);
        var successResult = results.FirstOrDefault(r => r.IsSuccess);
        return successResult.IsSuccess ? successResult : results.Last();
    }

    /// <summary>
    /// Maps a function over a sequence, collecting successful results.
    /// Continues even if some operations fail.
    /// </summary>
    public static async Task<ImmutableList<T>> MapSuccessful<S, T, E>(
        this IEnumerable<S> source,
        Func<S, Task<Result<T, E>>> operation
    )
    {
        var results = await Task.WhenAll(source.Select(operation));
        return [.. results.Where(r => r.IsSuccess).Select(r => r.Value)];
    }

    /// <summary>
    /// Maps a function over a sequence, failing fast on first error.
    /// </summary>
    public static async Task<Result<ImmutableList<T>, E>> TraverseResult<S, T, E>(
        this IEnumerable<S> source,
        Func<S, Task<Result<T, E>>> operation
    )
    {
        var results = ImmutableList.CreateBuilder<T>();

        foreach (var item in source)
        {
            var result = await operation(item);
            if (result.IsFailure)
                return Result.Failure<ImmutableList<T>, E>(result.Error);
            results.Add(result.Value);
        }

        return Result.Success<ImmutableList<T>, E>(results.ToImmutable());
    }

    /// <summary>
    /// Sequences a list of Results into a Result of a list.
    /// Fails fast on first error.
    /// </summary>
    public static Result<ImmutableList<T>, E> SequenceResult<T, E>(
        this IEnumerable<Result<T, E>> results
    )
    {
        var values = ImmutableList.CreateBuilder<T>();

        foreach (var result in results)
        {
            if (result.IsFailure)
                return Result.Failure<ImmutableList<T>, E>(result.Error);
            values.Add(result.Value);
        }

        return Result.Success<ImmutableList<T>, E>(values.ToImmutable());
    }

    /// <summary>
    /// Folds a sequence of values into a single result using an accumulator function.
    /// </summary>
    public static async Task<Result<TAcc, E>> FoldResult<T, TAcc, E>(
        this IEnumerable<T> source,
        TAcc initial,
        Func<TAcc, T, Task<Result<TAcc, E>>> folder
    )
    {
        var accumulator = initial;

        foreach (var item in source)
        {
            var result = await folder(accumulator, item);
            if (result.IsFailure)
                return result;
            accumulator = result.Value;
        }

        return Result.Success<TAcc, E>(accumulator);
    }

    /// <summary>
    /// Maps a value in a task.
    /// </summary>
    private static async Task<T2> Map<T1, T2>(this Task<T1> task, Func<T1, T2> mapper)
    {
        var result = await task;
        return mapper(result);
    }

    /// <summary>
    /// Partitions a sequence of Results into successes and failures.
    /// </summary>
    public static (ImmutableList<T> Successes, ImmutableList<E> Failures) Partition<T, E>(
        this IEnumerable<Result<T, E>> results
    )
    {
        var successes = ImmutableList.CreateBuilder<T>();
        var failures = ImmutableList.CreateBuilder<E>();

        foreach (var result in results)
        {
            if (result.IsSuccess)
                successes.Add(result.Value);
            else
                failures.Add(result.Error);
        }

        return (successes.ToImmutable(), failures.ToImmutable());
    }

    /// <summary>
    /// Unfolds a value into a sequence by repeatedly applying a function.
    /// </summary>
    public static IEnumerable<T> Unfold<T, TState>(
        TState initial,
        Func<TState, Maybe<(T value, TState next)>> generator
    )
    {
        var state = initial;

        while (true)
        {
            var result = generator(state);
            if (!result.HasValue)
                yield break;

            (var value, var next) = result.Value;
            yield return value;
            state = next;
        }
    }

    /// <summary>
    /// Creates a sequence by repeatedly applying a function until it returns None.
    /// </summary>
    public static async Task<ImmutableList<T>> UnfoldAsync<T, TState>(
        TState initial,
        Func<TState, Task<Maybe<(T value, TState next)>>> generator
    )
    {
        var results = ImmutableList.CreateBuilder<T>();
        var state = initial;

        while (true)
        {
            var result = await generator(state);
            if (!result.HasValue)
                break;

            (var value, var next) = result.Value;
            results.Add(value);
            state = next;
        }

        return results.ToImmutable();
    }
}
