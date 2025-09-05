using System;
using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using NUnit.Framework;

namespace Gp4Net.Tests.Infrastructure;

/// <summary>
/// Extension methods for functional testing.
/// Provides missing Maybe and Result extension methods needed by tests.
/// </summary>
public static class TestExtensions
{
    /// <summary>
    /// Converts a value to Maybe, treating null as None.
    /// </summary>
    /// <typeparam name="T">The type to convert.</typeparam>
    /// <param name="value">The value to convert.</param>
    /// <returns>Maybe with the value, or None if null.</returns>
    public static Maybe<T> ToMaybe<T>(this T value) where T : class
    {
        return Maybe<T>.From(value);
    }
    /// <summary>
    /// Executes an action if the Maybe has a value, then returns the original Maybe.
    /// This method provides side-effect execution without breaking the functional chain.
    /// </summary>
    /// <typeparam name="T">The type contained in the Maybe.</typeparam>
    /// <param name="maybe">The Maybe to operate on.</param>
    /// <param name="action">The action to execute if the Maybe has a value.</param>
    /// <returns>The original Maybe unchanged.</returns>
    public static Maybe<T> Do<T>(this Maybe<T> maybe, Action<T> action)
    {
        return maybe.Match(
            value =>
            {
                action(value);
                return maybe;
            },
            () => maybe
        );
    }

    /// <summary>
    /// Executes an action if the Maybe has a value, ignoring the value.
    /// Useful for side effects that don't need the actual value.
    /// </summary>
    /// <typeparam name="T">The type contained in the Maybe.</typeparam>
    /// <param name="maybe">The Maybe to operate on.</param>
    /// <param name="action">The action to execute if the Maybe has a value.</param>
    /// <returns>The original Maybe unchanged.</returns>
    public static Maybe<T> Do<T>(this Maybe<T> maybe, Action action)
    {
        return maybe.Match(
            value =>
            {
                action();
                return maybe;
            },
            () => maybe
        );
    }
}

/// <summary>
/// Extension methods for functional types to provide Should() assertions.
/// These complement the functional patterns with Result and Maybe assertions.
/// </summary>
public static class FunctionalAssertionExtensions
{
    /// <summary>
    /// Provides assertion capabilities for Result types using functional patterns.
    /// </summary>
    /// <typeparam name="T">The success type of the Result.</typeparam>
    /// <typeparam name="TError">The error type of the Result.</typeparam>
    /// <param name="result">The Result to assert on.</param>
    /// <returns>ResultAssertions for chaining.</returns>
    public static ResultAssertions<T, TError> Should<T, TError>(this Result<T, TError> result)
    {
        return new ResultAssertions<T, TError>(result);
    }

    /// <summary>
    /// Provides assertion capabilities for Result types using functional patterns.
    /// </summary>
    /// <typeparam name="TError">The error type of the Result.</typeparam>
    /// <param name="result">The Result to assert on.</param>
    /// <returns>UnitResultAssertions for chaining.</returns>
    public static UnitResultAssertions<TError> Should<TError>(this Result<TError> result)
    {
        return new UnitResultAssertions<TError>(result);
    }

    /// <summary>
    /// Provides assertion capabilities for Maybe types using functional patterns.
    /// </summary>
    /// <typeparam name="T">The type contained in the Maybe.</typeparam>
    /// <param name="maybe">The Maybe to assert on.</param>
    /// <returns>MaybeAssertions for chaining.</returns>
    public static MaybeAssertions<T> Should<T>(this Maybe<T> maybe)
    {
        return new MaybeAssertions<T>(maybe);
    }
}



/// <summary>
/// Functional assertions for Result types with success value.
/// </summary>
/// <typeparam name="T">The success type.</typeparam>
/// <typeparam name="TError">The error type.</typeparam>
public sealed class ResultAssertions<T, TError>
{
    private readonly Result<T, TError> _result;

    internal ResultAssertions(Result<T, TError> result)
    {
        _result = result;
    }

    /// <summary>
    /// Asserts that the Result is successful.
    /// </summary>
    /// <param name="because">Reason for the assertion.</param>
    /// <returns>This instance for method chaining.</returns>
    public ResultAssertions<T, TError> BeSuccess(string because = "")
    {
        Assert.That(_result.IsSuccess, Is.True, because);
        return this;
    }

    /// <summary>
    /// Asserts that the Result is successful with a specific value.
    /// </summary>
    /// <param name="expectedValue">The expected success value.</param>
    /// <param name="because">Reason for the assertion.</param>
    /// <returns>This instance for method chaining.</returns>
    public ResultAssertions<T, TError> BeSuccessWith(T expectedValue, string because = "")
    {
        _result.Match(
            value => Assert.That(value, Is.EqualTo(expectedValue), because),
            error => Assert.Fail($"Expected success with value {expectedValue}, but got failure: {error}. {because}")
        );
        return this;
    }

    /// <summary>
    /// Asserts that the Result is a failure.
    /// </summary>
    /// <param name="because">Reason for the assertion.</param>
    /// <returns>This instance for method chaining.</returns>
    public ResultAssertions<T, TError> BeFailure(string because = "")
    {
        Assert.That(_result.IsFailure, Is.True, because);
        return this;
    }

    /// <summary>
    /// Asserts that the Result is a failure with a specific error.
    /// </summary>
    /// <param name="expectedError">The expected error value.</param>
    /// <param name="because">Reason for the assertion.</param>
    /// <returns>This instance for method chaining.</returns>
    public ResultAssertions<T, TError> BeFailureWith(TError expectedError, string because = "")
    {
        _result.Match(
            value => Assert.Fail($"Expected failure with error {expectedError}, but got success: {value}. {because}"),
            error => Assert.That(error, Is.EqualTo(expectedError), because)
        );
        return this;
    }
}

/// <summary>
/// Functional assertions for Unit Result types.
/// </summary>
/// <typeparam name="TError">The error type.</typeparam>
public sealed class UnitResultAssertions<TError>
{
    private readonly Result<TError> _result;

    internal UnitResultAssertions(Result<TError> result)
    {
        _result = result;
    }

    /// <summary>
    /// Asserts that the Result is successful.
    /// </summary>
    /// <param name="because">Reason for the assertion.</param>
    /// <returns>This instance for method chaining.</returns>
    public UnitResultAssertions<TError> BeSuccess(string because = "")
    {
        Assert.That(_result.IsSuccess, Is.True, because);
        return this;
    }

    /// <summary>
    /// Asserts that the Result is a failure.
    /// </summary>
    /// <param name="because">Reason for the assertion.</param>
    /// <returns>This instance for method chaining.</returns>
    public UnitResultAssertions<TError> BeFailure(string because = "")
    {
        Assert.That(_result.IsFailure, Is.True, because);
        return this;
    }

    /// <summary>
    /// Asserts that the Result is a failure with a specific error.
    /// </summary>
    /// <param name="expectedError">The expected error value.</param>
    /// <param name="because">Reason for the assertion.</param>
    /// <returns>This instance for method chaining.</returns>
    public UnitResultAssertions<TError> BeFailureWith(TError expectedError, string because = "")
    {
        _result.Match(
            () => { Assert.Fail($"Expected failure with error {expectedError}, but got success. {because}"); },
            error => { Assert.That(error, Is.EqualTo(expectedError), because); }
        );
        return this;
    }
}

/// <summary>
/// Functional assertions for Maybe types.
/// </summary>
/// <typeparam name="T">The type contained in the Maybe.</typeparam>
public sealed class MaybeAssertions<T>
{
    private readonly Maybe<T> _maybe;

    internal MaybeAssertions(Maybe<T> maybe)
    {
        _maybe = maybe;
    }

    /// <summary>
    /// Asserts that the Maybe has a value.
    /// </summary>
    /// <param name="because">Reason for the assertion.</param>
    /// <returns>This instance for method chaining.</returns>
    public MaybeAssertions<T> HaveValue(string because = "")
    {
        Assert.That(_maybe.HasValue, Is.True, because);
        return this;
    }

    /// <summary>
    /// Asserts that the Maybe has a specific value.
    /// </summary>
    /// <param name="expectedValue">The expected value.</param>
    /// <param name="because">Reason for the assertion.</param>
    /// <returns>This instance for method chaining.</returns>
    public MaybeAssertions<T> HaveValue(T expectedValue, string because = "")
    {
        _maybe.Match(
            value => Assert.That(value, Is.EqualTo(expectedValue), because),
            () => Assert.Fail($"Expected Maybe to have value {expectedValue}, but it was None. {because}")
        );
        return this;
    }

    /// <summary>
    /// Asserts that the Maybe has no value.
    /// </summary>
    /// <param name="because">Reason for the assertion.</param>
    /// <returns>This instance for method chaining.</returns>
    public MaybeAssertions<T> HaveNoValue(string because = "")
    {
        Assert.That(_maybe.HasNoValue, Is.True, because);
        return this;
    }

    /// <summary>
    /// Asserts that the Maybe value is not null.
    /// </summary>
    /// <param name="because">Reason for the assertion.</param>
    /// <returns>This instance for method chaining.</returns>
    public MaybeAssertions<T> NotBeNull(string because = "")
    {
        _maybe.Match(
            value => Assert.That(value, Is.Not.Null, because),
            () => Assert.Fail($"Expected Maybe to have a non-null value, but it was None. {because}")
        );
        return this;
    }

    /// <summary>
    /// Provides access to continuation assertions (for .And syntax).
    /// </summary>
    public MaybeAssertions<T> And => this;

    /// <summary>
    /// Provides access to the wrapped value for further assertions.
    /// </summary>
    public MaybeValueAssertions<T> TheValue => new MaybeValueAssertions<T>(_maybe);

    /// <summary>
    /// Asserts that the Maybe contains a specific value.
    /// </summary>
    /// <param name="expectedValue">The expected value.</param>
    /// <param name="because">Reason for the assertion.</param>
    /// <returns>This instance for method chaining.</returns>
    public MaybeAssertions<T> Be(T expectedValue, string because = "")
    {
        _maybe.Match(
            value => Assert.That(value, Is.EqualTo(expectedValue), because),
            () => Assert.Fail($"Expected Maybe to contain {expectedValue}, but it was None. {because}")
        );
        return this;
    }
}

/// <summary>
/// Assertions for primitive types using NUnit patterns.
/// </summary>
/// <typeparam name="T">The type of the value.</typeparam>
public sealed class PrimitiveAssertions<T>
{
    private readonly T _value;

    internal PrimitiveAssertions(T value)
    {
        _value = value;
    }

    /// <summary>
    /// Asserts that the value equals the expected value.
    /// </summary>
    /// <param name="expected">The expected value.</param>
    /// <param name="because">Reason for the assertion.</param>
    /// <returns>This instance for method chaining.</returns>
    public PrimitiveAssertions<T> Be(T expected, string because = "")
    {
        Assert.That(_value, Is.EqualTo(expected), because);
        return this;
    }

    /// <summary>
    /// Asserts that the value is true (for boolean values).
    /// </summary>
    /// <param name="because">Reason for the assertion.</param>
    /// <returns>This instance for method chaining.</returns>
    public PrimitiveAssertions<T> BeTrue(string because = "")
    {
        Assert.That(_value, Is.True, because);
        return this;
    }

    /// <summary>
    /// Asserts that the value is false (for boolean values).
    /// </summary>
    /// <param name="because">Reason for the assertion.</param>
    /// <returns>This instance for method chaining.</returns>
    public PrimitiveAssertions<T> BeFalse(string because = "")
    {
        Assert.That(_value, Is.False, because);
        return this;
    }

    /// <summary>
    /// Asserts that the value is not equal to the specified value.
    /// </summary>
    /// <param name="unexpected">The value that should not be equal.</param>
    /// <param name="because">Reason for the assertion.</param>
    /// <returns>This instance for method chaining.</returns>
    public PrimitiveAssertions<T> NotBe(T unexpected, string because = "")
    {
        Assert.That(_value, Is.Not.EqualTo(unexpected), because);
        return this;
    }

    /// <summary>
    /// Asserts that the value is equivalent to the expected value.
    /// </summary>
    /// <param name="expected">The expected value.</param>
    /// <param name="because">Reason for the assertion.</param>
    /// <returns>This instance for method chaining.</returns>
    public PrimitiveAssertions<T> BeEquivalentTo(T expected, string because = "")
    {
        Assert.That(_value, Is.EqualTo(expected), because);
        return this;
    }
}

/// <summary>
/// Assertions for Maybe values to support fluent .And.TheValue syntax.
/// </summary>
/// <typeparam name="T">The type contained in the Maybe.</typeparam>
public sealed class MaybeValueAssertions<T>
{
    private readonly Maybe<T> _maybe;

    internal MaybeValueAssertions(Maybe<T> maybe)
    {
        _maybe = maybe;
    }

    /// <summary>
    /// Provides Should() access to the Maybe's value.
    /// </summary>
    public PrimitiveAssertions<T> Should()
    {
        return _maybe.Match(
            value => new PrimitiveAssertions<T>(value),
            () => 
            {
                Assert.Fail("Expected Maybe to have a value for assertion, but it was None");
                return new PrimitiveAssertions<T>(default(T)!); // This will never be reached
            }
        );
    }
}

/// <summary>
/// Assertions for object types to provide BeNull/NotBeNull functionality.
/// </summary>
/// <typeparam name="T">The type of the object.</typeparam>
public sealed class ObjectAssertions<T>
{
    private readonly T _value;

    internal ObjectAssertions(T value)
    {
        _value = value;
    }

    /// <summary>
    /// Asserts that the object is null.
    /// </summary>
    /// <param name="because">Reason for the assertion.</param>
    /// <returns>This instance for method chaining.</returns>
    public ObjectAssertions<T> BeNull(string because = "")
    {
        Assert.That(_value, Is.Null, because);
        return this;
    }

    /// <summary>
    /// Asserts that the object is not null.
    /// </summary>
    /// <param name="because">Reason for the assertion.</param>
    /// <returns>This instance for method chaining.</returns>
    public ObjectAssertions<T> NotBeNull(string because = "")
    {
        Assert.That(_value, Is.Not.Null, because);
        return this;
    }

    /// <summary>
    /// Asserts that the object equals the expected value.
    /// </summary>
    /// <param name="expected">The expected value.</param>
    /// <param name="because">Reason for the assertion.</param>
    /// <returns>This instance for method chaining.</returns>
    public ObjectAssertions<T> Be(T expected, string because = "")
    {
        Assert.That(_value, Is.EqualTo(expected), because);
        return this;
    }
}

