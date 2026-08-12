using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Infrastructure;

/// <summary>
/// The narrow construction adapter required by Spectre.Console.Cli.
/// Application dependencies are composed before command parsing and registered as instances.
/// </summary>
public sealed class TypeRegistrar : ITypeRegistrar
{
    private readonly Dictionary<Type, Func<object>> factories = [];

    /// <inheritdoc />
    public ITypeResolver Build() => new SpectreTypeAdapter(factories);

    /// <inheritdoc />
    public void Register(Type service, Type implementation) =>
        factories[service] = () => Create(implementation);

    /// <inheritdoc />
    public void RegisterInstance(Type service, object implementation) =>
        factories[service] = () => implementation;

    /// <inheritdoc />
    public void RegisterLazy(Type service, Func<object> factory) => factories[service] = factory;

    private object Create(Type type)
    {
        if (factories.TryGetValue(type, out var factory))
        {
            return factory();
        }

        if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(ILogger<>))
        {
            var loggerType = typeof(Logger<>).MakeGenericType(type.GetGenericArguments()[0]);
            if (
                Activator.CreateInstance(loggerType, Resolve(typeof(ILoggerFactory)))
                is object logger
            )
            {
                return logger;
            }

            throw new InvalidOperationException($"Unable to create {type.FullName}");
        }

        var constructors = type.GetConstructors()
            .OrderByDescending(candidate => candidate.GetParameters().Length)
            .ToArray();
        if (constructors.Length == 0)
        {
            throw new InvalidOperationException(
                $"No public constructor exists for {type.FullName}"
            );
        }

        var constructor = constructors[0];
        object[] arguments =
        [
            .. constructor.GetParameters().Select(parameter => Resolve(parameter.ParameterType))
        ];
        return constructor.Invoke(arguments);
    }

    private object Resolve(Type type) =>
        factories.TryGetValue(type, out var factory) ? factory() : Create(type);
}

/// <summary>
/// Resolves only the explicitly composed command graph.
/// </summary>
public sealed class SpectreTypeAdapter : ITypeResolver
{
    private readonly IReadOnlyDictionary<Type, Func<object>> factories;

    public SpectreTypeAdapter(IReadOnlyDictionary<Type, Func<object>> factories)
    {
        this.factories = new Dictionary<Type, Func<object>>(factories);
    }

    /// <inheritdoc />
    public object Resolve(Type type)
    {
        if (factories.TryGetValue(type, out var factory))
        {
            return factory();
        }

        if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(IEnumerable<>))
        {
            return Array.CreateInstance(type.GetGenericArguments()[0], 0);
        }

        throw new InvalidOperationException(
            $"No command construction was registered for {type.FullName}"
        );
    }

    /// <inheritdoc />
    public void Dispose() { }
}
