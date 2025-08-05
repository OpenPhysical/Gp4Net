using System;
using Microsoft.Extensions.DependencyInjection;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Infrastructure;

/// <summary>
/// Type registrar for integrating Microsoft.Extensions.DependencyInjection with Spectre.Console.Cli.
/// </summary>
public sealed class TypeRegistrar : ITypeRegistrar
{
    private readonly IServiceCollection? _builder;
    private readonly IServiceProvider? _provider;

    /// <summary>
    /// Initializes a new instance of the TypeRegistrar class.
    /// </summary>
    /// <param name="builder">The service collection.</param>
    public TypeRegistrar(IServiceCollection builder)
    {
        _builder = builder;
    }

    /// <summary>
    /// Initializes a new instance of the TypeRegistrar class with a pre-built service provider.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    public TypeRegistrar(IServiceProvider provider)
    {
        _provider = provider;
    }

    /// <inheritdoc />
    public ITypeResolver Build()
    {
        if (_provider != null)
        {
            return new TypeResolver(_provider);
        }

        if (_builder != null)
        {
            return new TypeResolver(_builder.BuildServiceProvider());
        }

        throw new InvalidOperationException("No service collection or provider available");
    }

    /// <inheritdoc />
    public void Register(Type service, Type implementation)
    {
        if (_builder == null)
        {
            throw new InvalidOperationException("Cannot register types with a pre-built service provider");
        }
        _ = _builder.AddSingleton(service, implementation);
    }

    /// <inheritdoc />
    public void RegisterInstance(Type service, object implementation)
    {
        if (_builder == null)
        {
            throw new InvalidOperationException("Cannot register instances with a pre-built service provider");
        }
        _ = _builder.AddSingleton(service, implementation);
    }

    /// <inheritdoc />
    public void RegisterLazy(Type service, Func<object> factory)
    {
        if (_builder == null)
        {
            throw new InvalidOperationException("Cannot register lazy factories with a pre-built service provider");
        }
        _ = _builder.AddSingleton(service, _ => factory());
    }
}

/// <summary>
/// Type resolver for integrating Microsoft.Extensions.DependencyInjection with Spectre.Console.Cli.
/// </summary>
public sealed class TypeResolver : ITypeResolver
{
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Initializes a new instance of the TypeResolver class.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    public TypeResolver(IServiceProvider provider)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
    }

    /// <inheritdoc />
    public object? Resolve(Type? type)
    {
        if (type == null)
        {
            return null;
        }

        return _provider.GetService(type);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_provider is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}