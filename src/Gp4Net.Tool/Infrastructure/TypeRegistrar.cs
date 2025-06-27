using System;
using Microsoft.Extensions.DependencyInjection;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Infrastructure
{
    /// <summary>
    /// Type registrar for integrating Microsoft.Extensions.DependencyInjection with Spectre.Console.Cli.
    /// </summary>
    public sealed class TypeRegistrar : ITypeRegistrar
    {
        private readonly IServiceCollection _builder;

        /// <summary>
        /// Initializes a new instance of the TypeRegistrar class.
        /// </summary>
        /// <param name="builder">The service collection.</param>
        public TypeRegistrar(IServiceCollection builder)
        {
            _builder = builder;
        }

        /// <inheritdoc />
        public ITypeResolver Build()
        {
            return new TypeResolver(_builder.BuildServiceProvider());
        }

        /// <inheritdoc />
        public void Register(Type service, Type implementation)
        {
            _builder.AddSingleton(service, implementation);
        }

        /// <inheritdoc />
        public void RegisterInstance(Type service, object implementation)
        {
            _builder.AddSingleton(service, implementation);
        }

        /// <inheritdoc />
        public void RegisterLazy(Type service, Func<object> factory)
        {
            _builder.AddSingleton(service, _ => factory());
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
}