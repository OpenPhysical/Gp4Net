using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using MoonSharp.Interpreter;

namespace Gp4Net.Tool.Scripting
{
    /// <summary>
    /// Manages Lua script execution and module registration.
    /// </summary>
    [PublicAPI]
    public class ScriptManager : IScriptManager
    {
        private readonly ILogger<ScriptManager> _logger;
        private readonly ScriptDirectoryResolver _directoryResolver;
        private readonly ICardService _cardService;
        private readonly IDomainServiceFactory _domainServiceFactory;
        private readonly Dictionary<string, Script> _scriptCache;
        private Gp4Net.Services.IGlobalPlatformService? _cachedGlobalPlatformService;

        /// <summary>
        /// Initializes a new instance of the ScriptManager class.
        /// </summary>
        public ScriptManager(
            ILogger<ScriptManager> logger,
            ScriptDirectoryResolver directoryResolver,
            ICardService cardService,
            IDomainServiceFactory domainServiceFactory
        )
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _directoryResolver =
                directoryResolver ?? throw new ArgumentNullException(nameof(directoryResolver));
            _cardService = cardService ?? throw new ArgumentNullException(nameof(cardService));
            _domainServiceFactory =
                domainServiceFactory
                ?? throw new ArgumentNullException(nameof(domainServiceFactory));
            _scriptCache = [];

            // Register user data types
            UserData.RegisterAssembly(typeof(ScriptManager).Assembly);
        }

        /// <summary>
        /// Creates a new Lua script with all modules loaded.
        /// </summary>
        public Script CreateScript()
        {
            var script = new Script
            {
                Options =
                {
                    // Set up module loader to search in our directories
                    ScriptLoader = new CustomScriptLoader(_directoryResolver)
                }
            };

            // Register modules
            RegisterGpModule(script);
            RegisterCryptoModule(script);
            RegisterUtilityModule(script);

            // Set up global functions
            RegisterGlobalFunctions(script);

            return script;
        }

        /// <summary>
        /// Executes a script file.
        /// </summary>
        public async Task<DynValue> ExecuteScriptFileAsync(string scriptPath)
        {
            var fullPath = _directoryResolver.FindScript(scriptPath);
            if (fullPath == null)
            {
                throw new FileNotFoundException($"Script not found: {scriptPath}");
            }

            _logger.LogDebug("Executing script: {ScriptPath}", fullPath);

            // Check cache
            if (!_scriptCache.TryGetValue(fullPath, out var script))
            {
                script = CreateScript();
                var scriptContent = await File.ReadAllTextAsync(fullPath).ConfigureAwait(false);
                _ = script.DoString(scriptContent, codeFriendlyName: Path.GetFileName(fullPath));
                _scriptCache[fullPath] = script;
            }

            return DynValue.Nil;
        }

        /// <summary>
        /// Executes a Lua function from a script.
        /// </summary>
        public DynValue ExecuteFunction(
            string scriptFunction,
            Dictionary<string, object>? parameters = null
        )
        {
            // Parse script:function format
            string scriptName = "kdf";
            string functionName = scriptFunction;

            if (scriptFunction.Contains(':'))
            {
                var parts = scriptFunction.Split(':');
                scriptName = parts[0];
                functionName = parts[1];
            }

            // Find and load script
            var scriptPath = _directoryResolver.FindScript(scriptName);
            if (scriptPath == null)
            {
                throw new FileNotFoundException($"Script not found: {scriptName}");
            }

            var script = GetOrLoadScript(scriptPath);

            // Get the function
            var function = script.Globals.Get(functionName);
            if (function.Type != DataType.Function)
            {
                throw new InvalidOperationException($"Function not found: {functionName}");
            }

            // Create context table with parameters
            var context = script.DoString("return {}").Table;

            if (parameters != null)
            {
                var paramsTable = script.DoString("return {}").Table;
                foreach (var param in parameters)
                {
                    paramsTable[param.Key] = param.Value;
                }
                context["params"] = paramsTable;
            }

            // Call the function
            return script.Call(function, context);
        }

        /// <summary>
        /// Executes a specific function in a script file with arguments.
        /// </summary>
        public DynValue ExecuteScriptFunction(
            string scriptPath,
            string functionName,
            string[] args,
            Dictionary<string, object>? context = null
        )
        {
            // Find and load script
            var fullScriptPath = _directoryResolver.FindScript(scriptPath);
            if (fullScriptPath == null)
            {
                throw new FileNotFoundException($"Script not found: {scriptPath}");
            }

            var script = GetOrLoadScript(fullScriptPath);

            // Get the function
            var function = script.Globals.Get(functionName);
            if (function.IsNil())
            {
                throw new InvalidOperationException(
                    $"Function '{functionName}' not found in script '{scriptPath}'"
                );
            }

            // Create context table
            var contextTable = script.DoString("return {}").Table;

            if (context != null)
            {
                foreach (var kvp in context)
                {
                    contextTable[kvp.Key] = kvp.Value;
                }
            }

            // Set global context for scripts to access
            script.Globals["_CONTEXT"] = contextTable;

            // Convert string args to Lua table
            var argsTable = script.DoString("return {}").Table;
            for (int i = 0; i < args.Length; i++)
            {
                argsTable[i + 1] = args[i]; // Lua is 1-indexed
            }

            // Call the function with args
            return script.Call(function, argsTable);
        }

        /// <summary>
        /// Executes a Lua expression.
        /// </summary>
        public DynValue ExecuteExpression(string expression)
        {
            var script = CreateScript();
            return script.DoString(expression);
        }

        /// <summary>
        /// Creates a Lua REPL session.
        /// </summary>
        public void StartRepl()
        {
            var script = CreateScript();

            Console.WriteLine("GP4Net Lua REPL");
            Console.WriteLine("Type 'exit' to quit");
            Console.WriteLine();

            while (true)
            {
                Console.Write("lua> ");
                var input = Console.ReadLine();

                if (string.IsNullOrWhiteSpace(input))
                {
                    continue;
                }

                if (input.Trim().ToLower() == "exit")
                {
                    break;
                }

                try
                {
                    var result = script.DoString(input);
                    if (result.Type != DataType.Void && result.Type != DataType.Nil)
                    {
                        Console.WriteLine($"=> {result}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
            }
        }

        private Script GetOrLoadScript(string scriptPath)
        {
            if (_scriptCache.TryGetValue(scriptPath, out var cachedScript))
            {
                return cachedScript;
            }

            var script = CreateScript();
            var scriptContent = File.ReadAllText(scriptPath);
            _ = script.DoString(scriptContent, codeFriendlyName: Path.GetFileName(scriptPath));
            _scriptCache[scriptPath] = script;

            return script;
        }

        private void RegisterGpModule(Script script)
        {
            var globalPlatformService = GetGlobalPlatformService();
            var gpModule = new GpScriptModule(_cardService, globalPlatformService, _logger);
            script.Globals["gp"] = UserData.Create(gpModule);
        }

        private Gp4Net.Services.IGlobalPlatformService GetGlobalPlatformService()
        {
            // Create on demand with proper context, cache for reuse
            return _cachedGlobalPlatformService ??= _domainServiceFactory
                .CreateGlobalPlatformService(_cardService);
        }

        private void RegisterCryptoModule(Script script)
        {
            var cryptoModule = new CryptoScriptModule();
            script.Globals["crypto"] = UserData.Create(cryptoModule);
        }

        private void RegisterUtilityModule(Script script)
        {
            var utilityModule = new UtilityScriptModule();

            // Register as global functions for convenience
            script.Globals["hex"] = (Func<string, byte[]>)utilityModule.Hex;
            script.Globals["bytes"] = (Func<object, byte[]>)utilityModule.Bytes;
            script.Globals["concat"] = (Func<byte[][], byte[]>)utilityModule.Concat;
            script.Globals["sub"] = (Func<byte[], int, int, byte[]>)utilityModule.Sub;
            script.Globals["xor"] = (Func<byte[], byte[], byte[]>)utilityModule.Xor;
            script.Globals["pad80"] = (Func<byte[], int, byte[]>)utilityModule.Pad80;
            script.Globals["hex_string"] = (Func<byte[], string>)utilityModule.HexString;
            script.Globals["random_bytes"] = (Func<int, byte[]>)utilityModule.RandomBytes;
        }

        private void RegisterGlobalFunctions(Script script)
        {
            // Print function that works with byte arrays
            script.Globals["print"] =
                (Action<DynValue[]>)(
                    (args) =>
                    {
                        var parts = new List<string>();
                        foreach (var arg in args)
                        {
                            if (
                                arg.Type == DataType.UserData
                                && arg.UserData.Object is byte[] bytes
                            )
                            {
                                parts.Add(BitConverter.ToString(bytes).Replace("-", ""));
                            }
                            else
                            {
                                parts.Add(arg.ToPrintString());
                            }
                        }
                        Console.WriteLine(string.Join(" ", parts));
                    }
                );

            // Require function for loading modules
            script.Globals["require"] =
                (Func<string, DynValue>)(
                    (moduleName) =>
                    {
                        var modulePath = _directoryResolver.FindScript(moduleName);
                        if (modulePath == null)
                        {
                            throw new FileNotFoundException($"Module not found: {moduleName}");
                        }

                        return script.DoFile(modulePath);
                    }
                );
        }

        /// <summary>
        /// Custom script loader that searches in our directories.
        /// </summary>
        private class CustomScriptLoader : MoonSharp.Interpreter.Loaders.IScriptLoader
        {
            private readonly ScriptDirectoryResolver _resolver;

            public CustomScriptLoader(ScriptDirectoryResolver resolver)
            {
                _resolver = resolver;
            }

            public object LoadFile(string file, Table globalContext)
            {
                var fullPath = _resolver.FindScript(file);
                if (fullPath == null)
                {
                    throw new FileNotFoundException($"Script not found: {file}");
                }

                return File.ReadAllText(fullPath);
            }

            public string ResolveFileName(string filename, Table globalContext)
            {
                return _resolver.FindScript(filename) ?? filename;
            }

            public string ResolveModuleName(string modname, Table globalContext)
            {
                return modname.Replace('.', '/');
            }
        }
    }
}
