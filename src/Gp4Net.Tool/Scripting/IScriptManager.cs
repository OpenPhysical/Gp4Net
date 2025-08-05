using System.Collections.Generic;
using System.Threading.Tasks;
using JetBrains.Annotations;
using MoonSharp.Interpreter;

namespace Gp4Net.Tool.Scripting;

/// <summary>
/// Interface for managing Lua script execution and module registration.
/// </summary>
[PublicAPI]
public interface IScriptManager
{
    /// <summary>
    /// Creates a new Lua script with all modules loaded.
    /// </summary>
    Script CreateScript();

    /// <summary>
    /// Executes a script file.
    /// </summary>
    Task<DynValue> ExecuteScriptFileAsync(string scriptPath);

    /// <summary>
    /// Executes a Lua function from a script.
    /// </summary>
    DynValue ExecuteFunction(
        string scriptFunction,
        Dictionary<string, object> parameters = null
    );

    /// <summary>
    /// Executes a specific function in a script file with arguments.
    /// </summary>
    DynValue ExecuteScriptFunction(
        string scriptPath,
        string functionName,
        string[] args,
        Dictionary<string, object> context = null
    );

    /// <summary>
    /// Executes a Lua expression.
    /// </summary>
    DynValue ExecuteExpression(string expression);

    /// <summary>
    /// Creates a Lua REPL session.
    /// </summary>
    void StartRepl();
}