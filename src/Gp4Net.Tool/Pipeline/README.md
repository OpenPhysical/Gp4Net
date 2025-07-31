# Pipeline Architecture Separation

## Overview

The Gp4Net architecture maintains a clear separation between two distinct pipeline concepts:

### 1. Command Pipeline (Core Library - Gp4Net)
- **Purpose**: Execute APDU commands through middleware
- **Pattern**: Pure functional with Result<T,E> monads
- **Context**: `IPipelineContext` - immutable data flow
- **Scope**: Low-level smart card communication
- **Example**: Secure channel wrapping, MAC calculation, command retry

### 2. CLI Pipeline (Tool - Gp4Net.Tool)
- **Purpose**: Orchestrate CLI commands and user interaction
- **Pattern**: Functional composition with exception handling at boundaries
- **Context**: `ICliExecutionContext` - service coordination
- **Scope**: High-level command orchestration
- **Example**: Connect to card, establish secure channel, execute operations

## Key Differences

| Aspect | Command Pipeline | CLI Pipeline |
|--------|-----------------|--------------|
| **Error Handling** | Result<T,E> throughout | Exceptions at boundaries |
| **State Management** | Immutable context | Stateful services |
| **Dependencies** | Injected via context | Service locator pattern |
| **Lifetime** | Per APDU command | Per CLI session |
| **Testing** | Pure functions, no mocks | Integration tests |

## Migration Path

To achieve full functional separation:

1. **Phase 1**: Use `FunctionalCliContext` for new commands
2. **Phase 2**: Migrate existing commands to functional patterns
3. **Phase 3**: Remove exception-based `CommandContext`
4. **Phase 4**: Pure functional composition throughout

## Example Usage

### Old Pattern (Exception-based)
```csharp
public async Task<int> ExecuteAsync(ICliExecutionContext context, Settings settings)
{
    return await context.ExecuteCardCommand(settings, async ctx =>
    {
        // Throws exceptions on failure
        var result = await DoSomething();
        return 0;
    });
}
```

### New Pattern (Functional)
```csharp
public async Task<int> ExecuteAsync(ICliExecutionContext context, Settings settings)
{
    return await context.ExecuteCardCommandFunctional(settings, async ctx =>
    {
        // Returns Result<T,E> on failure
        var result = await DoSomethingFunctional();
        return result.Map(_ => true);
    });
}
```

## Benefits

1. **Clear Separation**: Core library remains pure and reusable
2. **Better Testing**: Pure functions are easier to test
3. **Explicit Errors**: All failure modes are visible in types
4. **Composability**: Operations compose naturally with Result<T,E>
5. **No Surprises**: No hidden exceptions in business logic