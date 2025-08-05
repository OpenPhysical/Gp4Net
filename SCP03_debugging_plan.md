# Functional SCP Protocol Architecture Implementation Plan

## Overview
This plan outlines the implementation of a fully functional architecture for SCP02 and SCP03 protocols, replacing the inheritance-based approach with pure functions and functional composition.

## Current Status
✅ **Completed:**
- Fixed SCP02 sequence counter parsing issue
- Created ScpCommonOperations with shared APDU/MAC/padding functions  
- Created ScpCryptogramOperations for shared cryptogram logic
- Defined minimal IScpProtocol<TSelf> interface with static virtual members
- Implemented Scp02ProtocolImpl and Scp03ProtocolImpl
- Created ScpProtocolOperations with generic protocol methods
- Created GenericSecurityProcessor demonstrating functional architecture

🔄 **In Progress:**
- Fixing compilation errors in middleware and protocols
- Updating SecureChannelMiddleware to use functional API

❌ **TODO:**
- Complete compilation error fixes
- Replace SecureChannelProtocolBase with functional composition
- Update services to use new functional protocols
- Create comprehensive unit tests
- Update integration tests and cleanup obsolete code

## Architecture Principles

### 1. Functional Core
- **No Exceptions**: All operations return `Result<T, SmartCardError>`
- **Pure Functions**: Protocol operations have no side effects
- **Immutable State**: All data structures are immutable
- **Explicit Error Handling**: Every operation that can fail returns Result<T, TError>

### 2. Protocol Interface Design
```csharp
public interface IScpProtocol<TSelf> where TSelf : IScpProtocol<TSelf>
{
    // Static properties for compile-time protocol selection
    static abstract byte ProtocolVersion { get; }
    static abstract int BlockSize { get; }
    static abstract int MacSize { get; }
    static abstract int ChainingValueSize { get; }
    
    // Protocol-specific operations
    static abstract Result<byte[], SmartCardError> CalculateMac(byte[] key, byte[] data);
    static abstract Result<SessionKeys, SmartCardError> DeriveSessionKeys(
        IKeySet keySet, byte[] hostChallenge, byte[] cardChallenge, byte[]? sequenceCounter);
    
    // Default implementations using TSelf
    static virtual Result ValidateKeySet(IKeySet keySet) { /* default validation */ }
}
```

### 3. Functional Composition Pattern
```csharp
// Generic operations that work with any protocol
public static class ScpProtocolOperations
{
    public static Result<SecureChannelContext, SmartCardError> ProcessInitializeUpdate<TProtocol>(
        InitializeUpdateResponse response, byte[] hostChallenge, IKeySet keySet)
        where TProtocol : IScpProtocol<TProtocol>
    {
        return TProtocol.ValidateKeySet(keySet)
            .Bind(_ => TProtocol.DeriveSessionKeys(keySet, hostChallenge, response.CardChallenge, response.SequenceCounter))
            .Bind(sessionKeys => VerifyCardCryptogram<TProtocol>(response, hostChallenge, sessionKeys)
                .Map(_ => new SecureChannelContext(hostChallenge, response, sessionKeys, TProtocol.ProtocolVersion, keySet)));
    }
}
```

## Phase 1: Complete Functional Architecture (IN PROGRESS)

### 1.1 Fix Remaining Compilation Errors
- ✅ Fix ValidateKeySet method calls
- ✅ Fix ImmutableArray.ToArray() usage
- ✅ Fix ScpProtocolOperations return types
- 🔄 Fix SecureChannelMiddleware API usage
- ❌ Fix LoggingMiddleware references
- ❌ Build and validate all projects

### 1.2 Update SecureChannelMiddleware
```csharp
// Update to use functional API
public class SecureChannelMiddleware : CommandMiddlewareBase
{
    public override async Task<Result<CommandResponse, SmartCardError>> InvokeAsync(
        CommandRequest request, CommandDelegate next, CancellationToken cancellationToken = default)
    {
        var session = request.Context.Get<SecureChannelState>(ContextKeys.SecureChannelSession);
        
        if (!session.HasValue || !RequiresSecureChannel(request))
            return await next(request, cancellationToken);

        // Use functional security processors
        return session.Value.ProtocolVersion switch
        {
            0x02 => await ProcessWithScp02(request, next, session.Value, cancellationToken),
            0x03 => await ProcessWithScp03(request, next, session.Value, cancellationToken),
            _ => SmartCardError.InvalidArgument($"Unsupported protocol version: {session.Value.ProtocolVersion:X2}")
        };
    }
    
    private async Task<Result<CommandResponse, SmartCardError>> ProcessWithScp02(
        CommandRequest request, CommandDelegate next, SecureChannelState session, CancellationToken cancellationToken)
    {
        return await ProcessSecureCommand(
            request, next, session, 
            Scp02SecurityProcessor.ApplyCommandSecurity,
            Scp02SecurityProcessor.ApplyResponseSecurity,
            cancellationToken);
    }
}
```

### 1.3 Replace SecureChannelProtocolBase Usage
- ❌ Update FunctionalScp03Protocol to use composition instead of inheritance
- ❌ Create protocol factory using functional approach
- ❌ Update SecureChannelManager to use functional protocols

## Phase 2: Service Layer Integration

### 2.1 Update GlobalPlatformService
```csharp
public class FunctionalGlobalPlatformService : IGlobalPlatformService
{
    public Result<SecureChannelState, SmartCardError> EstablishSecureChannel(
        IKeySet keySet, SecurityLevel securityLevel)
    {
        return keySet switch
        {
            Scp02KeySet => EstablishScp02Channel(keySet, securityLevel),
            Scp03KeySet => EstablishScp03Channel(keySet, securityLevel),
            _ => SmartCardError.InvalidArgument("Unsupported key set type")
        };
    }
    
    private Result<SecureChannelState, SmartCardError> EstablishScp02Channel(
        IKeySet keySet, SecurityLevel securityLevel)
    {
        return GenerateHostChallenge()
            .Bind(hostChallenge => SendInitializeUpdate(hostChallenge))
            .Bind(response => Scp02SecurityProcessor.ProcessInitializeUpdate(response, hostChallenge, keySet))
            .Bind(context => Scp02SecurityProcessor.CreateExternalAuthenticate(context, securityLevel))
            .Bind(extAuth => SendExternalAuthenticate(extAuth))
            .Map(_ => CreateSecureChannelState(context, securityLevel));
    }
}
```

### 2.2 Command Builders Integration
- ❌ Update command builders to use functional protocols
- ❌ Integrate with pipeline middleware
- ❌ Add protocol-specific validation

## Phase 3: Testing Infrastructure

### 3.1 Protocol-Specific Unit Tests
```csharp
[TestFixture]
public class Scp02ProtocolImplTests
{
    [Test]
    public void DeriveSessionKeys_WithValidInputs_ReturnsExpectedKeys()
    {
        var keySet = new Scp02KeySet(TestKeys.Enc, TestKeys.Mac, TestKeys.Dek);
        var hostChallenge = "0102030405060708".FromHex();
        var cardChallenge = "090A0B0C0D0E".FromHex();
        var sequenceCounter = "0001".FromHex();
        
        var result = Scp02ProtocolImpl.DeriveSessionKeys(
            keySet, hostChallenge, cardChallenge, sequenceCounter);
        
        result.IsSuccess.Should().BeTrue();
        result.Value.SEnc.Should().Equal(expectedSEnc);
    }
}
```

### 3.2 Functional Integration Tests
```csharp
[TestFixture]
public class FunctionalSecurityProcessorTests
{
    [Test]
    public void Scp02SecurityProcessor_ProcessInitializeUpdate_WithValidResponse_CreatesContext()
    {
        var response = CreateValidScp02Response();
        var hostChallenge = GenerateHostChallenge();
        var keySet = new Scp02KeySet(TestKeys.Enc, TestKeys.Mac, TestKeys.Dek);
        
        var result = Scp02SecurityProcessor.ProcessInitializeUpdate(response, hostChallenge, keySet);
        
        result.IsSuccess.Should().BeTrue();
        result.Value.ProtocolVersion.Should().Be(0x02);
    }
}
```

### 3.3 End-to-End Functional Tests
- ❌ Virtual card tests using functional processors
- ❌ Real card compatibility tests
- ❌ Performance benchmarks

## Phase 4: Documentation and Cleanup

### 4.1 Code Documentation
- ❌ Update XML documentation for all functional methods
- ❌ Add usage examples in comments
- ❌ Document protocol-specific behavior

### 4.2 Remove Legacy Code
- ❌ Remove SecureChannelProtocolBase and subclasses
- ❌ Remove old SecureChannelSession implementations
- ❌ Clean up unused imports and dependencies

### 4.3 Architecture Documentation
- ❌ Update CLAUDE.md with new functional patterns
- ❌ Document protocol selection mechanisms
- ❌ Add troubleshooting guide

## Success Criteria

1. **Compilation**: All projects build without errors or warnings
2. **Tests**: All existing tests pass with new functional implementation
3. **Functionality**: SCP02/SCP03 authentication works with real cards
4. **Performance**: No performance regression from functional approach
5. **Maintainability**: Clear separation of protocol-specific and shared logic
6. **Documentation**: Complete documentation of functional patterns

## Current Priorities

1. **HIGH**: Fix remaining compilation errors (SecureChannelMiddleware, LoggingMiddleware)
2. **HIGH**: Complete functional middleware integration
3. **MEDIUM**: Update service layer to use functional protocols
4. **MEDIUM**: Create comprehensive unit tests
5. **LOW**: Documentation and cleanup

## Dependencies

- **CSharpFunctionalExtensions**: For Result<T, TError> types
- **Existing Key Management**: Scp02KeySet, Scp03KeySet classes
- **Command Infrastructure**: APDU command builders and pipeline
- **Transport Layer**: IApduTransport implementations