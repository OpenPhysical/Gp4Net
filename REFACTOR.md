# REFACTOR.md - Functional Architecture Refactoring

This document tracks the functional programming refactoring of Gp4Net. 

## MAJOR MILESTONE ACHIEVED ✅
**Successfully completed functional architecture migration with 94.3% test pass rate (804/853 tests passing)**

## Completed Core Refactoring ✅

### 1. Functional Architecture Implementation (COMPLETED)
- [x] Created `IScpProtocol<TSelf>` interface with static abstract members
- [x] Implemented `Scp02ProtocolImpl` and `Scp03ProtocolImpl` with static methods
- [x] Created `ScpCommonOperations` for shared APDU/MAC/padding functions
- [x] Created `ScpCryptogramOperations` for shared cryptogram logic
- [x] Created `ScpProtocolOperations` with generic protocol methods
- [x] Implemented `GenericSecurityProcessor<TProtocol>` demonstrating type-safe selection
- [x] Created immutable `SecureChannelState` with functional transitions
- [x] Created `MacChainingState` value object with proper domain modeling
- [x] Updated `SecureChannelMiddleware` to use functional API
- [x] Fixed SCP02 sequence counter parsing (2 bytes, not 3)

### 2. Test Migration Progress (94.3% Complete)
- [x] Created new functional test files (SecureChannelStateTests, Scp02/Scp03SecurityProcessorTests)
- [x] Deleted legacy protocol tests using old OOP API
- [x] Fixed compilation errors in test project
- [x] 804 out of 853 tests passing
- [ ] Fix remaining 49 failing tests in integration/conformance files

### 3. Security and Encryption
- [ ] Add complete R-ENC support to `SecureChannelSession`
- [ ] Implement C-MAC verification for EXTERNAL AUTHENTICATE command
- [ ] Implement sequence counter tracking for replay prevention
- [ ] Fix replay attack prevention test

### 4. Test Infrastructure
- [x] Create dynamic trace-based test system with JSON conversion
- [x] Implement enhanced trace conversion tool supporting GP Pro and GPShell formats
- [x] Create organized TestData/Traces directory structure with SCP02/SCP03 organization
- [x] Build automatic test discovery system for trace operations
- [ ] Rewrite R-ENC test to use purely functional approach
- [ ] Fix key derivation test with proper test vector validation
- [ ] Fix tests using invalid synthetic data
- [ ] Fix SCP03 MAC generation validation issues
- [ ] Fix remaining SCP02 conformance test failures

### 5. Code Quality and Standards
- [ ] Replace `ToHexString`/`FromHexString` extensions with `Convert` methods
- [ ] Fix card discovery tests to handle real card data structures
- [ ] Add documentation about when to use BouncyCastle vs TlvParser

## Completed Refactoring Tasks

### Static Virtual Interface Pattern
- [x] Create `IScpProtocolService` interface with static virtual members
- [x] Implement `Scp02ProtocolService` with 3DES-specific operations
- [x] Implement `Scp03ProtocolService` with AES-specific operations
- [x] Extract shared `CryptographicOperations` static class
- [x] Update virtual card to use same static services
- [x] Remove all duplicated MAC calculation code

### Functional Architecture
- [x] Create immutable `SecureChannelState` record with functional transitions
- [x] Implement `IFunctionalSecureChannelService` with pure functions
- [x] Rewrite `FunctionalVirtualCard` to use immutable state throughout
- [x] Create functional `CommandSecurityProcessor` as stateless service
- [x] Rewrite `ResponseSecurityProcessor` to be completely stateless
- [x] Remove all exceptions from `SecureChannelSession` - use `Result<T,E>`
- [x] Add `Maybe<T>` usage for optional values

### Protocol Fixes
- [x] Fix SCP03 EXTERNAL AUTHENTICATE MAC chaining value initialization
- [x] Fix R-MAC verification failure in functional virtual card
- [x] Fix client-side MAC chaining value initialization in `SecureChannelSession`
- [x] Fix SCP03 key derivation structure to match specification
- [x] Fix SCP03 security level validation to accept 0x30 (R-MAC + R-ENC)
- [x] Fix virtual card state loss between EXTERNAL AUTHENTICATE and GET DATA commands

## Refactoring Principles

1. **No Nulls**: Always use `Result<T>` or `Maybe<T>` for optional values
2. **No Exceptions**: All errors handled through `Result<T, SmartCardError>`
3. **Immutability**: Prefer immutable data structures and pure functions
4. **Static Virtual Members**: Use C# 11 features for compile-time polymorphism
5. **Domain Modeling**: Create proper value objects for domain concepts
6. **Functional Composition**: Build complex operations from simple pure functions
7. **Separation of Concerns**: Clear boundaries between domain logic and infrastructure

## Remaining Tasks (No Backwards Compatibility)

### Phase 1: Complete Test Migration (COMPLETED)
- [x] Update `CapLoadingIntegrationTests.cs` to use `SecureChannelState`
- [x] Update `Scp02ConformanceTests.cs` to use functional API
- [x] Update `Scp03ConformanceTests.cs` to use functional API  
- [x] Update `DebugScp03KeyDerivation.cs` to use functional API
- [x] `FunctionalGlobalPlatformServiceTests.cs` already uses functional API

### Phase 2: Consolidate Duplicates
- [x] Delete `GlobalPlatformService` and rename `FunctionalGlobalPlatformService` (COMPLETED)
- [ ] Delete legacy `Scp02Protocol` and `Scp03Protocol` classes
- [ ] Delete `SecureChannelSession` and all variants
- [ ] Delete old `CommandSecurityProcessor` and `ResponseSecurityProcessor`
- [ ] Consolidate any "Functional" prefixed classes

### Phase 3: Clean Development Artifacts
- [ ] Delete 24 debug scripts (fix_*.py, SCP03_*.txt, etc.)
- [ ] Clean up duplicate test files
- [ ] Remove commented-out code
- [ ] Update documentation

## Current Focus

1. Update remaining 49 failing tests to use functional API
2. Delete all legacy code (no backwards compatibility needed)
3. Clean up development artifacts
4. Achieve 100% test pass rate

## Clean Code Refactoring Plan

### MAC Algorithm Cleanup
1. **Separate MAC Implementations**:
   - Add `CalculateFull3DesMac` for SCP02 authentication cryptograms (Full Triple DES MAC)
   - Add `CalculateRetailMac` for SCP02 C-MAC/R-MAC (ISO 9797-1 Algorithm 3)
   - Fix `Calculate3DesMac` which incorrectly uses ISO9797Alg3Mac for everything
   - Update `Scp02ProtocolImpl` to have separate methods for cryptogram vs command MACs

2. **DRY Violations to Fix**:
   - **Triple DES Key Expansion**: Consolidate 5+ duplicate implementations into single `ExpandTripleDesKey` method
   - **ISO 7816-4 Padding**: Consolidate 7+ duplicate implementations into single source
   - **Array Operations**: Remove duplicate `ConcatenateArrays` implementations
   - **Retail MAC**: Replace manual implementation with proper BouncyCastle usage

3. **Code to Delete**:
   - All strategy pattern interfaces and implementations (`ICryptogramStrategy`, `IKeyDerivationStrategy`)
   - `KeyDerivationService` (use direct protocol methods)
   - All duplicate padding implementations
   - All duplicate key expansion code
   - Legacy `Calculate3DesMac` after implementing specific methods

4. **Architecture Principles**:
   - `CryptographicOperations.cs` as single source of truth for crypto primitives
   - Protocol implementations only contain protocol-specific logic
   - No strategy patterns - pure functions with compile-time protocol selection
   - Clear naming - no ambiguous method names