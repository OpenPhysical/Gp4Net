# Compilation Fixes Summary

## Issues Fixed

### 1. Missing SecurityLevel References
**Problem**: `SecurityLevel` enum could not be found in test files.
**Solution**: Added `using Gp4Net.Domain;` to the following files:
- `/tests/Gp4Net.Tests/Domain/Commands/ExternalAuthenticateCommandTests.cs`
- `/tests/Gp4Net.Tests/Domain/Protocol/Scp03ProtocolTests.cs`

### 2. Ambiguous DeleteCommand References
**Problem**: `DeleteCommand` exists in both `Gp4Net.Tool.Commands.Applet` and `Gp4Net.Domain.Commands` namespaces.
**Solution**: In `/tests/Gp4Net.Tests/Integration/DeleteCommandCryptoIntegrationTests.cs`:
- Added alias: `using DeleteCliCommand = Gp4Net.Tool.Commands.Applet.DeleteCommand;`
- Changed all references from `DeleteCommand` to `DeleteCliCommand`

### 3. VirtualCardTestBuilder Static Type Error
**Problem**: Cannot declare a variable of static type `VirtualCardTestBuilder`.
**Solution**: In `/tests/Gp4Net.Tests/Integration/DeleteCommandCryptoIntegrationTests.cs`:
- Removed the field declaration `private VirtualCardTestBuilder _cardBuilder;`
- Removed initialization in Setup method

### 4. Missing IGlobalPlatformService References
**Problem**: `IGlobalPlatformService` could not be found in multiple test files.
**Solution**: Added `using Gp4Net.Services;` to:
- `/tests/Gp4Net.Tests/Tool/Commands/BaseCommandTests.cs`
- `/tests/Gp4Net.Tests/Tool/Commands/Card/InfoCommandTests.cs`
- `/tests/Gp4Net.Tests/Tool/Commands/Card/ListReadersCommandTests.cs`
- `/tests/Gp4Net.Tests/Tool/Commands/Applet/DeleteCommandTests.cs`

### 5. Missing DeletionResult Reference
**Problem**: `DeletionResult` type could not be found.
**Solution**: In `/tests/Gp4Net.Tests/Integration/DeleteCommandIntegrationTests.cs`:
- Added `using Gp4Net.Domain;` (where DeletionResult is defined in Results.cs)

### 6. Missing NxpP71Scp02Card Type
**Problem**: `NxpP71Scp02Card` class no longer exists.
**Solution**: In `/tests/Gp4Net.Tests/Integration/ScpConversionIntegrationTests.cs`:
- Added `using Gp4Net.CardEmulator.Functional;`
- Changed all `new NxpP71Scp02Card()` to `VirtualCardTestBuilder.P71Card()`
- Changed method parameter from `NxpP71Scp02Card` to `FunctionalVirtualCard`

### 7. Missing ICardService Reference
**Problem**: `ICardService` could not be found.
**Solution**: In `/tests/Gp4Net.Tests/Tool/Commands/Applet/DeleteCommandPipelineTests.cs`:
- Added `using Gp4Net.Tool.Services;`

### 8. TestKeySet Missing Interface Member
**Problem**: `TestKeySet` does not implement `IKeySet.KeyId`.
**Solution**: In `/tests/Gp4Net.Tests/TestHelpers/TestKeySet.cs`:
- Added `KeyId` property to the class
- Added optional `keyId` parameter to constructor with default value of 0

### 9. SecurityLevel Enum Value Mismatches
**Problem**: Tests used incorrect enum values like `NoSecurity` and `CMacAndCDecryption`.
**Solution**: Updated enum values to match actual definition:
- Changed `SecurityLevel.NoSecurity` to `SecurityLevel.None`
- Changed `SecurityLevel.CMacAndCDecryption` to `SecurityLevel.CDecryption`

### 10. TestCase Attribute Compilation Errors
**Problem**: TestCase attributes cannot use non-constant expressions.
**Solution**: In `/tests/Gp4Net.Tests/Domain/Commands/GetDataCommandTests.cs`:
- Replaced `GetDataCommand.DataObjects.*` references with literal constants
- Fixed missing `Cplc` constant by using literal value `0x9F7F`

## Summary
All compilation errors related to missing references and ambiguous types have been successfully resolved. The remaining errors in the build output are related to NUnit assertion issues and test logic problems, which are outside the scope of this task.