# SCP02 Implementation Issues and Fixes

## Overview

This document catalogs all identified issues in the SCP02 (Secure Channel Protocol 02) implementation based on comprehensive analysis against the GlobalPlatform Card Specification v2.3.1. Each issue includes specification citations, current behavior, expected behavior, and implementation status.

## Critical Cryptographic Issues (Phase 1)

### Issue 1: Incorrect ISO 7816-4 Padding Implementation

**Specification Reference**: GP Card Spec v2.3.1, Section E.4.2.1 (lines 661-662)
> "Applying the same padding rules defined in section B.1.3, the data shall be padded with a further 8-byte block ('80 00 00 00 00 00 00 00')."

**Current Implementation**: `CryptographicOperations.PadToLength()` method uses zero-padding only
```csharp
// Current (WRONG)
var paddedData = new byte[targetLength];
Array.Copy(data, 0, paddedData, 0, data.Length);
// Remaining bytes are already zero-initialized
```

**Expected Implementation**: ISO 7816-4 padding with 0x80 followed by zeros
```csharp
// Expected (CORRECT)
paddedData[data.Length] = 0x80;
// Remaining bytes stay zero
```

**Impact**: All cryptogram verifications fail due to incorrect padding
**Status**: ❌ Not Fixed

### Issue 2: Wrong Key Derivation Constants Format

**Specification Reference**: GP Card Spec v2.3.1, Section E.4.1 (lines 598-612)
- C-MAC session keys: constant `'0101'` (2 bytes)
- R-MAC session keys: constant `'0102'` (2 bytes)  
- S-ENC session keys: constant `'0182'` (2 bytes)
- DEK session keys: constant `'0181'` (2 bytes)

**Current Implementation**: Uses single-byte constant `0x82` in `KeyDerivationService.DeriveScp02SessionKeys()`
```csharp
// Current (WRONG)
var sEncResult = DeriveScp02Key(
    scp02KeySet.EncKey,
    DerivationConstants.DataEncryption, // 0x82 (1 byte)
    sequenceCounter);
```

**Expected Implementation**: Use 2-byte constants from `DerivationConstants.Scp02`
```csharp
// Expected (CORRECT)
var sEncResult = DeriveScp02Key(
    scp02KeySet.EncKey,
    DerivationConstants.Scp02.SecureChannelEncryption, // 0x0182 (2 bytes)
    sequenceCounter);
```

**Impact**: Session key derivation produces incorrect keys
**Status**: ❌ Not Fixed

### Issue 3: Wrong Key Derivation Data Format

**Specification Reference**: GP Card Spec v2.3.1, Figure E-2 (lines 644-646)
> "Derivation data (16 bytes): Constant (2 bytes) || Sequence Counter (2 bytes) || '00' Padding (12 bytes)"

**Current Implementation**: Creates 8-byte derivation data
```csharp
// Current (WRONG)
var derivationData = new byte[8];
derivationData[0] = derivationConstant; // 1 byte
Array.Copy(sequenceCounter, 0, derivationData, 1, sequenceCounter.Length);
```

**Expected Implementation**: Create 16-byte derivation data
```csharp
// Expected (CORRECT)
var derivationData = new byte[16];
Array.Copy(constantBytes, 0, derivationData, 0, 2); // 2 bytes
Array.Copy(sequenceCounter, 0, derivationData, 2, 2); // 2 bytes
// Remaining 12 bytes are zero-padding
```

**Impact**: Wrong key derivation data format produces incorrect session keys
**Status**: ❌ Not Fixed

### Issue 4: Wrong Cryptographic Mode for Key Derivation

**Specification Reference**: GP Card Spec v2.3.1, Section E.4.1 (line 614)
> "The DES operation used to generate these keys is always triple DES in CBC mode."

**Current Implementation**: Uses ECB mode
```csharp
// Current (WRONG)
var cipher = new BufferedBlockCipher(new DesEdeEngine());
```

**Expected Implementation**: Use CBC mode
```csharp
// Expected (CORRECT)
var cipher = new BufferedBlockCipher(new CbcBlockCipher(new DesEdeEngine()));
```

**Impact**: Key derivation uses wrong cryptographic mode
**Status**: ❌ Not Fixed

### Issue 5: Wrong MAC Key Derivation Constant

**Specification Reference**: GP Card Spec v2.3.1, Section E.4.1 (lines 598-600)
> "Generating the Secure Channel C-MAC session keys... with a constant of '0101'"

**Current Implementation**: Uses `CardCryptogram` constant (0x00) for MAC key derivation
```csharp
// Current (WRONG)
var sMacResult = DeriveScp02Key(
    scp02KeySet.MacKey,
    DerivationConstants.CardCryptogram, // 0x00
    sequenceCounter);
```

**Expected Implementation**: Use correct C-MAC constant
```csharp
// Expected (CORRECT)
var sMacResult = DeriveScp02Key(
    scp02KeySet.MacKey,
    DerivationConstants.Scp02.CMac, // 0x0101
    sequenceCounter);
```

**Impact**: MAC key derivation uses wrong constant
**Status**: ❌ Not Fixed

### Issue 6: Incorrect Key Length Handling

**Specification Reference**: GP Card Spec v2.3.1, Figure E-2 shows session keys are complete 16-byte keys

**Current Implementation**: Duplicates 8-byte results for 16-byte keys
```csharp
// Current (WRONG)
if (baseKey.Length == 16) {
    var result = new byte[16];
    Array.Copy(output, 0, result, 0, 8);
    Array.Copy(output, 0, result, 8, 8); // Duplicate
    return result;
}
```

**Expected Implementation**: Derive complete 16-byte keys directly using CBC mode
**Impact**: Key derivation produces incorrect key values
**Status**: ❌ Not Fixed

## Protocol Implementation Issues (Phase 2)

### Issue 7: Missing DEK Session Key Derivation

**Specification Reference**: GP Card Spec v2.3.1, Section E.4.1 (lines 610-612)
> "Generating the Secure Channel data encryption session keys... with a constant of '0181'"

**Current Implementation**: Uses static DEK key
```csharp
// Current (WRONG)
return new SessionKeys(sEncResult.Value, sMac, sRMac, scp02KeySet.DekKey);
```

**Expected Implementation**: Derive DEK session key
```csharp
// Expected (CORRECT)
var sDekResult = DeriveScp02Key(
    scp02KeySet.DekKey,
    DerivationConstants.Scp02.DataEncryptionKey, // 0x0181
    sequenceCounter);
```

**Impact**: DEK operations use static keys instead of session keys
**Status**: ❌ Not Fixed

### Issue 8: Wrong Implementation Parameter Logic

**Specification Reference**: GP Card Spec v2.3.1, Table E-1
- `i=15`: "3 Secure Channel Keys" - derive all session keys
- `i=1A`: "1 Secure Channel base key" - different key handling

**Current Implementation**: Doesn't properly distinguish between 1-key and 3-key implementations
**Impact**: Key derivation strategy doesn't match implementation parameter requirements
**Status**: ❌ Not Fixed

### Issue 9: Missing Separate R-MAC Key Derivation

**Specification Reference**: GP Card Spec v2.3.1, Section E.4.1 (lines 602-604)
> "Generating the Secure Channel R-MAC session keys... with a constant of '0102'"

**Current Implementation**: Uses same key for C-MAC and R-MAC
```csharp
// Current (WRONG)
sRMac = sMacResult.Value; // Same as C-MAC
```

**Expected Implementation**: Derive R-MAC separately
```csharp
// Expected (CORRECT)
var sRMacResult = DeriveScp02Key(
    scp02KeySet.MacKey,
    DerivationConstants.Scp02.RMac, // 0x0102
    sequenceCounter);
```

**Impact**: R-MAC uses wrong key
**Status**: ❌ Not Fixed

### Issue 10: Missing ICV Encryption Implementation

**Specification Reference**: GP Card Spec v2.3.1, Section E.3.4 (lines 580-582)
> "The ICV is encrypted before being applied to the calculation of the next C-MAC. The encryption mechanism used is single DES with the first half of the Secure Channel C-MAC session key."

**Current Implementation**: No ICV encryption implementation
**Expected Implementation**: Encrypt ICV for implementations that require it (i=15, i=1A, i=55)
**Impact**: C-MAC chaining doesn't work correctly for implementations requiring ICV encryption
**Status**: ❌ Not Fixed

### Issue 11: Wrong Base Key Selection Logic

**Specification Reference**: GP Card Spec v2.3.1, Section E.4.1
- For 1-key implementations: use base key for all derivations
- For 3-key implementations: use specific keys (S-ENC, S-MAC, DEK)

**Current Implementation**: Always uses specific keys
**Expected Implementation**: Check implementation parameter to select appropriate base key or specific keys
**Impact**: Key derivation doesn't match specification for 1-key implementations
**Status**: ❌ Not Fixed

## Advanced Protocol Features (Phase 3)

### Issue 12: Missing Pseudo-Random Card Challenge Generation

**Specification Reference**: GP Card Spec v2.3.1, Section E.4.2.3 (lines 680-691)
For `i=55`: "Well-known pseudo-random algorithm (card challenge)"

**Current Implementation**: No pseudo-random challenge generation
**Expected Implementation**: Generate challenge using MAC over padded AID
**Impact**: `i=55` implementation parameter not supported
**Status**: ❌ Not Fixed

### Issue 13: Missing Key Version and Identifier Handling

**Specification Reference**: GP Card Spec v2.3.1, Section E.2
Keys have version numbers and identifiers that affect derivation and selection

**Current Implementation**: No key version validation or handling
**Expected Implementation**: Validate key versions and handle key selection
**Impact**: Key management doesn't follow specification requirements
**Status**: ❌ Not Fixed

### Issue 14: Missing Sequence Counter Management

**Specification Reference**: GP Card Spec v2.3.1, Section E.1.2 (lines 89-99)
> "The Sequence Counter is incremented by 1 when and only when the first C-MAC of a secure channel is verified as valid."

**Current Implementation**: No sequence counter management
**Expected Implementation**: Proper increment logic and persistence
**Impact**: Multi-session scenarios don't work correctly
**Status**: ❌ Not Fixed

### Issue 15: Missing Implicit Initiation Mode Support

**Specification Reference**: GP Card Spec v2.3.1, Section E.1.2.2
Implicit initiation via first C-MAC command without INITIALIZE UPDATE

**Current Implementation**: Only supports explicit initiation
**Expected Implementation**: Support implicit initiation with proper ICV calculation
**Impact**: Implicit secure channel initiation not supported
**Status**: ❌ Not Fixed

### Issue 16: Missing Modified vs Unmodified APDU C-MAC

**Specification Reference**: GP Card Spec v2.3.1, Table E-1, bit b2
- Modified APDU: alter class byte and Lc before MAC calculation
- Unmodified APDU: MAC calculation on original APDU, modify after

**Current Implementation**: No distinction between modes
**Expected Implementation**: Support both modified and unmodified APDU C-MAC calculation
**Impact**: Some implementation parameters don't work correctly
**Status**: ❌ Not Fixed

## Key Diversification System (Phase 4)

### Issue 17: Missing Key Diversification Support

**Specification Reference**: GP Card Spec v2.3.1, Section E.5.1.6
INITIALIZE UPDATE response includes "Key diversification data"

**Current Implementation**: No key diversification processing
**Expected Implementation**: Use diversification data in key derivation
**Impact**: Card-specific key derivation not supported
**Status**: ❌ Not Fixed

### Issue 18: Missing Diversification Data Generation in Emulator

**Specification Reference**: GP Card Spec v2.3.1, Table E-8
INITIALIZE UPDATE response must include 10-byte diversification data

**Current Implementation**: Emulator doesn't generate proper diversification data
**Expected Implementation**: Generate realistic diversification data for testing
**Impact**: Testing doesn't match real card behavior
**Status**: ❌ Not Fixed

## Complete Protocol Support (Phase 5)

### Issue 19: Missing AID-based ICV Calculation

**Specification Reference**: GP Card Spec v2.3.1, Section E.3.3 (lines 555-563)
For `i=1A`: "ICV set to MAC over AID" - ICV calculated from selected application AID

**Current Implementation**: No AID-based ICV calculation
**Expected Implementation**: Calculate ICV using MAC over padded AID
**Impact**: `i=1A` implementation parameter not supported
**Status**: ❌ Not Fixed

### Issue 20: Missing Different Key Set Configuration Support

**Specification Reference**: GP Card Spec v2.3.1, Table E-1, bit b1
- 1 Secure Channel base key vs 3 Secure Channel Keys

**Current Implementation**: Assumes 3-key configuration always
**Expected Implementation**: Support both 1-key and 3-key configurations
**Impact**: 1-key implementations don't work
**Status**: ❌ Not Fixed

### Issue 21: Missing APDU Header Modification

**Specification Reference**: GP Card Spec v2.3.1, Section E.4.4 (lines 784-790)
Class byte modification for secure messaging indication

**Current Implementation**: No APDU header modification logic
**Expected Implementation**: Proper class byte and Lc modification
**Impact**: Secure messaging indication not correct
**Status**: ❌ Not Fixed

### Issue 22: Missing R-MAC Session Management

**Specification Reference**: GP Card Spec v2.3.1, Sections E.5.3 and E.5.4
BEGIN R-MAC SESSION and END R-MAC SESSION commands

**Current Implementation**: No R-MAC session management
**Expected Implementation**: Support R-MAC session commands
**Impact**: R-MAC functionality incomplete
**Status**: ❌ Not Fixed

### Issue 23: Missing Data Field Encryption/Decryption

**Specification Reference**: GP Card Spec v2.3.1, Section E.4.6
Command data field encryption for confidentiality

**Current Implementation**: No data field encryption support
**Expected Implementation**: Encrypt/decrypt command data fields
**Impact**: Confidentiality level not supported
**Status**: ❌ Not Fixed

### Issue 24: Missing Sensitive Data Encryption

**Specification Reference**: GP Card Spec v2.3.1, Section E.4.7
Sensitive data encryption using DEK session key

**Current Implementation**: No sensitive data encryption
**Expected Implementation**: Encrypt sensitive data with DEK
**Impact**: Key loading and sensitive operations not secure
**Status**: ❌ Not Fixed

### Issue 25: Missing Security Level Management

**Specification Reference**: GP Card Spec v2.3.1, Section E.1.5
Security level state management and transitions

**Current Implementation**: No security level management
**Expected Implementation**: Track and enforce security levels
**Impact**: Security state not properly managed
**Status**: ❌ Not Fixed

### Issue 26: Missing Card Life Cycle State Validation

**Specification Reference**: GP Card Spec v2.3.1, Table E-6
SCP02 command support per card life cycle state

**Current Implementation**: No life cycle state validation
**Expected Implementation**: Validate commands against card state
**Impact**: Commands may be accepted when they shouldn't be
**Status**: ❌ Not Fixed

## Implementation Priority

All issues are marked as HIGH priority due to the interconnected nature of SCP02 features. The protocol requires complete implementation rather than partial fixes to function correctly.

## Testing Requirements

- All test vectors must pass after fixes
- Emulator must generate proper diversification data
- All implementation parameters (i=04, i=05, i=15, i=1A, i=55) must be supported
- No regressions in SCP03 functionality

## Specification References

- **Primary**: GlobalPlatform Card Specification v2.3.1, Appendix E (SCP02)
- **Secondary**: GlobalPlatform Card Specification v2.3.1, Appendix B (Cryptographic Algorithms)
- **Test Vectors**: Located in `scripts/scp02_test_vectors.txt`

---

**Document Status**: Created during comprehensive SCP02 analysis
**Last Updated**: 2025-08-04
**Next Review**: After each phase completion