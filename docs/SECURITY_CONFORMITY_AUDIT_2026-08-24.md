# Gp4Net Security and Conformity Audit

**Audit date:** 2026-08-24  
**Target:** current `Gp4Net` working tree  
**Product claims reviewed:** GlobalPlatform Card Specification 2.3.1; SCP02; SCP03 v1.1.2; CAP validation/loading; host library, CLI, and virtual-card emulator

## Executive summary

The four findings selected for remediation are implemented. Literal command-line secret keys remain accepted by explicit decision. The final solution test run passed 1,142 tests, and the current NuGet advisory scan reported no vulnerable direct or transitive packages.

This audit found **five actionable issues**: two High and three Medium. The most important operational issue is that ordinary secure-channel flows silently choose public GlobalPlatform test keys when key material is omitted. The most important conformity issue is that the emulator accepts DELETE tokens without verification and even recognizes the wrong token tag.

| ID | Severity | Finding |
|---|---:|---|
| GP-AUD-001 | High | Secure-channel operations silently default to public test keys; the safety validator is not connected |
| GP-AUD-002 | High | Emulator DELETE token handling is non-conformant and does not authenticate delegated deletion |
| GP-AUD-003 | Medium | CAP and metadata parsing has no decompression or document-size limits |
| GP-AUD-004 | Medium | Secret keys are accepted directly on the command line |
| GP-AUD-005 | Medium | Advertised applet listing command is registered but always fails |

## Remediation status

- **GP-AUD-001 remediated:** implicit public GP test keys now produce one prominent stderr warning before secure-channel establishment. Explicit keys and named keysets do not trigger it.
- **GP-AUD-002 remediated for emulator-supported AES:** DELETE uses tag `9E`, verifies AES-CMAC tokens in fixed time, rejects malformed or unexpected data before mutation, generates AES-CMAC receipts, and persists a non-wrapping 16-bit confirmation counter. Unsupported schemes are not advertised.
- **GP-AUD-003 remediated:** public immutable `CapParsingLimits` defaults enforce archive, entry, expansion, compression-ratio, manifest, and XML limits. XML parsing prohibits DTDs and external resolution.
- **GP-AUD-004 accepted:** literal secret-key command-line options remain supported by product decision.
- **GP-AUD-005 remediated:** `applet list` uses the pipeline secure channel and complete GET STATUS retrieval, including `6310` continuation, ISD/apps/SSD/packages filters, and table/JSON/CSV rendering.

## Hardware and emulator parity verification

Testing on an NXP P71D321 JCOP4 card through an OMNIKEY 5022 reader exposed gaps that isolated emulator and command tests had missed: recursive CLI activation, unprotected post-authentication commands, selection changes during DELETE, ZIP bytes sent instead of the expanded CAP component stream, and unescaped console markup. With GP test keys, gp4net now lists card content, deletes the OpenFIPS201 package, reinstalls it from its CAP, and independently agrees with GlobalPlatformPro inventory.

The primary emulator blind spot was architectural: it accepted the host-side ZIP archive at the card LOAD boundary, while a physical card accepts a `C4` Load File Data Block containing the ordered, expanded CAP components. Tests also invoked processors below the complete CLI and secure-channel composition seams. The gap is closed with strict `C4` validation, raw component-stream parsing, a real OpenFIPS CAP parity fixture, explicit automatic-wrapping coverage, and CLI activation tests. The same OpenFIPS install now succeeds end to end on both the physical card and emulator.

Additional interoperability testing used official PivApplet, FIDO2Applet, and SmartPGP release CAPs. It found and fixed a fixture-specific emulator check that hard-coded OpenFIPS's CAP header length, unsafe JSON serialization of empty `Maybe` values, and placeholder `applet instantiate` and `applet load` implementations. All three third-party CAPs validate and install in the emulator, and the FIDO2 CAP was exercised through the completed `applet load` command. FIDO2 was loaded and instantiated with official custom CBOR parameters on JCOP4, and SmartPGP was installed on JCOP4.

AES delegated LOAD is implemented against GlobalPlatform v2.3.1 Appendix C: SHA-256 LFDBH, AES-CMAC Load Tokens, optional AES DAP blocks, strict confirmations, AES-CMAC Load Receipts, and atomic confirmation-counter updates. Emulator tests use a real OpenFIPS CAP and prove that invalid DAP authentication clears pending state without registry or counter mutation. DES, RSA, ECC, and delegated install/make-selectable operations remain explicitly unsupported.

Hardware validation on an NXP P71D321/JCOP4 GP 2.2.3 card proved SCP02 authentication, a 53-block ordinary LOAD, combined install/make-selectable with explicit application parameters, registry listing, and DELETE. The card received the complete AES delegated INSTALL [for load] fields and rejected an ISD-targeted request with `6A80`, as expected without a provisioned delegated Security Domain. A successful receipt-bearing delegated LOAD still requires a card with a provisioned SSD and matching AES token/receipt keys. Hardware-derived semantic APDUs are retained in `tests/TestData/Hardware/jcop4-p71d321-gp223.json`.

The hardware run exposed additional CLI parity gaps that emulator-only tests did not reveal: a duplicate implicit-test-key warning after successful LOAD, comma-separated privilege syntax rejected despite the documented option contract, duplicated `0x` status-word formatting, optional GET DATA failures being parsed as hexadecimal display text, and diagnostic logging corrupting JSON/CSV stdout. These are fixed. Diagnostics now use stderr and debug APDU logging is opt-in.

The registry was expanded until JCOP4 returned `6310` during GET STATUS with an `E3/4F` TLV split across response pages. gp4net correctly issued the next-occurrence command with `P2=03`, concatenated response data before BER parsing, and recovered the SmartPGP load-file/module/SD association. The exact pages are executable regression coverage in `ApplicationsGetStatusTests` and retained in the hardware corpus.

A real supplementary Security Domain was created from JCOP4's built-in SSD module with Delegated Management privilege. AES token-verification key version `0x70` and receipt-generation key version `0x71` were provisioned. Hardware comparison then exposed and corrected an LFDBH defect: `Descriptor.cap` had incorrectly been included in the loadable component stream. FIDO2's corrected SHA-256 changed from `E13495...` to `21532C...`, matching GPPro and the card; an ordinary 146-block gp4net load then succeeded. Delegated INSTALL still returns `6985` on this card after the correction. Its mandatory ISD confirmation identity objects (`42`/`45`) are absent and cannot be set through the tested STORE DATA or PUT DATA paths, leaving card policy/provisioning as the likely blocker to a successful receipt-bearing operation.

## Findings

### GP-AUD-001: Secure-channel operations silently default to public test keys

**Severity:** High  
**Affected components:** CLI secure-channel pipeline, card info, keyset parser  
**CWE:** CWE-1392, Use of Default Credentials

When no explicit keys or named keyset are supplied, `EstablishFromRequestAsync` calls `EstablishWithDefaultKeysetAsync`, which hard-codes `gp_test_keys`. `KeysetParser` independently treats an empty specification as the public GP test key. These paths are reachable from installation, deletion, key change, ISD data, and other management commands.

The repository contains an `EnvironmentValidation` service intended to prevent test keys from being paired with production cards, but its `ValidateEnvironmentAsync` entry point has no production callers. It therefore does not mitigate the default.

**Impact:** A user who omits key arguments can unknowingly authenticate to a card still provisioned with public test keys and perform destructive management operations. The implicit fallback also hides unsafe card provisioning instead of forcing explicit acknowledgement.

**Evidence:**

- `src/Gp4Net.Tool/Pipeline/SecureChannelOperations.cs:29-70`
- `src/Gp4Net.Tool/Pipeline/SecureChannelOperations.cs:142-156`
- `src/Gp4Net.Tool/Commands/Common/KeysetParser.cs:29-59`
- `src/Gp4Net.Tool/Services/EnvironmentValidation.cs:103-162`

**Recommendation:** Fail closed when neither explicit key material nor a named key source is supplied. Permit test keys only through an explicit `--allow-test-keys` option restricted to virtual readers or an affirmative interactive confirmation. Connect environment validation before INITIALIZE UPDATE and treat unknown card provenance as unsafe, not as permission to continue.

### GP-AUD-002: Emulator DELETE token handling is non-conformant

**Severity:** High  
**Affected component:** virtual-card emulator  
**Specification:** GlobalPlatform Card Specification v2.3.1, DELETE command section 11.2, especially Tables 11-23 through 11-26 and delegated-management token/receipt processing

The emulator mutates card state for every `4F` object identifier and reports success while:

1. recognizing `D3` as a deletion token, although the DELETE command builder and Card Specification encode the Delete Token as data object `9E`;
2. explicitly accepting any purported token without cryptographic verification;
3. ignoring unknown and invalid TLVs rather than rejecting malformed security-relevant input; and
4. returning a successful receipt placeholder regardless of whether delegated-management verification occurred.

**Impact:** Emulator tests can pass flows that a conforming card must reject. This is security-significant for software validated against the emulator because delegated deletion authorization and receipt behavior are not exercised.

**Evidence:**

- `src/Gp4Net.CardEmulator/Core/VirtualCard.cs:1027-1115`
- `src/Gp4Net.CardEmulator/Core/VirtualCard.cs:1120-1135`
- `src/Gp4Net.CardEmulator/Core/VirtualCard.cs:1746-1790`
- `src/Gp4Net/Domain/Commands/DeleteCommand.cs:179-275`

**Recommendation:** Parse `9E` as the Delete Token, reject disallowed/invalid TLVs, verify the token with the controlling Security Domain's configured verification key, enforce the delegated-management privilege model, and generate or validate receipts exactly as required. If delegated management is intentionally unsupported, fail with an appropriate status word whenever a token or receipt path is requested.

### GP-AUD-003: CAP and metadata parsing has no resource limits

**Severity:** Medium  
**Affected components:** CAP library and `applet validate` CLI  
**CWE:** CWE-409, Improper Handling of Highly Compressed Data

CAP parsing iterates every ZIP entry and copies recognized components fully into memory without limits on archive size, entry size, total expanded bytes, entry count, or compression ratio. Manifest and `javacard.xml` metadata are likewise read without character limits.

**Impact:** A crafted CAP/JAR can consume excessive memory or CPU during local validation or loading, causing denial of service in CLI, CI, or services embedding the library.

**Evidence:**

- `src/Gp4Net/Domain/CapFile/CapFileStructure.cs:120-308`
- `src/Gp4Net.Tool/Commands/Applet/ValidateCliCommand.cs:1451-1575`

**Recommendation:** Apply a configurable maximum input size, entry count, per-entry expanded size, total expanded size, and compression ratio before copying data. Parse XML through a configured `XmlReader` with DTD prohibited and `MaxCharactersInDocument` set. Stop reading streams once the applicable limit is exceeded.

### GP-AUD-004: Secret keys are accepted directly on the command line

**Severity:** Medium  
**Affected component:** CLI  
**CWE:** CWE-214, Invocation of Process Using Visible Sensitive Information

The CLI accepts ENC, MAC, DEK, and full keysets as hexadecimal command-line arguments. Command lines commonly persist in shell history and may be visible to same-host process inspection, terminal recording, CI logs, and crash diagnostics.

**Evidence:**

- `src/Gp4Net.Tool/Commands/BaseCommandSettings.cs:18-34`
- `src/Gp4Net.Tool/Commands/StandardCommandSettings.cs:104-106`
- `src/Gp4Net.Tool/Commands/Card/InfoCommand.cs:528-530`

**Recommendation:** Support protected key sources such as environment-variable names, permission-checked files, standard input, or OS secret stores. Keep literal key flags only behind an explicit insecure-development option and warn before use. Redact key-shaped values from logs and exception rendering.

### GP-AUD-005: Advertised applet listing command always fails

**Severity:** Medium  
**Affected component:** CLI  
**Specification:** GlobalPlatform Card Specification v2.3.1, GET STATUS command section 11.4

The README advertises applet listing, and the command catalog registers `gp4net applet list`. Its public `ExecuteAsync` implementation unconditionally prints that application listing is not implemented and exits with status 1. Unreachable private methods are also placeholders.

**Impact:** A documented core management capability is unavailable despite the library already containing GET STATUS construction, continuation, and response parsing. Operators may incorrectly infer that an empty or failed inventory represents card state.

**Evidence:**

- `README.md:18-23`
- `src/Gp4Net.Tool/Commands/Applet/ListCliCommand.cs:20-74`
- `src/Gp4Net.Tool/Infrastructure/CommandRegistrationExtensions.cs:150-198`

**Recommendation:** Wire the command to `Applications.GetAllStatusDataAsync` and the existing response conversion path, including `6310` continuation via GET STATUS `P2=01`. Until implemented, remove the capability claim and command registration.

## Re-verified areas

- SCP02 and SCP03 host challenges use the cryptographic RNG abstraction.
- SCP02/SCP03 command and response MAC comparisons use fixed-time comparison in the active security paths.
- SCP02 S-RMAC derivation and SCP03 response-security paths have focused regression tests.
- INITIALIZE UPDATE parsing now enforces exact SCP02 and SCP03 response lengths.
- ISD initial privileges now include the complete privilege set expected by GlobalPlatform 2.3.1 section 6.6.2.
- Current NuGet advisory lookup found no vulnerable packages.

These statements are code-review conclusions, not a GlobalPlatform certification or proof of complete protocol conformance.

## Verification evidence

```text
dotnet test Gp4Net.sln --no-restore --nologo
Result (2026-08-26): 1,154 passed, 0 failed, 0 warnings, 3 test projects

dotnet list Gp4Net.sln package --vulnerable --include-transitive
Result: no vulnerable packages in all six projects
```

Destructive validation was performed on a disposable NXP P71D321/JCOP4 card using
SCP02 and public GP test keys. Captured vectors cover secure-channel derivation,
ordinary LOAD/INSTALL/DELETE, install parameters, delegated-policy failures, and a
real `6310` GET STATUS continuation whose page boundary split an `E3/4F` TLV.
The emulator now fails delegated LOAD with `6985` when the Receipt Generation SD
has no usable receipt key, matching GP 2.3.1 C.1.1.2 and the observed hardware.
Focused tests also force emulator GET STATUS pagination and continuation.

The hardware-driven remediation added gp4net library and CLI support for creating
supplementary Security Domains, ordinary AES-DAP loading, and application
extradition. Gp4net created delegated SSD `A0000001515350D7` on the disposable
JCOP4 and GET STATUS confirmed its privileges and ISD association. Extradition
matched the GP Table 11-45 APDU but the card returned policy status `6985`.

AES-DAP validation found and fixed two emulator/test gaps: `Descriptor.cap` was
incorrectly included in the loadable stream, and the CLI's 255-byte default left
no room for SCP02 C-MAC. The corrected FIDO2 LFDBH is `21532C...`, the CLI now
uses 245-byte blocks, and gp4net and GlobalPlatformPro independently emit the
same AES DAP CMAC/block and receive the same card-policy `6985`. This verifies
wire parity while leaving D4 provisioning/card policy as an explicit unresolved
hardware limitation.

Hardware evidence improves interoperability confidence but is not GlobalPlatform
certification or proof against every supported card profile.

## Specification baseline

| Specification | Library status | Audit use |
|---|---|---|
| GlobalPlatform Card Specification v2.3.1 | Present | Primary card-management and SCP02 baseline |
| GlobalPlatform SCP03 Protocol v1.1.2 | Present | SCP03 establishment and secure messaging |
| ISO/IEC 7816-4:2020 | Present | APDU and interindustry command structure |
| Java Card 3.0.5 VM/CAP specifications | Present | CAP structure baseline |

No required core specification was missing for this audit. SCP10 is present but was excluded because Gp4Net does not claim SCP10 support.

## Priority remediation order

1. Remove implicit public test-key fallback and connect the safety gate.
2. Make DELETE delegated-management handling fail closed or fully implement verification.
3. Add CAP/JAR/XML resource limits.
4. Add protected key-input mechanisms.
5. Implement or withdraw the applet-list command and claim.
