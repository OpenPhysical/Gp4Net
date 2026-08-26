# Gp4Net GlobalPlatform Conformity Review

**Status:** Living document  
**Baseline audit:** 2026-08-12 (full-library review vs Reference Library + repo specs)  
**Last re-verified:** 2026-08-12 against `HEAD` `30b8b5e` (branch `master`, ahead of `origin/master`)  
**Scope:** Host library + card emulator; no SCP10/SCP11/SCP04 implementation claimed  
**Primary specs:** GP Card Spec v2.3.1; SCP02 Appendix E; SCP03 Amendment D v1.1.1/v1.1.2  

This document tracks conformity findings from the full-library audit and their burn-down by subsequent commits. Re-verify open items after major protocol changes.

---

## Executive summary (current)

| Area | Original verdict | Current verdict |
|------|------------------|-----------------|
| SCP02/SCP03 mutual authentication | Largely compliant | **Compliant** (AES-128 proven; AES-192/256 cryptogram path fixed) |
| Host C-ENC / secure messaging | **Not conformant** | **Fixed** (encrypt order + counter; i-gated SCP02 ICV / modified APDU) |
| SCP02 S-RMAC (`0102`) | **Missing** | **Fixed** |
| Response unwrap dual paths | **Broken pipeline** | **Fixed** (pipeline uses `RemoveResponseSecurity`) |
| SET STATUS / STORE DATA / DELETE framing | **Broken** | **Fixed** |
| Privilege GET STATUS decode | **Wrong bit map** | **Fixed** (routes through `PrivilegeHelpers`) |
| Lifecycle model | **Collapsed card vs app** | **Mostly fixed** (domain split added; legacy enum residue remains) |
| Key Information Template | **Broken parse** | **Fixed** |
| INSTALL variants / params | Partial / wrong tags | **Largely fixed** |
| PUT KEY DES types | Non-spec `81`/`82` | **Fixed** (`80`) |
| Emulator ISD privileges / CPLC | Incomplete / malformed | **Still open** (partial progress elsewhere) |
| SCP10 / MANAGE CHANNEL builders | Missing | **Still missing** (out of product scope unless claimed) |

**Bottom line:** Critical secure-channel and Section 11 command framing findings from the baseline audit are largely burned down. Remaining work is lifecycle enum cleanup, emulator fidelity, optional GP surface area, and documentation/citation accuracy.

---

## Burn-down reference commits

Primary fix series (representative; not exhaustive):

| Commit | Theme |
|--------|--------|
| `114cb2e` | SCP02/SCP03 command protection (C-ENC) |
| `1c309ad` | SET STATUS / STORE DATA / DELETE framing |
| `83f7224` | Privilege decoding |
| `01ebde3` | Lifecycle domain split |
| `e2ff481` | Key information templates |
| `41ebe13` / `7b79787` / `87bf8b6` / `fca168e` | SCP i-parameter handling |
| `87ca123` / `e4363cf` / `6c73c02` | Response verify / generate / ENC symmetry |
| `4135c8c` | PUT KEY DES type `80` |
| `7f8af32` / `e3a6c91` | INSTALL params + variants |
| `0029d26` | GET STATUS continuation |
| `3cc11e7` / `5a09d7d` | R-MAC session framing |
| `3d27990` / `a7c7a0b` / `ae028a1` | PUT KEY / static DEK |
| `30b8b5e` / `3999be1` | DAP parse fail-closed; LFDB hash algs |

---

## Finding register

Statuses: **Fixed** · **Partial** · **Open** · **Won’t fix / out of scope** · **N/A (docs only)**

### Critical (baseline)

| ID | Finding | Spec | Status | Evidence / notes |
|----|---------|------|--------|------------------|
| SC-C1 | Host `ApplyCommandSecurity` never applied C-ENC | SCP03 6.2.6; SCP02 E.4.4–E.4.6 | **Fixed** | `ScpService.Security`: SCP03 encrypt-then-MAC with `commandCounter = EncryptionCounter + 1`; SCP02 MAC-then-encrypt when `HasCEncryption()` |
| SC-C2 | SCP02 S-RMAC reused S-MAC; `0102` unused | E.4.1 | **Fixed** | `KeyDerivation.DeriveScp02SessionKeysFromContext` derives `SrMac` with `KeyDerivationConstants.SrMac` |
| SC-C3 | Pipeline response unwrap broken (16-byte R-MAC, zero IV); dual crypto paths | SCP03 6.2.5–6.2.7 | **Fixed** | `CommandProcessors` calls `ScpService.Security.RemoveResponseSecurity`; host verify vs card `ApplyResponseSecurity` split |
| SC-C4 | `ProcessScp03ResponseSecurity` generated R-MAC as card | 6.2.5 | **Fixed** | Replaced by `ApplyResponseSecurity` (card/emulator) + `RemoveResponseSecurity` (host) |
| CMD-C1 | SET STATUS P1/P2 inverted | 11.10 | **Fixed** | `SetStatusCommand`: P1 = `80`/`40`, P2 = requested state |
| CMD-C2 | STORE DATA P1/P2 wrong | 11.11 | **Fixed** | Structure bits `08`/`10`/`60`; P1.b8 last; P2 = block number |
| CMD-C3 | DELETE object-only used P1=`80` | 11.2 | **Fixed** | `DeleteObjectOnly = 0x00`; related via P2 `0x80`; token under `9E` |
| MODEL-C1 | GET STATUS privilege bit map wrong | Tables 11-7…11-9 | **Fixed** | `Responses` / `TlvService` use `PrivilegeHelpers.ToList` |
| MODEL-C2 | Lifecycle collapsed card vs app (`Locked=0x7F` as app) | Tables 11-3…11-6 | **Partial** | New `GlobalPlatformLifecycle` + domain enums; legacy `Constants.GlobalPlatform.LifecycleState.Locked = 0x7F` and fixed switch parsers remain |

### High (baseline)

| ID | Finding | Spec | Status | Evidence / notes |
|----|---------|------|--------|------------------|
| SC-H1 | SCP03 encryption counter started at 0 used as first IV | 6.2.6 start **1** | **Fixed** | State stores last-used counter (0 before first cmd); apply path uses `+1` for first command |
| SC-H2 | SCP02 ICV encryption always on | Table E-1 b5 | **Fixed** | Gated on `HasIcvEncryption()` + EXTERNAL AUTH exception |
| SC-H3 | SCP02 always modified APDU | Table E-1 b2 | **Fixed** | `GetMacInput(modifyHeader: implementation.UsesModifiedApdu())` |
| SC-H4 | Host challenge via `Random.Shared` | Mutual auth | **Fixed** | `CryptoService.Rng.GenerateHostChallenge` → BouncyCastle `SecureRandom` |
| SC-H5 | AES-192/256 cryptogram rejected non-16 S-MAC | 6.2.1–6.2.2 | **Fixed** | `Scp03.CalculateCryptogram` accepts 16/24/32 |
| CMD-H1 | INSTALL variants missing | 11.5 | **Fixed** | Extradition, personalization, registry update, make selectable, load+install+selectable |
| CMD-H2 | INSTALL empty params omit `C9`; load used illegal `C9` | 11.5.2 | **Fixed** | Mandatory `C9` (incl. empty); load params corrected |
| CMD-H3 | PUT KEY DES types `81`/`82` | Table 11-16 | **Fixed** | `TripleDes2Key`/`TripleDes3Key` wire as `0x80` |
| CMD-H4 | GET STATUS no get-next; deprecated default P2 | 11.4 | **Partial** | `ResponseFormat.Next = 0x01` present; service prefers TLV; legacy format still limited |
| CMD-H5 | LOAD no DAP/ciphered; extended APDU | 11.6 / 11.1.5 | **Partial** | DAP parse fail-closed (`30b8b5e`); plain C4 load OK; `CreateFromCapFileExtended` still allows long blocks; ciphered `D3`/`D4` not fully productized |
| MODEL-H1 | Key Info type/length broken | 11.28 / 11.16 | **Fixed** | `KeyInfoTemplateCodec` + type/length components; ECC types present |
| MODEL-H2 | Emulator ISD default privileges incomplete | §6.6.2 | **Open** | Still `SecurityDomain \| AuthorizedManagement` only |

### Medium / Low (selected)

| ID | Finding | Status | Notes |
|----|---------|--------|-------|
| SC-M1 | SCP03 “i” mapped to AES key length | **Fixed** | Table 5-1 semantics; `Scp03I10/20/30/60/70` comments corrected; `GetAesKeyLength` removed |
| SC-M2 | SCP02 i comments inverted | **Fixed** | `ScpImplementation` comments align with Table E-1 |
| SC-M6 | S-DEK constant `0x08` RFU in v1.1.1 | **Partial** | Session DEK correctly not derived for SCP03; validator may still allow RFU labels in KDF helper |
| CMD-M3 | BEGIN R-MAC missing LV | **Fixed** | Length byte prepended in `BeginRMacSessionCommand` |
| MODEL-R2 | SCP OID “i” labels folklore | **Open** | Review if still mislabeled in `GlobalPlatformOids` |
| CPLC-C1 | Cited as GP Card Spec E.1.1 | **Open** | Industry object; comment still claims GP E.1.1 in `CardInformationGatherer` |
| CPLC-C3 | Emulator default CPLC malformed | **Open** | Re-check emulator payload layout |
| D-1 | `SecurityDomainInfoCodec` tag confusion | **Fixed** | Now sequence counter `C1` codec |
| CAP-M9 | `CapFileLoadingWorkflow` stub | **Open** | Still `NotImplemented` after WSCT migration note |
| GP-X1 | MANAGE CHANNEL builder | **Open / out of scope** | INS only |
| GP-X2 | SCP10 suite | **Out of scope** | Spec present; no product claim |
| CONST-L1 | `INSTALL_FOR_INSTALL = 0x0C` mislabel | **Open (nit)** | Value is install+make selectable; pure install is `0x04` |
| CONST-L2 | Legacy `LifecycleStates` comments wrong | **Open (nit)** | LOADED/INSTALLED comment text still imprecise |
| CONST-L3 | `Privileges` const class only byte 1 | **Open (nit)** | Full flags live in `Privilege` enum |
| PARSE-L1 | `ParseLifecycleState` fixed values + maps Locked→enum `0x7F` | **Partial** | Registry validation uses `IsRegistryState`; display enum still conflates |

---

## Command coverage matrix (current)

| Command | Baseline | Current |
|---------|----------|---------|
| SELECT | Good | Good |
| INITIALIZE UPDATE | Good | Good |
| EXTERNAL AUTHENTICATE | Fair | Good |
| GET DATA | Fair | Fair |
| GET STATUS | Fair | Good–Fair |
| INSTALL | Fair–Poor | Good (variants present) |
| LOAD | Fair | Fair–Good |
| DELETE | Poor | Good |
| PUT KEY | Fair | Good (symmetric SCP) |
| SET STATUS | **Fail** | Good |
| STORE DATA | **Fail** | Good |
| BEGIN/END R-MAC | Fair | Good |
| MANAGE CHANNEL | Missing | Missing |
| GET SERVICE / SCP10 | Missing | Missing |

---

## Secure channel coverage (current)

```
SCP02
  Key derivation 0182/0101/0181 .... COMPLIANT
  Key derivation 0102 S-RMAC ....... COMPLIANT (fixed)
  Cryptograms ...................... COMPLIANT
  C-MAC modified / unmodified ...... COMPLIANT (i-gated)
  ICV encryption ................... COMPLIANT (i-gated)
  C-ENC host apply ................. COMPLIANT (fixed)
  R-MAC host verify ................ COMPLIANT (uses S-RMAC)

SCP03
  KDF 800-108 / labels ............. COMPLIANT
  Cryptograms 00/01 ................ COMPLIANT (16/24/32)
  C-MAC chain 16 / wire 8 .......... COMPLIANT
  C-ENC order + counter ............ COMPLIANT (fixed)
  R-MAC / R-ENC host path .......... COMPLIANT (unified remove path)
  Static DEK PUT KEY ............... COMPLIANT
  i Table 5-1 modeling ............. COMPLIANT
```

---

## Remaining priority backlog

1. **Finish lifecycle migration** — retire or clearly mark legacy `Constants.GlobalPlatform.LifecycleState` (`Locked=0x7F`); make parsers emit domain-specific types / preserve wire bytes.
2. **Emulator GP fidelity** — ISD default privileges (§6.6.2), card lifecycle transitions, conformant CPLC body.
3. **LOAD product gaps** — ciphered LFDB; keep short-Lc path primary; wire DAP into LOAD stream builders if needed beyond parse.
4. **CapFileLoadingWorkflow** — complete or remove stub.
5. **Citation cleanup** — CPLC is not Card Spec E.1.1; OID i-value descriptions; `INSTALL_FOR_INSTALL` naming.
6. **Optional surface** — MANAGE CHANNEL, GET DATA `2F00` case-3, SCP10 only if product requires.

---

## Spec inventory used

| Document | Location |
|----------|----------|
| GP Card Specification v2.3.1 | `~/Documents/Reference Library/01_Standards/Smart_Card_Standards/Specifications/` + `docs/` |
| SCP03 Protocol / Amd D | Reference Library `Protocols/2023_GlobalPlatform_SCP03_Protocol_v1.1.2.pdf`; `docs/GPC_2.2_D_*`, `docs/GPC_2.3_D_*` |
| SCP02 | Card Spec Appendix E; `docs/SCP02_specification.md` |
| SCP10 | Reference Library (not implemented) |
| Parsed text | `docs/parsed/` |

---

## How to re-verify

```bash
# Spot-check critical secure messaging
rg -n "ApplyCommandEncryption|HasIcvEncryption|UsesModifiedApdu" src/Gp4Net/Services/ScpService.Security.cs
rg -n "SrMac|0x01, 0x02" src/Gp4Net/Cryptography/CryptoService.KeyDerivation.cs
rg -n "RemoveResponseSecurity" src/Gp4Net/Pipeline/CommandProcessors.cs

# Spot-check command framing
rg -n "statusType|stateControl" src/Gp4Net/Domain/Commands/SetStatusCommand.cs
rg -n "BlockNumber|DataStructureFormat" src/Gp4Net/Domain/Commands/StoreDataCommand.cs
rg -n "DeleteObjectOnly|0x9E" src/Gp4Net/Domain/Commands/DeleteCommand.cs

# Privilege decode
rg -n "PrivilegeHelpers.ToList" src/Gp4Net/Services

# Targeted tests
dotnet test --filter "FullyQualifiedName~Scp|FullyQualifiedName~PutKey|FullyQualifiedName~GetStatus|FullyQualifiedName~Install"
```

---

## Change log

| Date | Change |
|------|--------|
| 2026-08-12 | Baseline full-library conformity audit (chat + subagent deep dives) |
| 2026-08-12 | Re-verified against `30b8b5e`; marked burn-down Fixed/Partial/Open; wrote this artifact |
