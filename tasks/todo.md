# Implementation Plan

## Status

| Item | Done |
|---|---|
| DID document struct defined in Solidity | ✅ |
| DID registry create function implemented | ✅ |
| DID registry store/read implemented | ✅ |
| DID registry update function implemented | ✅ |
| DID registry deactivate function implemented | ✅ |
| did:orcl:uuid identifier format implemented | ❌ |
| DID path implemented for SCHEMA object | ❌ |
| DID path implemented for CRED_DEF object | ❌ |

---

## Item 6 — did:orcl:uuid identifier format

**Source reference:** authzXcc.go:199 — only enforcement is non-empty string after TrimSpace.
**Decision:** Validate 3 colon-separated segments only (no method/UUID enforcement — matches chaincode).

### Changes

**contracts/didRegistrar.sol**
- Add `error InvalidDidFormat()`
- Add internal pure `_validateDid(string memory did)`:
  - Revert if empty
  - Iterate bytes and count colons — must equal exactly 2 (segments: did / method / id)
- Call `_validateDid(doc.id)` as first line of `createDid()`

**contracts/didController.sol**
- Call `_validateDid(doc.id)` as first line of `updateDid()`

---

## Item 7 — DID path for SCHEMA object

**Source reference:** schema.go:18-23 (struct fields), schema.go:52 (key format)
**Decision:** Separate `SchemaRegistry` contract. Key by `keccak256(abi.encode(issuerId, name, version))` to replicate chaincode uniqueness semantics.

### New file: contracts/SchemaRegistry.sol

**Struct** (from schema.go):
```
string id         — content-derived key (hex of keccak256)
string issuerId   — required non-empty  (ssi.URI in Go)
string name       — required non-empty
string version    — required non-empty
string[] attrNames — required, min 1 element
```

**Storage:**
```
mapping(bytes32 => Schema) internal schemas
mapping(string => uint256) public nonces   — keyed by issuerId
```

**Functions:**
- `publishSchema(string issuerId, string name, string version, string[] attrNames, bytes sig, address controller) returns (bytes32)`
  - Validate all fields
  - Check schema not already published (revert `SchemaAlreadyExists`)
  - Verify ECDSA sig: `keccak256(abi.encodePacked(issuerId, name, version, nonces[issuerId]))`
  - Store, increment nonce, emit `SchemaPublished`
- `getSchema(bytes32 id) returns (Schema memory)`
  - Revert `SchemaNotFound` if empty

**Events:** `SchemaPublished(bytes32 indexed id, string issuerId, string name, string version)`
**Errors:** `SchemaAlreadyExists()`, `SchemaNotFound()`, `InvalidSchema()`

---

## Item 8 — DID path for CRED_DEF object

**Source reference:** credentialDefinition.go:17-23 (struct), L82/L85 (validations), L114 (key format)
**Decision:** Separate `CredDefRegistry` contract. Key by `keccak256(abi.encode(issuerId, schemaId, tag))` — allows multiple CredDefs per schema, unique per issuer+schema+tag.

### New file: contracts/CredDefRegistry.sol

**Enum + Struct** (from credentialDefinition.go):
```
enum CredDefType { CL }   — default:"CL" in Go source

string id          — content-derived key
string issuerId    — required non-empty  (L82)
string schemaId    — required non-empty  (L85)
CredDefType credDefType  — CL only for now
string tag         — no validation in chaincode
bytes value        — CL public key material (map[string]any in Go → raw bytes in Solidity)
```

**Storage:**
```
mapping(bytes32 => CredDef) internal credDefs
mapping(string => uint256) public nonces   — keyed by issuerId
```

**Functions:**
- `publishCredDef(string issuerId, string schemaId, CredDefType credDefType, string tag, bytes value, bytes sig, address controller) returns (bytes32)`
  - Validate issuerId and schemaId non-empty
  - Check cred def not already published (revert `CredDefAlreadyExists`)
  - Verify ECDSA sig: `keccak256(abi.encodePacked(issuerId, schemaId, tag, nonces[issuerId]))`
  - Store, increment nonce, emit `CredDefPublished`
- `getCredDef(bytes32 id) returns (CredDef memory)`
  - Revert `CredDefNotFound` if empty

**Events:** `CredDefPublished(bytes32 indexed id, string issuerId, string schemaId, string tag)`
**Errors:** `CredDefAlreadyExists()`, `CredDefNotFound()`, `InvalidCredDef()`

---

## Files to create/modify

| File | Change |
|---|---|
| `contracts/didRegistrar.sol` | Add `_validateDid()`, call in `createDid()` |
| `contracts/didController.sol` | Call `_validateDid()` in `updateDid()` |
| `contracts/SchemaRegistry.sol` | New contract |
| `contracts/CredDefRegistry.sol` | New contract |
| `test/did/DIDRegistry.test.ts` | Add DID format validation tests |
| `test/schema/SchemaRegistry.test.ts` | New test file |
| `test/credDef/CredDefRegistry.test.ts` | New test file |

---

## Questions for user before implementing

1. Should `SchemaRegistry` and `CredDefRegistry` verify that the `issuerId` is a registered active DID in `didController` before publishing? (Cross-contract call to `getDidState()`)
2. Should all three contracts (`didController`, `SchemaRegistry`, `CredDefRegistry`) be deployed separately, or combined into one entry-point contract?
3. For the `value` field in CredDef — should callers pass raw JSON as `bytes`, or is there a known struct to ABI-encode?
