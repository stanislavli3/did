// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

// PUBLIC KEY FORMAT DECISION (Issue 4)
// Secp256k1 uncompressed public key = 04 || x (32 bytes) || y (32 bytes) = 65 bytes total
// OR: strip the 04 prefix → store as raw x||y = 64 bytes
// DECISION: store as 64 bytes (strip prefix) — validated on input: pubKey.length == 64
// Rationale: prefix is constant (always 04 for uncompressed), stripping saves 1 byte of calldata
//            and simplifies equality checks. Prefix is re-added by off-chain resolver if needed.
// If OBP runtime requires a different format, update this comment and the validation in createDID.
struct DIDDocument {
    // SLOT 0: controller (20 bytes) + active (1 byte) + created (8 bytes) = 29 bytes → fits slot 0
    address controller; // 20 bytes
    bool active; // 1 byte  — packed with controller
    uint64 created; // 8 bytes — packed with controller + active
    // SLOT 1: updated (8 bytes) — own slot because slot 0 is full (29 bytes used, only 3 remain)
    uint64 updated; // 8 bytes
    // SLOT 2+: dynamic types always get their own slots
    bytes publicKey; // 64 bytes for Secp256k1 uncompressed — stored as dynamic bytes
    string serviceEndpoint;
}

contract DIDRegistry is AccessControl, Ownable2Step, ReentrancyGuard {
    // ─────────────────────────────────────────────────────────────────────────
    // Roles
    // ─────────────────────────────────────────────────────────────────────────

    bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    // ─────────────────────────────────────────────────────────────────────────
    // Constants & immutables
    // ─────────────────────────────────────────────────────────────────────────

    string public constant DID_METHOD = "did:example";
    uint256 public immutable DEPLOYED_AT; // set to block.timestamp in constructor

    // ─────────────────────────────────────────────────────────────────────────
    // Storage
    // ─────────────────────────────────────────────────────────────────────────

    mapping(string => DIDDocument) private _documents;
    mapping(string => bool) private _exists;

    // ─────────────────────────────────────────────────────────────────────────
    // Errors
    // ─────────────────────────────────────────────────────────────────────────

    error DIDRegistry__EmptyDID();
    error DIDRegistry__AlreadyExists(string did);
    error DIDRegistry__NotFound(string did);
    error DIDRegistry__Unauthorized(address caller, string did);
    error DIDRegistry__Deactivated(string did);
    error DIDRegistry__InvalidPublicKey(uint256 length, uint256 expected);
    error DIDRegistry__ZeroAddress();

    // ─────────────────────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────────────────────

    event DIDCreated(string indexed did, address indexed controller, uint64 timestamp);
    event DIDUpdated(string indexed did, address indexed controller, uint64 timestamp);
    event DIDDeactivated(string indexed did, address indexed controller, uint64 timestamp);

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────

    constructor(address initialRegistrar) Ownable(msg.sender) {
        if (initialRegistrar == address(0)) revert DIDRegistry__ZeroAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(REGISTRAR_ROLE, initialRegistrar);
        DEPLOYED_AT = block.timestamp;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Functions
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Creates a new DID document on-chain
    /// @dev    Only callable by an account holding REGISTRAR_ROLE.
    ///         Reverts with DIDRegistry__EmptyDID if did is an empty string.
    ///         Reverts with DIDRegistry__AlreadyExists if a document for this DID already exists.
    ///         Reverts with DIDRegistry__InvalidPublicKey if pubKey.length != 64.
    ///         Emits DIDCreated(did, msg.sender, block.timestamp) on success.
    ///         CEI: checks (validate inputs, check existence) → effects (write to _documents, _exists)
    ///         → interactions (emit event). No external calls are made.
    /// @param did      The DID string identifier (e.g. "did:example:abc123")
    /// @param pubKey   64-byte raw Secp256k1 public key (x||y, no 04 prefix; see format decision comment)
    /// @param endpoint Service endpoint URI — empty string is valid and means no endpoint
    function createDID(
        string calldata did,
        bytes calldata pubKey,
        string calldata endpoint
    ) external onlyRole(REGISTRAR_ROLE) nonReentrant {}

    /// @notice Resolves a DID to its current document
    /// @dev    Read-only (view). Safe to call from any address with no access restriction.
    ///         Reverts with DIDRegistry__NotFound if DID has never been registered.
    ///         Reverts with DIDRegistry__Deactivated if DID was deactivated — callers must handle
    ///         the deactivated case separately; a deactivated DID is not the same as not found.
    /// @param  did The DID string to resolve
    /// @return     The DIDDocument struct as stored on-chain (all fields, including publicKey bytes)
    function resolveDID(string calldata did) external view returns (DIDDocument memory) {}

    /// @notice Updates the public key and service endpoint of an existing, active DID
    /// @dev    Only callable by the DID's original controller (msg.sender must equal document.controller).
    ///         Reverts with DIDRegistry__NotFound if DID does not exist.
    ///         Reverts with DIDRegistry__Deactivated if DID has been deactivated.
    ///         Reverts with DIDRegistry__Unauthorized if caller is not the controller.
    ///         Reverts with DIDRegistry__InvalidPublicKey if newPubKey.length != 64.
    ///         Emits DIDUpdated(did, msg.sender, block.timestamp) on success.
    ///         CEI: checks (validate, lookup) → effects (write fields + updated timestamp)
    ///         → interactions (emit event). No external calls are made.
    /// @param  did         The DID string identifier to update
    /// @param  newPubKey   New 64-byte raw Secp256k1 public key (x||y, no 04 prefix)
    /// @param  newEndpoint New service endpoint URI (empty string is valid — clears the endpoint)
    function updateDID(
        string calldata did,
        bytes calldata newPubKey,
        string calldata newEndpoint
    ) external nonReentrant {}

    /// @notice Deactivates a DID, making it permanently unresolvable
    /// @dev    Callable by the DID controller OR any account holding ADMIN_ROLE.
    ///         Reverts with DIDRegistry__NotFound if DID does not exist.
    ///         Reverts with DIDRegistry__Deactivated if DID is already deactivated (idempotent guard).
    ///         Reverts with DIDRegistry__Unauthorized if caller is neither the controller nor ADMIN_ROLE.
    ///         Emits DIDDeactivated(did, document.controller, block.timestamp) on success.
    ///         CEI: checks (lookup, authorization) → effects (set active = false, write updated)
    ///         → interactions (emit event). No external calls are made.
    ///         NOTE: Deactivation is irreversible in V1 — there is no reactivation function.
    /// @param did The DID string to deactivate
    function deactivateDID(string calldata did) external nonReentrant {}
}
