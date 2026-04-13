// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./didCore.sol";
import "./signatureVerifier.sol";
import "./interfaces/IDidRegistry.sol";
import "./interfaces/ICredDefRegistry.sol";

/// @title RevocationRegistry
/// @notice On-chain registry for AnonCreds revocation registry definitions and
///         revocation status lists.
///         Mirrors the RevRegDefReceiver / RevStatusListReceiver boundaries from
///         the Fabric chaincode (pkg/acr/revocationRegistryDefinition.go,
///         pkg/acr/revocationStatusList.go).
///
/// RevRegDef uniqueness:  keccak256(abi.encode(issuerId, credDefId, tag))
/// RevStatusList:         one per RevRegDef, created and updated in place.
/// Authorization:         issuerId must be an Active DID; credDefId must exist.
/// Replay protection:     nonce per issuerId.
contract RevocationRegistry {

    // ── types ─────────────────────────────────────────────────────────────────

    /// @dev Mirrors RevRegDefValue in the Fabric chaincode.
    ///      tailsLocation: URI pointing to the tails file (for holder witness updates).
    ///      tailsHash:     SHA-256 hex digest of the tails file (integrity check).
    ///      maxCredNum:    maximum number of credentials this registry can hold.
    struct RevRegDefValue {
        string tailsLocation;
        string tailsHash;
        uint32 maxCredNum;
    }

    /// @dev Mirrors RevRegDef in the Fabric chaincode.
    ///      revocDefType is always "CL_ACCUM" for AnonCreds CL credentials.
    struct RevRegDef {
        bytes32        id;
        string         issuerId;
        string         revocDefType;
        bytes32        credDefId;
        string         tag;
        RevRegDefValue value;
    }

    /// @dev Mirrors RevStatusList in the Fabric chaincode.
    ///      revocationList: packed bitfield — bit i = 1 means credential index i is revoked.
    ///      currentAccumulator: opaque bytes for the BN254/RSA accumulator value.
    struct RevStatusList {
        bytes32 revRegId;
        uint256 timestamp;
        bytes   currentAccumulator;
        bytes   revocationList;
    }

    // ── storage ───────────────────────────────────────────────────────────────

    mapping(bytes32 => RevRegDef)     internal revRegDefs;
    mapping(bytes32 => RevStatusList) internal revStatusLists;
    mapping(string  => uint256)       public   nonces;

    IDidRegistry    public immutable didRegistry;
    ICredDefRegistry public immutable credDefRegistry;

    // ── events ────────────────────────────────────────────────────────────────

    event RevRegDefCreated(
        bytes32 indexed id,
        string  issuerId,
        bytes32 indexed credDefId,
        string  tag
    );

    event RevStatusListUpdated(
        bytes32 indexed revRegId,
        uint256 timestamp
    );

    // ── errors ────────────────────────────────────────────────────────────────

    error RevRegDefAlreadyExists();
    error RevRegDefNotFound();
    error RevStatusListNotFound();
    error InvalidRevRegDef();
    error IssuerNotActive();
    error CredDefNotFound();
    error KeyCollision();

    // ── constructor ───────────────────────────────────────────────────────────

    constructor(address _didRegistry, address _credDefRegistry) {
        didRegistry    = IDidRegistry(_didRegistry);
        credDefRegistry = ICredDefRegistry(_credDefRegistry);
    }

    // ── write ─────────────────────────────────────────────────────────────────

    /// @notice Create a new revocation registry definition.
    /// @param issuerId      DID of the issuer — must be Active in the DID registry.
    /// @param credDefId     bytes32 key of the credential definition being revoked.
    /// @param tag           Disambiguates multiple revocation registries per cred def.
    /// @param value         Tails file metadata and max credential count.
    /// @param signature     ECDSA signature over keccak256(issuerId ‖ credDefId ‖ tag ‖ nonce).
    /// @param controller    EVM address that produced the signature.
    /// @return id  Deterministic bytes32 key: keccak256(abi.encode(issuerId, credDefId, tag)).
    function createRevRegDef(
        string         calldata issuerId,
        bytes32                 credDefId,
        string         calldata tag,
        RevRegDefValue calldata value,
        bytes          calldata signature,
        address                 controller
    ) external returns (bytes32 id) {
        // ── validation ────────────────────────────────────────────────────────
        if (bytes(issuerId).length == 0 || bytes(value.tailsLocation).length == 0)
            revert InvalidRevRegDef();

        // ── cross-contract: issuer DID must be Active ─────────────────────────
        if (didRegistry.getDidState(issuerId) != DidState.Active) revert IssuerNotActive();

        // ── cross-contract: referenced cred def must exist ────────────────────
        if (!credDefRegistry.credDefExists(credDefId)) revert CredDefNotFound();

        // ── uniqueness ────────────────────────────────────────────────────────
        id = keccak256(abi.encode(issuerId, credDefId, tag));
        if (bytes(revRegDefs[id].issuerId).length != 0) {
            if (
                keccak256(bytes(revRegDefs[id].issuerId)) != keccak256(bytes(issuerId)) ||
                revRegDefs[id].credDefId                  != credDefId                  ||
                keccak256(bytes(revRegDefs[id].tag))      != keccak256(bytes(tag))
            ) revert KeyCollision();
            revert RevRegDefAlreadyExists();
        }

        // ── signature verification ────────────────────────────────────────────
        bytes32 payloadHash = keccak256(
            abi.encodePacked(issuerId, credDefId, tag, nonces[issuerId])
        );
        require(
            SignatureVerifier.verifyEVMController(payloadHash, signature, controller),
            "Invalid Signature"
        );

        // ── persist ───────────────────────────────────────────────────────────
        RevRegDef storage r = revRegDefs[id];
        r.id           = id;
        r.issuerId     = issuerId;
        r.revocDefType = "CL_ACCUM";
        r.credDefId    = credDefId;
        r.tag          = tag;
        r.value.tailsLocation = value.tailsLocation;
        r.value.tailsHash     = value.tailsHash;
        r.value.maxCredNum    = value.maxCredNum;

        nonces[issuerId]++;
        emit RevRegDefCreated(id, issuerId, credDefId, tag);
    }

    /// @notice Update (or initialise) the revocation status list for a registry.
    /// @param revRegId          bytes32 key of the RevRegDef being updated.
    /// @param timestamp         Unix timestamp of the update.
    /// @param currentAccumulator New accumulator value (opaque bytes).
    /// @param revocationList    New revocation bitfield (opaque bytes).
    /// @param signature         ECDSA signature over keccak256(revRegId ‖ timestamp ‖ nonce).
    /// @param controller        EVM address that produced the signature.
    function updateRevStatusList(
        bytes32 revRegId,
        uint256 timestamp,
        bytes   calldata currentAccumulator,
        bytes   calldata revocationList,
        bytes   calldata signature,
        address          controller
    ) external {
        // ── rev reg def must exist ────────────────────────────────────────────
        RevRegDef storage def = revRegDefs[revRegId];
        if (bytes(def.issuerId).length == 0) revert RevRegDefNotFound();

        // ── issuer must still be Active ───────────────────────────────────────
        if (didRegistry.getDidState(def.issuerId) != DidState.Active) revert IssuerNotActive();

        // ── signature verification (scoped to the issuer's nonce) ─────────────
        bytes32 payloadHash = keccak256(
            abi.encodePacked(revRegId, timestamp, nonces[def.issuerId])
        );
        require(
            SignatureVerifier.verifyEVMController(payloadHash, signature, controller),
            "Invalid Signature"
        );

        // ── persist ───────────────────────────────────────────────────────────
        RevStatusList storage s = revStatusLists[revRegId];
        s.revRegId           = revRegId;
        s.timestamp          = timestamp;
        s.currentAccumulator = currentAccumulator;
        s.revocationList     = revocationList;

        nonces[def.issuerId]++;
        emit RevStatusListUpdated(revRegId, timestamp);
    }

    // ── read ──────────────────────────────────────────────────────────────────

    /// @notice Retrieve a revocation registry definition by its id.
    function getRevRegDef(bytes32 id) external view returns (RevRegDef memory) {
        if (bytes(revRegDefs[id].issuerId).length == 0) revert RevRegDefNotFound();
        return revRegDefs[id];
    }

    /// @notice Retrieve the current revocation status list for a registry.
    function getRevStatusList(bytes32 revRegId) external view returns (RevStatusList memory) {
        if (revStatusLists[revRegId].revRegId == bytes32(0)) revert RevStatusListNotFound();
        return revStatusLists[revRegId];
    }

    /// @notice Returns true if a revocation registry definition exists.
    function revRegDefExists(bytes32 id) external view returns (bool) {
        return bytes(revRegDefs[id].issuerId).length != 0;
    }
}
