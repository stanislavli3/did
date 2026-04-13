// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./didCore.sol";
import "./signatureVerifier.sol";
import "./interfaces/IDidRegistry.sol";
import "./interfaces/ISchemaRegistry.sol";

/// @title CredDefRegistry
/// @notice On-chain registry for AnonCreds credential definitions.
///         Mirrors the CredDefReceiver boundary from the Fabric chaincode
///         (pkg/acr/credentialDefinition.go).
///
/// CredDef uniqueness:  keccak256(abi.encode(issuerId, schemaId, tag))
/// Authorization:       issuerId must be an Active DID; schemaId must exist.
/// Replay protection:   nonce per issuerId.
///
/// The `value` field carries the CL public key material — treated as opaque
/// bytes (map[string]any in Go → caller-encoded bytes in Solidity).
contract CredDefRegistry {

    // ── types ─────────────────────────────────────────────────────────────────

    /// @dev Matches default:"CL" tag in credentialDefinition.go.
    ///      Defined as an enum to make the constraint explicit rather than
    ///      relying on an unchecked string.
    enum CredDefType { CL }

    struct CredDef {
        bytes32     id;
        string      issuerId;
        bytes32     schemaId;
        CredDefType credDefType;
        string      tag;
        bytes       value;
    }

    // ── storage ───────────────────────────────────────────────────────────────

    mapping(bytes32 => CredDef) private credDefs;
    mapping(string  => uint256) public  nonces;

    IDidRegistry    public immutable didRegistry;
    ISchemaRegistry public immutable schemaRegistry;

    // ── events ────────────────────────────────────────────────────────────────

    event CredDefPublished(
        bytes32 indexed id,
        string  issuerId,
        bytes32 indexed schemaId,
        string  tag
    );

    // ── errors ────────────────────────────────────────────────────────────────

    error CredDefAlreadyExists();
    error CredDefNotFound();
    error InvalidCredDef();
    error IssuerNotActive();
    error SchemaNotFound();
    error KeyCollision();

    // ── constructor ───────────────────────────────────────────────────────────

    constructor(address _didRegistry, address _schemaRegistry) {
        didRegistry    = IDidRegistry(_didRegistry);
        schemaRegistry = ISchemaRegistry(_schemaRegistry);
    }

    // ── write ─────────────────────────────────────────────────────────────────

    /// @notice Publish a new credential definition.
    /// @param issuerId    DID of the issuer — must be Active in the DID registry.
    /// @param schemaId    bytes32 key of an existing schema in SchemaRegistry.
    /// @param credDefType Credential definition type — only CL is currently supported.
    /// @param tag         Disambiguates multiple CredDefs for the same schema (no validation per spec).
    /// @param value       Opaque CL public key material bytes.
    /// @param signature   ECDSA signature over keccak256(issuerId ‖ schemaId ‖ tag ‖ nonce).
    /// @param controller  EVM address that produced the signature.
    /// @return id  Deterministic bytes32 key: keccak256(abi.encode(issuerId, schemaId, tag)).
    function publishCredDef(
        string      calldata issuerId,
        bytes32              schemaId,
        CredDefType          credDefType,
        string      calldata tag,
        bytes       calldata value,
        bytes       calldata signature,
        address              controller
    ) external returns (bytes32 id) {
        // ── validation (mirrors credentialDefinition.go L82/L85) ─────────────
        if (bytes(issuerId).length == 0) revert InvalidCredDef();

        // ── cross-contract: issuer DID must be Active ─────────────────────────
        if (didRegistry.getDidState(issuerId) != DidState.Active) revert IssuerNotActive();

        // ── cross-contract: referenced schema must exist ──────────────────────
        if (!schemaRegistry.schemaExists(schemaId)) revert SchemaNotFound();

        // ── uniqueness ────────────────────────────────────────────────────────
        id = keccak256(abi.encode(issuerId, schemaId, tag));
        if (bytes(credDefs[id].issuerId).length != 0) {
            // Distinguish a true keccak256 collision (different pre-image, same hash)
            // from a legitimate duplicate submission (identical inputs).
            if (
                keccak256(bytes(credDefs[id].issuerId)) != keccak256(bytes(issuerId)) ||
                credDefs[id].schemaId                   != schemaId                   ||
                keccak256(bytes(credDefs[id].tag))      != keccak256(bytes(tag))
            ) revert KeyCollision();
            revert CredDefAlreadyExists();
        }

        // ── signature verification ────────────────────────────────────────────
        bytes32 payloadHash = keccak256(
            abi.encodePacked(issuerId, schemaId, tag, nonces[issuerId])
        );
        require(
            SignatureVerifier.verifyEVMController(payloadHash, signature, controller),
            "Invalid Signature"
        );

        // ── persist ───────────────────────────────────────────────────────────
        CredDef storage cd = credDefs[id];
        cd.id          = id;
        cd.issuerId    = issuerId;
        cd.schemaId    = schemaId;
        cd.credDefType = credDefType;
        cd.tag         = tag;
        cd.value       = value;

        nonces[issuerId]++;
        emit CredDefPublished(id, issuerId, schemaId, tag);
    }

    // ── read ──────────────────────────────────────────────────────────────────

    /// @notice Retrieve a credential definition by its id.
    function getCredDef(bytes32 id) external view returns (CredDef memory) {
        if (bytes(credDefs[id].issuerId).length == 0) revert CredDefNotFound();
        return credDefs[id];
    }
}
