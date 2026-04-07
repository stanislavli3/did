// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./didCore.sol";
import "./signatureVerifier.sol";
import "./interfaces/IDidRegistry.sol";

/// @title SchemaRegistry
/// @notice On-chain registry for AnonCreds credential schemas.
///         Mirrors the SchemaReceiver boundary from the Fabric chaincode (pkg/acr/schema.go).
///
/// Schema uniqueness: keccak256(abi.encode(issuerId, name, version))
/// Authorization:     issuerId must be an Active DID; ECDSA signature required.
/// Replay protection: nonce per issuerId.
contract SchemaRegistry {

    // ── structs ───────────────────────────────────────────────────────────────

    struct Schema {
        bytes32     id;
        string      issuerId;
        string      name;
        string      version;
        string[]    attrNames;
    }

    // ── storage ───────────────────────────────────────────────────────────────

    mapping(bytes32 => Schema) private schemas;
    mapping(string  => uint256) public  nonces;

    IDidRegistry public immutable didRegistry;

    // ── events ────────────────────────────────────────────────────────────────

    event SchemaPublished(
        bytes32 indexed id,
        string  issuerId,
        string  name,
        string  version
    );

    // ── errors ────────────────────────────────────────────────────────────────

    error SchemaAlreadyExists();
    error SchemaNotFound();
    error InvalidSchema();
    error IssuerNotActive();

    // ── constructor ───────────────────────────────────────────────────────────

    constructor(address _didRegistry) {
        didRegistry = IDidRegistry(_didRegistry);
    }

    // ── write ─────────────────────────────────────────────────────────────────

    /// @notice Publish a new credential schema.
    /// @param issuerId  DID of the issuer — must be Active in the DID registry.
    /// @param name      Human-readable schema name, non-empty.
    /// @param version   Schema version string, non-empty.
    /// @param attrNames Credential attribute names, at least one required.
    /// @param signature ECDSA signature over keccak256(issuerId ‖ name ‖ version ‖ nonce).
    /// @param controller EVM address that produced the signature.
    /// @return id  Deterministic bytes32 key: keccak256(abi.encode(issuerId, name, version)).
    function publishSchema(
        string   calldata issuerId,
        string   calldata name,
        string   calldata version,
        string[] calldata attrNames,
        bytes    calldata signature,
        address           controller
    ) external returns (bytes32 id) {
        // ── validation (mirrors schema.go field checks) ──────────────────────
        if (
            bytes(issuerId).length  == 0 ||
            bytes(name).length      == 0 ||
            bytes(version).length   == 0 ||
            attrNames.length        == 0
        ) revert InvalidSchema();

        // ── authorization: issuer DID must be Active ─────────────────────────
        if (didRegistry.getDidState(issuerId) != DidState.Active) revert IssuerNotActive();

        // ── uniqueness ───────────────────────────────────────────────────────
        id = keccak256(abi.encode(issuerId, name, version));
        if (bytes(schemas[id].issuerId).length != 0) revert SchemaAlreadyExists();

        // ── signature verification ───────────────────────────────────────────
        bytes32 payloadHash = keccak256(
            abi.encodePacked(issuerId, name, version, nonces[issuerId])
        );
        require(
            SignatureVerifier.verifyEVMController(payloadHash, signature, controller),
            "Invalid Signature"
        );

        // ── persist ──────────────────────────────────────────────────────────
        Schema storage s = schemas[id];
        s.id      = id;
        s.issuerId = issuerId;
        s.name    = name;
        s.version = version;
        for (uint i = 0; i < attrNames.length; i++) {
            s.attrNames.push(attrNames[i]);
        }

        nonces[issuerId]++;
        emit SchemaPublished(id, issuerId, name, version);
    }

    // ── read ──────────────────────────────────────────────────────────────────

    /// @notice Retrieve a schema by its id.
    function getSchema(bytes32 id) external view returns (Schema memory) {
        if (bytes(schemas[id].issuerId).length == 0) revert SchemaNotFound();
        return schemas[id];
    }

    /// @notice Returns true if a schema with the given id has been published.
    ///         Used by CredDefRegistry for cross-contract validation.
    function schemaExists(bytes32 id) external view returns (bool) {
        return bytes(schemas[id].issuerId).length != 0;
    }
}
