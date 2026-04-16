// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./didCore.sol";
import "./signatureVerifier.sol";

contract didRegistrar {
    mapping(string => DidRecord) internal registry;
    mapping(string => uint256) public nonces;
    mapping(string => address) internal didOwner;
    mapping(address => string[]) internal ownerDids;

    event DidCreated(string indexed did, uint256 timestamp);
    event DidUpdated(string indexed did, uint256 timestamp);
    event DidDeactivated(string indexed did, uint256 timestamp);

    error DocumentAlreadyExists();
    error InvalidSignature();
    error InvalidDidFormat();

    /// @dev Validates the did:orcl:<uuid-v4> format via byte-level parsing.
    ///      Segment 0 must be "did", segment 1 must be "orcl",
    ///      segment 2 must be a RFC 4122 UUID v4 (36 bytes, version=4, variant=[89ab]).
    function _validateDid(string memory did) internal pure {
        bytes memory b = bytes(did);
        uint len = b.length;
        if (len == 0) revert InvalidDidFormat();

        uint i = 0;

        // ── segment 0: must be "did" ──────────────────────────────────────────
        if (i + 3 > len || b[i] != 0x64 || b[i+1] != 0x69 || b[i+2] != 0x64)
            revert InvalidDidFormat();
        i += 3;
        if (i >= len || b[i] != 0x3a) revert InvalidDidFormat();
        i++;

        // ── segment 1: must be "orcl" ─────────────────────────────────────────
        if (i + 4 > len || b[i] != 0x6f || b[i+1] != 0x72 || b[i+2] != 0x63 || b[i+3] != 0x6c)
            revert InvalidDidFormat();
        i += 4;
        if (i >= len || b[i] != 0x3a) revert InvalidDidFormat();
        i++;

        // ── segment 2: UUID v4, exactly 36 bytes, no trailing characters ──────
        if (len - i != 36) revert InvalidDidFormat();
        _validateUuidV4(b, i);
    }

    /// @dev Validates a 36-byte UUID v4 segment starting at `offset` in `b`.
    ///      Format: xxxxxxxx-xxxx-4xxx-[89ab]xxx-xxxxxxxxxxxx
    function _validateUuidV4(bytes memory b, uint offset) private pure {
        if (b[offset +  8] != 0x2d ||
            b[offset + 13] != 0x2d ||
            b[offset + 18] != 0x2d ||
            b[offset + 23] != 0x2d) revert InvalidDidFormat();

        if (b[offset + 14] != 0x34) revert InvalidDidFormat();

        bytes1 variant = b[offset + 19];
        if (variant != 0x38 && variant != 0x39 && variant != 0x61 && variant != 0x62)
            revert InvalidDidFormat();

        for (uint j = 0; j < 36; j++) {
            if (j == 8 || j == 13 || j == 18 || j == 23) continue;
            if (j == 14 || j == 19) continue;
            bytes1 c = b[offset + j];
            if (!((c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66)))
                revert InvalidDidFormat();
        }
    }

    // Core Registrar Logic
    // Added 'controller' to args representing the EVM address of the signer
    function createDid(DidDocument memory doc, bytes calldata signature) external returns (string memory) {
        _validateDid(doc.id);

        if (registry[doc.id].state != DidState.Unregistered) {
            revert DocumentAlreadyExists();
        }

        // 1. Construct the payload hash from the DID and current nonce
        bytes32 payloadHash = keccak256(abi.encodePacked(doc.id, nonces[doc.id]));

        // 2. Verify signature
        require(SignatureVerifier.verifyEVMController(payloadHash, signature, msg.sender), "Invalid Signature");

        DidRecord storage record = registry[doc.id];

        record.document.id = doc.id;

        for (uint i = 0; i < doc.controller.length; i++) {
            record.document.controller.push(doc.controller[i]);
        }
        for (uint i = 0; i < doc.verificationMethods.length; i++) {
            record.document.verificationMethods.push(doc.verificationMethods[i]);
        }
        for (uint i = 0; i < doc.authentication.length; i++) {
            record.document.authentication.push(doc.authentication[i]);
        }
        for (uint i = 0; i < doc.services.length; i++) {
            record.document.services.push(doc.services[i]);
        }

        record.state = DidState.Active;
        record.metadata.created = block.timestamp;
        record.metadata.updated = block.timestamp;

        didOwner[doc.id] = msg.sender;
        ownerDids[msg.sender].push(doc.id);

        nonces[doc.id]++;

        emit DidCreated(doc.id, block.timestamp);
        return doc.id;
    }

    function deactivateDid(string calldata did, bytes calldata signature) external {
        if (registry[did].state != DidState.Active) {
            revert("DID is not active");
        }

        // 1. Construct the payload hash from the DID and current nonce
        bytes32 payloadHash = keccak256(abi.encodePacked(did, nonces[did]));

        // 2. Verify authorization
        require(SignatureVerifier.verifyEVMController(payloadHash, signature, msg.sender), "Invalid Signature");

        // 3. Update state
        DidRecord storage record = registry[did];
        record.state = DidState.Deactivated;
        record.metadata.updated = block.timestamp;

        nonces[did]++;
        emit DidDeactivated(did, block.timestamp);
    }
}
