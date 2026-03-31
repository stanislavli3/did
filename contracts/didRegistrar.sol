// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./didCore.sol";
import "./signatureVerifier.sol";

contract didRegistrar {
    mapping(string => DidRecord) internal registry;
    mapping(string => uint256) public nonces;

    event DidCreated(string indexed did, uint256 timestamp);
    event DidUpdated(string indexed did, uint256 timestamp);
    event DidDeactivated(string indexed did, uint256 timestamp);

    error DocumentAlreadyExists();
    error InvalidSignature();

    // Core Registrar Logic
    // Added 'controller' to args representing the EVM address of the signer
    function createDid(DidDocument memory doc, bytes calldata signature, address controller) external returns (string memory) {
        if (registry[doc.id].state != DidState.Unregistered) {
            revert DocumentAlreadyExists();
        }

        // 1. Construct the payload hash from the DID and current nonce
        bytes32 payloadHash = keccak256(abi.encodePacked(doc.id, nonces[doc.id]));

        // 2. Verify signature
        require(SignatureVerifier.verifyEVMController(payloadHash, signature, controller), "Invalid Signature");

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

        nonces[doc.id]++;

        emit DidCreated(doc.id, block.timestamp);
        return doc.id;
    }

    function deactivateDid(string calldata did, bytes calldata signature, address controller) external {
        if (registry[did].state != DidState.Active) {
            revert("DID is not active");
        }

        // 1. Construct the payload hash from the DID and current nonce
        bytes32 payloadHash = keccak256(abi.encodePacked(did, nonces[did]));

        // 2. Verify authorization
        require(SignatureVerifier.verifyEVMController(payloadHash, signature, controller), "Invalid Signature");

        // 3. Update state
        DidRecord storage record = registry[did];
        record.state = DidState.Deactivated;
        record.metadata.updated = block.timestamp;

        nonces[did]++;
        emit DidDeactivated(did, block.timestamp);
    }
}
