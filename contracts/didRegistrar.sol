// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./didCore.sol"; // Ensure this exactly matches the file name

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
    function createDid(DidDocument calldata doc, bytes calldata signature, address controller) external returns (string memory) {
        if (registry[doc.id].state != DidState.Unregistered) {
            revert DocumentAlreadyExists();
        }

        // 1. Construct the payload hash from the DID and current nonce
        bytes32 payloadHash = keccak256(abi.encodePacked(doc.id, nonces[doc.id]));

        // 2. Call the correct library function
        require(SignatureVerifier.verifyEVMController(payloadHash, signature, controller), "Invalid Signature");

        DidRecord storage record = registry[doc.id];
        
        record.document.id = doc.id;
        record.document.controller = doc.controller;
        record.state = DidState.Active;
        record.metadata.created = block.timestamp;
        record.metadata.updated = block.timestamp;

        // Note: For inner nested arrays in `doc` (like verificationMethods), 
        // you will need to map/push them manually into the storage pointer if required.

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

library SignatureVerifier {
    function verifyEVMController(bytes32 payloadHash, bytes memory signature, address controller) internal pure returns (bool) {
        bytes32 ethSignedMessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", payloadHash)
        );
        
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);
        return ecrecover(ethSignedMessageHash, v, r, s) == controller;
    }

    function splitSignature(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "invalid signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}