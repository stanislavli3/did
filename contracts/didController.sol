// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./didCore.sol";
import "./didResolver.sol"; // Assuming DidResolver inherits DidRegistrar
import "./signatureVerifier.sol";

/// @title DidController
/// @notice Main entry point handling payload validation, routing, and verifiable history events
contract didController is didResolver {

    // Verifiable History Events
    // Note: DidCreated and DidDeactivated are inherited from DidRegistrar.
    // Indexers will listen to these to reconstruct history natively absent GetHistoryForKey.
    event CrossContractExecuted(string indexed did, address indexed targetContact, bool success);
    // DidUpdated is inherited from the registrar/resolver; do not redefine it here to avoid duplicate event signature.

    error ExecutionFailed(bytes data);
    error UnauthorizedCaller();
    error InvalidPayload();

    // Controller Routing & Payload Validation

    /// @notice Updates an existing DID Document
    function updateDid(
        DidDocument calldata doc,
        bytes calldata signature,
        address controller
    ) external {
        DidRecord storage record = registry[doc.id];
        if (record.state != DidState.Active) {
            revert UnauthorizedCaller();
        }

        // Top-level Payload Validation
        if (bytes(doc.id).length == 0) revert InvalidPayload();

        // Top-level Authorization routing
        // Encodes the action intent to prevent replay attacks across different functions
        bytes32 payloadHash = keccak256(abi.encodePacked(doc.id, "update", nonces[doc.id]));
        require(SignatureVerifier.verifyEVMController(payloadHash, signature, controller), "Invalid Signature");

        // State Mutation
        record.document.controller = doc.controller;
        record.metadata.updated = block.timestamp;
        
        nonces[doc.id]++;

        // Emit history event
        emit DidUpdated(doc.id, block.timestamp);
    }

    /// @notice Executes an action on another smart contract on behalf of the DID
    function executeCrossContract(
        string calldata did,
        address targetContract,
        bytes calldata payload,
        bytes calldata signature,
        address controller
    ) external returns (bytes memory) {
        
        DidRecord storage record = registry[did];
        if (record.state != DidState.Active) {
            revert UnauthorizedCaller();
        }

        // Top-level Payload Validation
        if (targetContract == address(0) || payload.length == 0) revert InvalidPayload();

        // Top-level Authorization routing
        bytes32 payloadHash = keccak256(abi.encodePacked(did, targetContract, payload, nonces[did]));
        require(SignatureVerifier.verifyEVMController(payloadHash, signature, controller), "Invalid Signature");

        nonces[did]++;

        // Low-level EVM execution on the target
        (bool success, bytes memory result) = targetContract.call(payload);
        
        if (!success) {
            revert ExecutionFailed(result);
        }

        // Emit history event
        emit CrossContractExecuted(did, targetContract, success);

        return result;
    }
}