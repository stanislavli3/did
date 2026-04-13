// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./didCore.sol";
import "./didResolver.sol";
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
    error MethodAlreadyExists();
    error MethodNotFound();
    error ServiceAlreadyExists();
    error ServiceNotFound();
    error ControllerAlreadyExists();
    error ControllerNotFound();
    error AuthenticationAlreadyExists();
    error AuthenticationNotFound();
    error UnsupportedKeyType();

    // Controller Routing & Payload Validation

    /// @notice Updates an existing DID Document
    function updateDid(
        DidDocument memory doc,
        bytes calldata signature,
        address controller
    ) external {
        // Format validation first — fail fast before any storage read
        _validateDid(doc.id);

        DidRecord storage record = registry[doc.id];
        if (record.state != DidState.Active) {
            revert UnauthorizedCaller();
        }

        // Top-level Authorization routing
        // Encodes the action intent to prevent replay attacks across different functions
        bytes32 payloadHash = keccak256(abi.encodePacked(doc.id, "update", nonces[doc.id]));
        require(SignatureVerifier.verifyEVMController(payloadHash, signature, controller), "Invalid Signature");

        // State Mutation — replace all document fields
        delete record.document.controller;
        for (uint i = 0; i < doc.controller.length; i++) {
            record.document.controller.push(doc.controller[i]);
        }

        delete record.document.verificationMethods;
        for (uint i = 0; i < doc.verificationMethods.length; i++) {
            record.document.verificationMethods.push(doc.verificationMethods[i]);
        }

        delete record.document.authentication;
        for (uint i = 0; i < doc.authentication.length; i++) {
            record.document.authentication.push(doc.authentication[i]);
        }

        delete record.document.services;
        for (uint i = 0; i < doc.services.length; i++) {
            record.document.services.push(doc.services[i]);
        }

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

    /// @notice Adds a VerificationMethod to an existing DID document
    function addVerificationMethod(
        string calldata did,
        VerificationMethod calldata method,
        bytes calldata signature,
        address controller
    ) external {
        DidRecord storage record = registry[did];
        if (record.state != DidState.Active) revert UnauthorizedCaller();

        // Reject duplicate method IDs
        VerificationMethod[] storage vms = record.document.verificationMethods;
        for (uint i = 0; i < vms.length; i++) {
            if (keccak256(bytes(vms[i].id)) == keccak256(bytes(method.id))) revert MethodAlreadyExists();
        }

        // Enforce secp256k1 key type — ecrecover only supports this suite
        if (keccak256(bytes(method.keyType)) != keccak256(bytes("EcdsaSecp256k1RecoveryMethod2020")))
            revert UnsupportedKeyType();

        bytes32 payloadHash = keccak256(abi.encodePacked(did, "addVerificationMethod", method.id, nonces[did]));
        require(SignatureVerifier.verifyEVMController(payloadHash, signature, controller), "Invalid Signature");

        vms.push(method);
        record.metadata.updated = block.timestamp;
        nonces[did]++;
        emit DidUpdated(did, block.timestamp);
    }

    /// @notice Removes a VerificationMethod from an existing DID document by method ID
    function removeVerificationMethod(
        string calldata did,
        string calldata methodId,
        bytes calldata signature,
        address controller
    ) external {
        DidRecord storage record = registry[did];
        if (record.state != DidState.Active) revert UnauthorizedCaller();

        bytes32 payloadHash = keccak256(abi.encodePacked(did, "removeVerificationMethod", methodId, nonces[did]));
        require(SignatureVerifier.verifyEVMController(payloadHash, signature, controller), "Invalid Signature");

        VerificationMethod[] storage vms = record.document.verificationMethods;
        for (uint i = 0; i < vms.length; i++) {
            if (keccak256(bytes(vms[i].id)) == keccak256(bytes(methodId))) {
                vms[i] = vms[vms.length - 1]; // swap with last
                vms.pop();
                record.metadata.updated = block.timestamp;
                nonces[did]++;
                emit DidUpdated(did, block.timestamp);
                return;
            }
        }
        revert MethodNotFound();
    }

    /// @notice Adds a Service endpoint to an existing DID document
    function addService(
        string calldata did,
        Service calldata service,
        bytes calldata signature,
        address controller
    ) external {
        DidRecord storage record = registry[did];
        if (record.state != DidState.Active) revert UnauthorizedCaller();

        // Reject duplicate service IDs
        Service[] storage services = record.document.services;
        for (uint i = 0; i < services.length; i++) {
            if (keccak256(bytes(services[i].id)) == keccak256(bytes(service.id))) revert ServiceAlreadyExists();
        }

        bytes32 payloadHash = keccak256(abi.encodePacked(did, "addService", service.id, nonces[did]));
        require(SignatureVerifier.verifyEVMController(payloadHash, signature, controller), "Invalid Signature");

        services.push(service);
        record.metadata.updated = block.timestamp;
        nonces[did]++;
        emit DidUpdated(did, block.timestamp);
    }

    /// @notice Removes a Service endpoint from an existing DID document by service ID
    function removeService(
        string calldata did,
        string calldata serviceId,
        bytes calldata signature,
        address controller
    ) external {
        DidRecord storage record = registry[did];
        if (record.state != DidState.Active) revert UnauthorizedCaller();

        bytes32 payloadHash = keccak256(abi.encodePacked(did, "removeService", serviceId, nonces[did]));
        require(SignatureVerifier.verifyEVMController(payloadHash, signature, controller), "Invalid Signature");

        Service[] storage services = record.document.services;
        for (uint i = 0; i < services.length; i++) {
            if (keccak256(bytes(services[i].id)) == keccak256(bytes(serviceId))) {
                services[i] = services[services.length - 1]; // swap with last
                services.pop();
                record.metadata.updated = block.timestamp;
                nonces[did]++;
                emit DidUpdated(did, block.timestamp);
                return;
            }
        }
        revert ServiceNotFound();
    }

    /// @notice Adds a controller DID string to the controller[] list of an existing DID document
    function addController(
        string calldata did,
        string calldata newController,
        bytes calldata signature,
        address controller
    ) external {
        DidRecord storage record = registry[did];
        if (record.state != DidState.Active) revert UnauthorizedCaller();

        string[] storage controllers = record.document.controller;
        for (uint i = 0; i < controllers.length; i++) {
            if (keccak256(bytes(controllers[i])) == keccak256(bytes(newController))) revert ControllerAlreadyExists();
        }

        bytes32 payloadHash = keccak256(abi.encodePacked(did, "addController", newController, nonces[did]));
        require(SignatureVerifier.verifyEVMController(payloadHash, signature, controller), "Invalid Signature");

        controllers.push(newController);
        record.metadata.updated = block.timestamp;
        nonces[did]++;
        emit DidUpdated(did, block.timestamp);
    }

    /// @notice Removes a controller DID string from the controller[] list of an existing DID document
    function removeController(
        string calldata did,
        string calldata controllerToRemove,
        bytes calldata signature,
        address controller
    ) external {
        DidRecord storage record = registry[did];
        if (record.state != DidState.Active) revert UnauthorizedCaller();

        bytes32 payloadHash = keccak256(abi.encodePacked(did, "removeController", controllerToRemove, nonces[did]));
        require(SignatureVerifier.verifyEVMController(payloadHash, signature, controller), "Invalid Signature");

        string[] storage controllers = record.document.controller;
        for (uint i = 0; i < controllers.length; i++) {
            if (keccak256(bytes(controllers[i])) == keccak256(bytes(controllerToRemove))) {
                controllers[i] = controllers[controllers.length - 1];
                controllers.pop();
                record.metadata.updated = block.timestamp;
                nonces[did]++;
                emit DidUpdated(did, block.timestamp);
                return;
            }
        }
        revert ControllerNotFound();
    }

    /// @notice Adds a verification method ID reference to the authentication[] relationship list
    function addAuthentication(
        string calldata did,
        string calldata methodId,
        bytes calldata signature,
        address controller
    ) external {
        DidRecord storage record = registry[did];
        if (record.state != DidState.Active) revert UnauthorizedCaller();

        string[] storage auth = record.document.authentication;
        for (uint i = 0; i < auth.length; i++) {
            if (keccak256(bytes(auth[i])) == keccak256(bytes(methodId))) revert AuthenticationAlreadyExists();
        }

        bytes32 payloadHash = keccak256(abi.encodePacked(did, "addAuthentication", methodId, nonces[did]));
        require(SignatureVerifier.verifyEVMController(payloadHash, signature, controller), "Invalid Signature");

        auth.push(methodId);
        record.metadata.updated = block.timestamp;
        nonces[did]++;
        emit DidUpdated(did, block.timestamp);
    }

    /// @notice Removes a verification method ID reference from the authentication[] relationship list
    function removeAuthentication(
        string calldata did,
        string calldata methodId,
        bytes calldata signature,
        address controller
    ) external {
        DidRecord storage record = registry[did];
        if (record.state != DidState.Active) revert UnauthorizedCaller();

        bytes32 payloadHash = keccak256(abi.encodePacked(did, "removeAuthentication", methodId, nonces[did]));
        require(SignatureVerifier.verifyEVMController(payloadHash, signature, controller), "Invalid Signature");

        string[] storage auth = record.document.authentication;
        for (uint i = 0; i < auth.length; i++) {
            if (keccak256(bytes(auth[i])) == keccak256(bytes(methodId))) {
                auth[i] = auth[auth.length - 1];
                auth.pop();
                record.metadata.updated = block.timestamp;
                nonces[did]++;
                emit DidUpdated(did, block.timestamp);
                return;
            }
        }
        revert AuthenticationNotFound();
    }

    /// @notice Returns the current state of a DID (Unregistered, Active, Deactivated)
    function getDidState(string calldata did) external view returns (DidState) {
        return registry[did].state;
    }
}
