// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./didCore.sol";
import "./didRegistrar.sol"; // Assuming registry visibility is changed to internal/public

contract didResolver is didRegistrar {

    error DocumentNotFound();
    error FragmentNotFound();
    error RevocationNotFound();

    /// @notice Resolves a full DID Document
    function resolve(string calldata did) external view returns (DidDocument memory, DocumentMetadata memory) {
        DidRecord storage record = registry[did];
        if (record.state == DidState.Unregistered) {
            revert DocumentNotFound();
        }
        return (record.document, record.metadata);
    }

    /// @notice Dereferences a specific Verification Method by its fragment ID
    function dereferenceVerificationMethod(string calldata did, string calldata fragmentId) 
        external 
        view 
        returns (VerificationMethod memory) 
    {
        DidRecord storage record = registry[did];
        if (record.state == DidState.Unregistered) {
            revert DocumentNotFound();
        }

        for (uint i = 0; i < record.document.verificationMethods.length; i++) {
            if (keccak256(abi.encodePacked(record.document.verificationMethods[i].id)) == keccak256(abi.encodePacked(fragmentId))) {
                return record.document.verificationMethods[i];
            }
        }
        
        revert FragmentNotFound();
    }

    /// @notice Returns all revocation objects for a DID (path: /revocation)
    /// @dev Returns empty array when no revocations exist — does not revert
    function dereferenceRevocations(string calldata did)
        external
        view
        returns (RevocationObject[] memory)
    {
        DidRecord storage record = registry[did];
        if (record.state == DidState.Unregistered) revert DocumentNotFound();
        return record.document.revocations;
    }

    /// @notice Returns a single RevocationObject by id (path: /revocation/{revocationId})
    function dereferenceRevocationById(string calldata did, string calldata revocationId)
        external
        view
        returns (RevocationObject memory)
    {
        DidRecord storage record = registry[did];
        if (record.state == DidState.Unregistered) revert DocumentNotFound();

        RevocationObject[] storage revocations = record.document.revocations;
        for (uint i = 0; i < revocations.length; i++) {
            if (keccak256(bytes(revocations[i].id)) == keccak256(bytes(revocationId)))
                return revocations[i];
        }
        revert RevocationNotFound();
    }

    /// @notice Returns the EVM address that owns (created) the given DID.
    ///         Returns address(0) for unregistered DIDs.
    function getOwner(string calldata did) external view returns (address) {
        return didOwner[did];
    }

    /// @notice Returns all DID strings registered by the given EVM address.
    function getDIDsByOwner(address owner) external view returns (string[] memory) {
        return ownerDids[owner];
    }
}