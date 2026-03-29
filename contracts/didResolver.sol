// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./didCore.sol";
import "./didRegistrar.sol"; // Assuming registry visibility is changed to internal/public

contract didResolver is didRegistrar {
    
    error DocumentNotFound();
    error FragmentNotFound();

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
}