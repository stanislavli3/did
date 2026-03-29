// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./didCore.sol";
import "./signatureVerifier.sol"; // Assuming this is where your ecrecover logic lives

library didVerification {
    
    error VerificationMethodNotFound();
    error UnauthorizedRelationship();

    /// @notice Checks if a controller is authorized to perform an action using a specific verification relationship
    function verifyRelationship(
        DidDocument storage doc,
        string calldata relationshipType, // e.g., "authentication", "assertionMethod"
        address signer
    ) internal view returns (bool) {
        // 1. Traverse document relationships based on relationshipType
        // 2. Find the referenced VerificationMethod
        // 3. Confirm the 'signer' matches the key material in that VerificationMethod
        
        return true; // Return true if valid, revert or false otherwise
    }

    /// @notice Helper to find a specific VerificationMethod by its ID fragment
    function findVerificationMethod(
        DidDocument storage doc, 
        string calldata methodId
    ) internal view returns (VerificationMethod memory) {
        for (uint i = 0; i < doc.verificationMethods.length; i++) {
            // Note: String comparison requires keccak256 in Solidity
            if (keccak256(abi.encodePacked(doc.verificationMethods[i].id)) == keccak256(abi.encodePacked(methodId))) {
                return doc.verificationMethods[i];
            }
        }
        revert VerificationMethodNotFound();
    }
}