// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./didCore.sol";

library didVerification {

    error VerificationMethodNotFound();
    error UnauthorizedRelationship();
    error UnsupportedRelationshipType();

    /// @notice Checks if a signer is authorized under a specific verification relationship.
    /// @dev Walks the relationship array (e.g. authentication), finds each referenced
    ///      VerificationMethod, and checks whether publicKeyMultibase encodes the signer address.
    ///      publicKeyMultibase is expected to be abi.encode(address) — a 32-byte ABI-padded address.
    /// @param doc         The DID document to check against (storage ref for gas efficiency)
    /// @param relationshipType  One of: "authentication" (others will revert UnsupportedRelationshipType)
    /// @param signer      The EVM address claiming authorization
    /// @return true if the signer is found in the relationship, false otherwise
    function verifyRelationship(
        DidDocument storage doc,
        string calldata relationshipType,
        address signer
    ) internal view returns (bool) {
        if (keccak256(bytes(relationshipType)) == keccak256(bytes("authentication"))) {
            return _checkRelationship(doc, doc.authentication, signer);
        }

        revert UnsupportedRelationshipType();
    }

    /// @notice Helper to find a specific VerificationMethod by its ID fragment
    function findVerificationMethod(
        DidDocument storage doc,
        string calldata methodId
    ) internal view returns (VerificationMethod memory) {
        for (uint i = 0; i < doc.verificationMethods.length; i++) {
            if (keccak256(bytes(doc.verificationMethods[i].id)) == keccak256(bytes(methodId))) {
                return doc.verificationMethods[i];
            }
        }
        revert VerificationMethodNotFound();
    }

    /// @dev For each method ID reference in the relationship array, resolves the VerificationMethod
    ///      and checks if its publicKeyMultibase encodes the signer address.
    function _checkRelationship(
        DidDocument storage doc,
        string[] storage relationship,
        address signer
    ) private view returns (bool) {
        for (uint i = 0; i < relationship.length; i++) {
            // Find the referenced VerificationMethod in the document
            for (uint j = 0; j < doc.verificationMethods.length; j++) {
                if (keccak256(bytes(doc.verificationMethods[j].id)) == keccak256(bytes(relationship[i]))) {
                    // publicKeyMultibase is abi.encode(address) — 32 bytes, ABI-padded
                    if (doc.verificationMethods[j].publicKeyMultibase.length == 32) {
                        address encoded = abi.decode(doc.verificationMethods[j].publicKeyMultibase, (address));
                        if (encoded == signer) return true;
                    }
                    break; // method found but key didn't match; move to next relationship entry
                }
            }
        }
        return false;
    }
}
