// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../didCore.sol";
import "../didVerification.sol";

/// @dev Thin wrapper that exposes didVerification internal functions for testing
contract DidVerificationHarness {
    DidDocument private _doc;

    function setDoc(DidDocument memory doc) external {
        _doc.id = doc.id;

        delete _doc.controller;
        for (uint i = 0; i < doc.controller.length; i++) {
            _doc.controller.push(doc.controller[i]);
        }

        delete _doc.verificationMethods;
        for (uint i = 0; i < doc.verificationMethods.length; i++) {
            _doc.verificationMethods.push(doc.verificationMethods[i]);
        }

        delete _doc.authentication;
        for (uint i = 0; i < doc.authentication.length; i++) {
            _doc.authentication.push(doc.authentication[i]);
        }

        delete _doc.services;
        for (uint i = 0; i < doc.services.length; i++) {
            _doc.services.push(doc.services[i]);
        }
    }

    function verifyRelationship(string calldata relationshipType, address signer) external view returns (bool) {
        return didVerification.verifyRelationship(_doc, relationshipType, signer);
    }

    function findVerificationMethod(string calldata methodId) external view returns (VerificationMethod memory) {
        return didVerification.findVerificationMethod(_doc, methodId);
    }
}
