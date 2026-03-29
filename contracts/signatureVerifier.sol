// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library signatureVerifier {
    
    /// @notice Verifies an ECDSA SECP256k1 signature against an EVM address (controller)
    /// @param payloadHash The keccak256 hash of the payload data
    /// @param signature The 65-byte signature bytes
    /// @param controller The expected signer's EVM address
    /// @return bool True if the recovered address matches the controller
    function verifyEVMController(bytes32 payloadHash, bytes memory signature, address controller) internal pure returns (bool) {
        // Prepends the standard Ethereum message prefix
        bytes32 ethSignedMessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", payloadHash)
        );
        
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);
        
        // ecrecover returns the address that signed the message
        address recoveredSigner = ecrecover(ethSignedMessageHash, v, r, s);
        
        return recoveredSigner != address(0) && recoveredSigner == controller;
    }

    /// @notice Helper to split a standard 65-byte signature into r, s, and v components
    function splitSignature(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Invalid signature length");

        assembly {
            // First 32 bytes stores the length of the bytes array
            // mload reads 32 bytes from memory starting at the given memory address
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}