// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../SchemaRegistry.sol";

/// @title SchemaRegistryHarness
/// @notice Test harness that exposes direct storage writes to simulate a
///         keccak256 pre-image collision without requiring one to be found.
///         Deploy this instead of SchemaRegistry in collision tests.
contract SchemaRegistryHarness is SchemaRegistry {

    constructor(address _didRegistry) SchemaRegistry(_didRegistry) {}

    /// @dev Forces a Schema record into storage at an arbitrary key.
    ///      Lets tests occupy a slot with different field values than the
    ///      inputs that would normally produce that key, triggering KeyCollision.
    function forceStoreAtKey(
        bytes32 id,
        string calldata issuerId,
        string calldata name,
        string calldata version
    ) external {
        Schema storage s = schemas[id];
        s.id       = id;
        s.issuerId = issuerId;
        s.name     = name;
        s.version  = version;
        // attrNames intentionally omitted — collision check only reads issuerId/name/version
    }
}
