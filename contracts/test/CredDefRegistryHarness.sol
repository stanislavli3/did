// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../CredDefRegistry.sol";

/// @title CredDefRegistryHarness
/// @notice Test harness that exposes direct storage writes to simulate a
///         keccak256 pre-image collision without requiring one to be found.
///         Deploy this instead of CredDefRegistry in collision tests.
contract CredDefRegistryHarness is CredDefRegistry {

    constructor(address _didRegistry, address _schemaRegistry)
        CredDefRegistry(_didRegistry, _schemaRegistry) {}

    /// @dev Forces a CredDef record into storage at an arbitrary key.
    ///      Lets tests occupy a slot with different field values than the
    ///      inputs that would normally produce that key, triggering KeyCollision.
    function forceStoreAtKey(
        bytes32 id,
        string calldata issuerId,
        bytes32 schemaId,
        string calldata tag
    ) external {
        CredDef storage cd = credDefs[id];
        cd.id       = id;
        cd.issuerId = issuerId;
        cd.schemaId = schemaId;
        cd.tag      = tag;
        cd.credDefType = CredDefType.CL;
        // value intentionally omitted — collision check only reads issuerId/schemaId/tag
    }
}
