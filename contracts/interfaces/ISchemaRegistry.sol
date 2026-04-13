// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Minimal interface for cross-contract schema existence queries
interface ISchemaRegistry {
    function schemaExists(bytes32 id) external view returns (bool);
}
