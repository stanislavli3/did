// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Minimal interface for cross-contract credential definition existence queries
interface ICredDefRegistry {
    function credDefExists(bytes32 id) external view returns (bool);
}
