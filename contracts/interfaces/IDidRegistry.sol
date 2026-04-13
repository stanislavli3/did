// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../didCore.sol";

/// @notice Minimal interface for cross-contract DID state queries
interface IDidRegistry {
    function getDidState(string calldata did) external view returns (DidState);
}
