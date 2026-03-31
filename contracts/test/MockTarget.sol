// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @dev Simple target contract for executeCrossContract tests
contract MockTarget {
    uint256 public value;

    function setValue(uint256 _value) external {
        value = _value;
    }
}
