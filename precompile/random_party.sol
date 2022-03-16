// (c) 2022-2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: MIT

pragma solidity >=0.8.0;

interface RandomPartyInterface {
    // blah
    function start() external;

    // blah
    function commit(bytes32 encoded) external returns (uint256);

    // blah
    function reveal(uint256 index, bytes32 preimage) external;

    // blah
    function compute() external;

    // blah
    function result(uint256 round) external view returns (bytes32);

    // blah
    function next() external view returns (uint256);
}
