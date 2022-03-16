// (c) 2022-2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: MIT

pragma solidity >=0.8.0;

interface RandomPartyInterface {
    function start() external;

    function commit(bytes32 encoded) external;

    function reveal(uint256 index, bytes32 preimage) external;

    function compute() external;

    function result(uint256 round) external view returns (bytes32);

    function next() external view returns (uint256);
}
