// (c) 2022-2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: MIT

pragma solidity >=0.8.0;

// RandomPartyPrecompile is an implementation of an incentivized
// commit/reveal VRF.
//
// Participants in Random Parties follow the flow below:
// 1) start() => cleans up the metadata of a previous Random Party and inits
//     a new Random Party (setting the length of the "commit" phase and "reveal"
//     phase to [PhaseSeconds] and setting the "commit" lockup to
//     [CommitStake])
//
//     Note: There is only ever 1 Random Party going on at once.
// 2) [optional] sponsor() => anyone can donate funds to an incentive pool that
//     is distributed amongst all participants that reveal the preimage of their
//     commitment
// 3) commit(bytes32 encoded) => submit the hash of some preimage that will
//     be broadcasted during the "reveal" phase ([CommitStake] tokens must be
//     locked as part of this operation and are returned when the preimage is
//     revealed)
// 4) reveal(uint256 index, bytes32 preimage) => reveal the preimage for some
//     hash that was broadcast during the "commit" phase ([CommitStake] is returned
//     at this time)
//
//     Note: If someone that posted a commitment does not reveal that
//     commitment, they will not be able to retrieve their [CommitState].
//     This mechanism is a naive deterrent for participants that may try to
//     game the result of the computation.
// 5) compute() => after the "commit" and "reveal" phases have passed, anyone
//     can pay to compute the hash of all preimages (any balance in the
//     incentive pool is distributed equally to everyone that broadcast a preimage)
//
// Contracts use the following methods to access the state of an ongoing/completed Random Party:
// 1) reward() => returns the amount in the current incentive pool
// 2) result(uint256 round) => returns the computed hash of preimages of a given Random Party
//     round
// 3) next() => returns the number of the next Random Party round (this
//     number-1 is used to query the latest result)
//
// In short, anyone can start a Random Party on the
// chain, anyone can sponsor a reward for contributors, anyone can
// participate in providing randomness, and anyone can use the round results
// in their smart contract.
interface RandomPartyInterface {
    // Start Random Party round
    function start() external;

    // Donate funds to the Random Party round incentive pool
    function sponsor() payable external;

    // Query the size of the current Random Party incentive pool
    function reward() external view returns (uint256);

    // Commit to the hash of some preimage (requires locking [CommitStake])
    function commit(bytes32 encoded) payable external returns (uint256);

    // Reveal the preimage of a previously committed hash (receive locked
    // [CommitStake])
    function reveal(uint256 index, bytes32 preimage) external;

    // Generate the hash of all revealed preimages and distribute any funds in
    // the incentive pool to all participants equally
    function compute() external;

    // Query the hash of all preimages in [round]
    function result(uint256 round) external view returns (bytes32);

    // Query the index of the next Random Party Round
    function next() external view returns (uint256);
}
