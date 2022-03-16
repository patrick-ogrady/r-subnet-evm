// (c) 2019-2020, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package precompile

import (
	"fmt"
	"math/big"

	"github.com/ava-labs/subnet-evm/vmerrs"
	"github.com/ethereum/go-ethereum/common"
)

// -> Start() => commitDeadline=time+1 hour/revealDeadline=time+2 hour; del commits; del reveals; commits=0; reveals=0
// < Commit Deadline (if 0, no ongoing)
// -> Commit(hash) => com1=hash;commits=1
// < Reveal Deadline
// -> Reveal(num,preimage) =>rev1=preimage;reveals=1;
// -> Compute() => roundX=result;commitDeadline=0;revealDeadline=0;
// -> Result(round)-> hash
// -> Completed()-> uint256

var (
	_ StatefulPrecompileConfig = (*RandomPartyConfig)(nil)

	RandomPartyPrecompile StatefulPrecompiledContract = createRandomPartyPrecompile(RandomPartyAddress)
)

var (
	// RandomParty function signatures
	startSignature     = CalculateFunctionSelector("start()")
	commitSignature    = CalculateFunctionSelector("commit(hash)")
	revealSignature    = CalculateFunctionSelector("reveal(uint256,hash)")
	computeSignature   = CalculateFunctionSelector("compute()")
	resultSignature    = CalculateFunctionSelector("result(uint256)")
	completedSignature = CalculateFunctionSelector("completed()")
)

// RandomPartyConfig specifies the configuration of the allow list.
// Specifies the block timestamp at which it goes into effect as well as the initial set of allow list admins.
type RandomPartyConfig struct {
	BlockTimestamp *big.Int `json:"blockTimestamp"`
}

// Address returns the address of the random party contract.
func (c *RandomPartyConfig) Address() common.Address {
	return RandomPartyAddress
}

// Timestamp returns the timestamp at which the allow list should be enabled
func (c *RandomPartyConfig) Timestamp() *big.Int { return c.BlockTimestamp }

// Configure initializes the address space of [precompileAddr] by initializing the role of each of
// the addresses in [RandomPartyAdmins].
func (c *RandomPartyConfig) Configure(state StateDB) {}

// Contract returns the singleton stateful precompiled contract to be used for
// the random party.
func (c *RandomPartyConfig) Contract() StatefulPrecompiledContract {
	return RandomPartyPrecompile
}

var (
	commitDeadlineKey = []byte{0x1}
	revealDeadlineKey = []byte{0x2}
	commitPrefix      = []byte{0x3}
	revealPrefix      = []byte{0x4}
	resultPrefix      = []byte{0x5}
	completedKey      = []byte{0x6}
)

func setRandomPartyBig(state StateDB, key []byte, val *big.Int) {
	state.SetState(RandomPartyAddress, common.BytesToHash(key), common.BigToHash(val))
}

func getRandomPartyBig(state StateDB, key []byte) *big.Int {
	h := state.GetState(RandomPartyAddress, common.BytesToHash(key))
	return new(big.Int).SetBytes(h.Bytes())
}

func addCounterHash(state StateDB, prefix []byte, hash common.Hash) {
	currV := getRandomPartyBig(state, prefix)
	newV := new(big.Int).Add(currV, common.Big1)
	setRandomPartyBig(state, prefix, newV)
	k := append(prefix, currV.Bytes()...)
	state.SetState(RandomPartyAddress, common.BytesToHash(k), hash)
}

func getCounterHash(state StateDB, prefix []byte, v *big.Int) common.Hash {
	k := append(prefix, v.Bytes()...)
	return state.GetState(RandomPartyAddress, common.BytesToHash(k))
}

func deleteCounterHash(state StateDB, prefix []byte, v *big.Int) {
	k := append(prefix, v.Bytes()...)
	state.SetState(RandomPartyAddress, common.BytesToHash(k), common.Hash{})
}

func addResultHash(state StateDB, round *big.Int, value common.Hash) {
	k := append(resultPrefix, round.Bytes()...)
	state.SetState(RandomPartyAddress, common.BytesToHash(k), value)
}

func getResultHash(state StateDB, round *big.Int) common.Hash {
	k := append(resultPrefix, round.Bytes()...)
	return state.GetState(RandomPartyAddress, common.BytesToHash(k))
}

func PackCommitRandomParty(hash common.Hash) []byte {
	return append(commitSignature, hash.Bytes()...)
}

func UnpackCommitRandomParty(input []byte) (common.Hash, error) {
	if len(input) != common.HashLength {
		return common.Hash{}, fmt.Errorf("invalid input length for commit: %d", len(input))
	}
	return common.BytesToHash(input), nil
}

func PackRevealRandomParty(v *big.Int, hash common.Hash) []byte {
	r := append(revealSignature, common.BigToHash(v).Bytes()...)
	return append(r, hash.Bytes()...)
}

func UnpackRevealRandomParty(input []byte) (*big.Int, common.Hash, error) {
	if len(input) != common.HashLength*2 {
		return nil, common.Hash{}, fmt.Errorf("invalid input length for reveal: %d", len(input))
	}
	return new(big.Int).SetBytes(input[:common.HashLength]), common.BytesToHash(input[common.HashLength:]), nil
}

func PackResultRandomParty(v *big.Int) []byte {
	return append(resultSignature, common.BigToHash(v).Bytes()...)
}

func UnpackResultRandomParty(input []byte) (*big.Int, error) {
	if len(input) != common.HashLength {
		return nil, fmt.Errorf("invalid input length for result: %d", len(input))
	}
	return new(big.Int).SetBytes(input), nil
}

// createRandomPartyStageSetter returns an execution function for setting the allow list status of the input address argument to [role].
// This execution function is speciifc to [precompileAddr].
func createRandomPartyStageSetter(precompileAddr common.Address, role RandomPartyStage) RunStatefulPrecompileFunc {
	return func(evm PrecompileAccessibleState, callerAddr, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) (ret []byte, remainingGas uint64, err error) {
		if remainingGas, err = deductGas(suppliedGas, ModifyRandomPartyGasCost); err != nil {
			return nil, 0, err
		}

		if len(input) != allowListInputLen {
			return nil, remainingGas, fmt.Errorf("invalid input length for modifying allow list: %d", len(input))
		}

		modifyAddress := common.BytesToAddress(input)

		if readOnly {
			return nil, remainingGas, vmerrs.ErrWriteProtection
		}

		// Verify that the caller is in the allow list and therefore has the right to modify it
		callerStatus := getRandomPartyStatus(evm.GetStateDB(), precompileAddr, callerAddr)
		if !callerStatus.IsAdmin() {
			return nil, remainingGas, fmt.Errorf("%w: %s", ErrCannotModifyRandomParty, callerAddr)
		}

		setRandomPartyStage(evm.GetStateDB(), precompileAddr, modifyAddress, role)
		// Return an empty output and the remaining gas
		return []byte{}, remainingGas, nil
	}
}

// createReadRandomParty returns an execution function that reads the allow list for the given [precompileAddr].
// The execution function parses the input into a single address and returns the 32 byte hash that specifies the
// designated role of that address
func createReadRandomParty(precompileAddr common.Address) RunStatefulPrecompileFunc {
	return func(evm PrecompileAccessibleState, callerAddr common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) (ret []byte, remainingGas uint64, err error) {
		if remainingGas, err = deductGas(suppliedGas, ReadRandomPartyGasCost); err != nil {
			return nil, 0, err
		}

		if len(input) != allowListInputLen {
			return nil, remainingGas, fmt.Errorf("invalid input length for read allow list: %d", len(input))
		}

		readAddress := common.BytesToAddress(input)
		role := getRandomPartyStatus(evm.GetStateDB(), precompileAddr, readAddress)
		roleBytes := common.Hash(role).Bytes()
		return roleBytes, remainingGas, nil
	}
}

// createRandomPartyPrecompile returns a StatefulPrecompiledContract with R/W control of an allow list at [precompileAddr]
func createRandomPartyPrecompile(precompileAddr common.Address) StatefulPrecompiledContract {
	setAdmin := newStatefulPrecompileFunction(setAdminSignature, createRandomPartyStageSetter(precompileAddr, RandomPartyAdmin))
	setEnabled := newStatefulPrecompileFunction(setEnabledSignature, createRandomPartyStageSetter(precompileAddr, RandomPartyEnabled))
	setNone := newStatefulPrecompileFunction(setNoneSignature, createRandomPartyStageSetter(precompileAddr, RandomPartyNoRole))
	read := newStatefulPrecompileFunction(readRandomPartySignature, createReadRandomParty(precompileAddr))

	// Construct the contract with no fallback function.
	contract := newStatefulPrecompileWithFunctionSelectors(nil, []*statefulPrecompileFunction{setAdmin, setEnabled, setNone, read})
	return contract
}
