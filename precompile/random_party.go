// (c) 2022, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package precompile

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ava-labs/subnet-evm/vmerrs"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	delim = byte('/')
)

var (
	_ StatefulPrecompileConfig = (*RandomPartyConfig)(nil)

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
	RandomPartyPrecompile StatefulPrecompiledContract = createRandomPartyPrecompile(RandomPartyAddress)
)

var (
	// Random Party function signatures
	StartSignature   = CalculateFunctionSelector("start()")
	SponsorSignature = CalculateFunctionSelector("sponsor()")
	RewardSignature  = CalculateFunctionSelector("reward()")
	CommitSignature  = CalculateFunctionSelector("commit(bytes32)")
	RevealSignature  = CalculateFunctionSelector("reveal(uint256,bytes32)")
	ComputeSignature = CalculateFunctionSelector("compute()")
	ResultSignature  = CalculateFunctionSelector("result(uint256)")
	NextSignature    = CalculateFunctionSelector("next()")
)

var (
	// Random Party errors
	ErrRandomPartyUnderway  = errors.New("random party underway")
	ErrNoRandomPartyStarted = errors.New("no random party started")
	ErrTooLate              = errors.New("too late to interact")
	ErrTooEarly             = errors.New("too early")
	ErrDuplicateReveal      = errors.New("duplicate reveal")
	ErrInsufficientFunds    = errors.New("insufficient funds to perform commit")
)

// RandomPartyConfig specifies the configuration of the Random Party precompile.
type RandomPartyConfig struct {
	BlockTimestamp *big.Int `json:"blockTimestamp"`

	PhaseSeconds *big.Int `json:"phaseSeconds"`
	CommitStake  *big.Int `json:"commitStake"`
}

// Address returns the address of the Random Party contract.
func (c *RandomPartyConfig) Address() common.Address {
	return RandomPartyAddress
}

// Timestamp returns the timestamp at which the Random Party should be enabled
func (c *RandomPartyConfig) Timestamp() *big.Int { return c.BlockTimestamp }

// SetPhaseSeconds persists the configuration for "commit" and "reveal"
// duration to the [StateDB].
func SetPhaseSeconds(state StateDB, duration *big.Int) {
	setBig(state, phaseSecondsKey, duration)
}

// SetCommitState persists the configuration for the required [CommitStake]
// to the [StateDB].
func SetCommitStake(state StateDB, fee *big.Int) {
	setBig(state, commitStakeKey, fee)
}

// Configure initializes the address space of [RandomPartyAddress].
func (c *RandomPartyConfig) Configure(state StateDB) {
	SetPhaseSeconds(state, c.PhaseSeconds)
	SetCommitStake(state, c.CommitStake)
}

// Contract returns the singleton stateful precompiled contract to be used for
// the Random Party.
func (c *RandomPartyConfig) Contract() StatefulPrecompiledContract {
	return RandomPartyPrecompile
}

var (
	// Random Party state keys
	commitDeadlineKey = []byte{0x1}
	revealDeadlineKey = []byte{0x2}
	commitPrefix      = []byte{0x3}
	revealPrefix      = []byte{0x4}
	resultPrefix      = []byte{0x5}
	phaseSecondsKey   = []byte{0x6}
	commitStakeKey    = []byte{0x7}
	commitOwnerPrefix = []byte{0x8}
	rewardPrefix      = []byte{0x9}
)

func fastKey(pfx []byte, n *big.Int) common.Hash {
	val := n.Bytes()
	b := make([]byte, len(pfx)+1+len(val))
	copy(b, pfx)
	b[len(pfx)] = delim
	copy(b[len(pfx)+1:], val)
	return common.BytesToHash(b)
}

func transfer(state StateDB, dest common.Address, amount *big.Int) {
	if !state.Exist(dest) {
		state.CreateAccount(dest) // could've been deleted between interactions
	}
	state.AddBalance(dest, getBig(state, commitStakeKey))
}

func HBigBytes(b *big.Int) []byte {
	return common.BigToHash(b).Bytes()
}

// *math.Big setter/getter
func setBig(state StateDB, key []byte, val *big.Int) {
	state.SetState(RandomPartyAddress, common.BytesToHash(key), common.BigToHash(val))
}
func getBig(state StateDB, key []byte) *big.Int {
	h := state.GetState(RandomPartyAddress, common.BytesToHash(key))
	return new(big.Int).SetBytes(h.Bytes())
}

// counter commmon.Hash setter/getter/deleter
func addCounterHash(state StateDB, pfx []byte, hash common.Hash) *big.Int {
	currV := getBig(state, pfx)
	newV := new(big.Int).Add(currV, common.Big1)
	setBig(state, pfx, newV)
	state.SetState(RandomPartyAddress, fastKey(pfx, currV), hash)
	return currV
}
func getCounterHash(state StateDB, pfx []byte, v *big.Int) common.Hash {
	return state.GetState(RandomPartyAddress, fastKey(pfx, v))
}
func deleteCounterHash(state StateDB, pfx []byte, v *big.Int) {
	state.SetState(RandomPartyAddress, fastKey(pfx, v), common.Hash{})
}

// common.Address setter/getter/deleter
func setIdxAddress(state StateDB, pfx []byte, idx *big.Int, addr common.Address) {
	state.SetState(RandomPartyAddress, fastKey(pfx, idx), addr.Hash())
}
func getIdxAddress(state StateDB, pfx []byte, idx *big.Int) common.Address {
	h := state.GetState(RandomPartyAddress, fastKey(pfx, idx))
	return common.BytesToAddress(h.Bytes())
}
func deleteIdxAddress(state StateDB, pfx []byte, idx *big.Int) {
	state.SetState(RandomPartyAddress, fastKey(pfx, idx), common.Hash{})
}

// packers/unpackers
func PackCommit(hash common.Hash) []byte {
	return append(CommitSignature, hash.Bytes()...)
}
func UnpackCommit(input []byte) (common.Hash, error) {
	if len(input) != common.HashLength {
		return common.Hash{}, fmt.Errorf("invalid input length for commit: %d", len(input))
	}
	return common.BytesToHash(input), nil
}
func PackReveal(v *big.Int, hash common.Hash) []byte {
	r := append(RevealSignature, common.BigToHash(v).Bytes()...)
	return append(r, hash.Bytes()...)
}
func UnpackReveal(input []byte) (*big.Int, common.Hash, error) {
	if len(input) != common.HashLength*2 {
		return nil, common.Hash{}, fmt.Errorf("invalid input length for reveal: %d", len(input))
	}
	return new(big.Int).SetBytes(input[:common.HashLength]), common.BytesToHash(input[common.HashLength:]), nil
}
func PackResult(v *big.Int) []byte {
	return append(ResultSignature, common.BigToHash(v).Bytes()...)
}
func UnpackResult(input []byte) (*big.Int, error) {
	if len(input) != common.HashLength {
		return nil, fmt.Errorf("invalid input length for result: %d", len(input))
	}
	return new(big.Int).SetBytes(input), nil
}

func start(evm PrecompileAccessibleState, callerAddr, addr common.Address, input []byte, suppliedGas uint64, value *big.Int, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	if remainingGas, err = deductGas(suppliedGas, StartGasCost); err != nil {
		return nil, 0, err
	}

	if len(input) != 0 {
		return nil, remainingGas, fmt.Errorf("invalid input length for start: %d", len(input))
	}

	stateDB := evm.GetStateDB()
	commitDeadline := getBig(stateDB, commitDeadlineKey)
	if commitDeadline.Sign() != 0 {
		return nil, remainingGas, ErrRandomPartyUnderway
	}

	if readOnly {
		return nil, remainingGas, vmerrs.ErrWriteProtection
	}

	// Cleanup old commits and reveals
	commits := getBig(stateDB, commitPrefix)
	for i := common.Big0; i.Cmp(commits) < 0; i = new(big.Int).Add(i, common.Big1) {
		if remainingGas, err = deductGas(remainingGas, DeleteGasCost); err != nil {
			return nil, 0, err
		}
		deleteCounterHash(stateDB, commitPrefix, i)
		deleteIdxAddress(stateDB, commitOwnerPrefix, i)
	}
	setBig(stateDB, commitPrefix, common.Big0)
	reveals := getBig(stateDB, revealPrefix)
	for i := common.Big0; i.Cmp(reveals) < 0; i = new(big.Int).Add(i, common.Big1) {
		if remainingGas, err = deductGas(remainingGas, DeleteGasCost); err != nil {
			return nil, 0, err
		}
		deleteCounterHash(stateDB, revealPrefix, i)
		deleteIdxAddress(stateDB, rewardPrefix, i)
	}
	setBig(stateDB, revealPrefix, common.Big0)

	// Set phase deadlines
	phaseDuration := getBig(stateDB, phaseSecondsKey)
	commitDeadline = new(big.Int).Add(evm.BlockTime(), phaseDuration)
	setBig(stateDB, commitDeadlineKey, commitDeadline)
	setBig(stateDB, revealDeadlineKey, new(big.Int).Add(commitDeadline, phaseDuration))
	return []byte{}, remainingGas, nil
}

func sponsor(evm PrecompileAccessibleState, callerAddr, addr common.Address, input []byte, suppliedGas uint64, value *big.Int, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	if remainingGas, err = deductGas(suppliedGas, SponsorGasCost); err != nil {
		return nil, 0, err
	}

	if len(input) != 0 {
		return nil, remainingGas, fmt.Errorf("invalid input length for reward: %d", len(input))
	}

	stateDB := evm.GetStateDB()
	commitDeadline := getBig(stateDB, commitDeadlineKey)
	if commitDeadline.Sign() == 0 {
		return nil, remainingGas, ErrNoRandomPartyStarted
	}
	if evm.BlockTime().Cmp(commitDeadline) >= 0 {
		return nil, remainingGas, ErrTooLate
	}

	rewardAmount := getBig(stateDB, rewardPrefix)

	if readOnly {
		return nil, remainingGas, vmerrs.ErrWriteProtection
	}

	setBig(stateDB, rewardPrefix, new(big.Int).Add(rewardAmount, value))
	return []byte{}, remainingGas, nil
}

func reward(evm PrecompileAccessibleState, callerAddr, addr common.Address, input []byte, suppliedGas uint64, value *big.Int, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	if remainingGas, err = deductGas(suppliedGas, RewardGasCost); err != nil {
		return nil, 0, err
	}

	if len(input) != 0 {
		return nil, remainingGas, fmt.Errorf("invalid input length for reward: %d", len(input))
	}

	stateDB := evm.GetStateDB()
	commitDeadline := getBig(stateDB, commitDeadlineKey)
	if commitDeadline.Sign() == 0 {
		return nil, remainingGas, ErrNoRandomPartyStarted
	}
	return HBigBytes(getBig(stateDB, rewardPrefix)), remainingGas, nil
}

func commit(evm PrecompileAccessibleState, callerAddr, addr common.Address, input []byte, suppliedGas uint64, value *big.Int, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	if remainingGas, err = deductGas(suppliedGas, CommitGasCost); err != nil {
		return nil, 0, err
	}

	stateDB := evm.GetStateDB()
	commitDeadline := getBig(stateDB, commitDeadlineKey)
	if commitDeadline.Sign() == 0 {
		return nil, remainingGas, ErrNoRandomPartyStarted
	}
	if evm.BlockTime().Cmp(commitDeadline) >= 0 {
		return nil, remainingGas, ErrTooLate
	}

	h, err := UnpackCommit(input)
	if err != nil {
		return nil, remainingGas, err
	}

	// Make sure value is sufficient
	commitStakeAmount := getBig(stateDB, commitStakeKey)
	if value == nil || value.Cmp(commitStakeAmount) < 0 {
		return nil, remainingGas, fmt.Errorf("%w: required %d", ErrInsufficientFunds, commitStakeAmount)
	}

	if readOnly {
		return nil, remainingGas, vmerrs.ErrWriteProtection
	}

	idx := addCounterHash(stateDB, commitPrefix, h)
	setIdxAddress(stateDB, commitOwnerPrefix, idx, callerAddr)
	return HBigBytes(idx), remainingGas, nil
}

func reveal(evm PrecompileAccessibleState, callerAddr, addr common.Address, input []byte, suppliedGas uint64, value *big.Int, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	if remainingGas, err = deductGas(suppliedGas, RevealGasCost); err != nil {
		return nil, 0, err
	}

	stateDB := evm.GetStateDB()
	commitDeadline := getBig(stateDB, commitDeadlineKey)
	revealDeadline := getBig(stateDB, revealDeadlineKey)
	if commitDeadline.Sign() == 0 || revealDeadline.Sign() == 0 {
		return nil, remainingGas, ErrNoRandomPartyStarted
	}
	if evm.BlockTime().Cmp(commitDeadline) < 0 {
		return nil, remainingGas, ErrTooEarly
	}
	if evm.BlockTime().Cmp(revealDeadline) >= 0 {
		return nil, remainingGas, ErrTooLate
	}

	idx, preimage, err := UnpackReveal(input)
	if err != nil {
		return nil, remainingGas, err
	}
	largestCommit := getBig(stateDB, commitPrefix)
	if idx.Cmp(largestCommit) >= 0 {
		return nil, remainingGas, fmt.Errorf("no hash with index %d", idx)
	}
	h := getCounterHash(stateDB, commitPrefix, idx)
	if h.Big().Sign() == 0 {
		return nil, remainingGas, ErrDuplicateReveal
	}
	ch := crypto.Keccak256Hash(preimage.Bytes())
	if h != ch {
		return nil, remainingGas, fmt.Errorf("expected %v but got %v (hash %v preimage %v)", h, ch, h, preimage)
	}

	feeRecipient := getIdxAddress(stateDB, commitOwnerPrefix, idx)

	if readOnly {
		return nil, remainingGas, vmerrs.ErrWriteProtection
	}

	transfer(stateDB, feeRecipient, getBig(stateDB, commitStakeKey))

	// prevent duplicate reveals
	deleteCounterHash(stateDB, commitPrefix, idx)
	deleteIdxAddress(stateDB, commitOwnerPrefix, idx)
	nidx := addCounterHash(stateDB, revealPrefix, preimage)
	setIdxAddress(stateDB, rewardPrefix, nidx, feeRecipient)
	return []byte{}, remainingGas, nil
}

func compute(evm PrecompileAccessibleState, callerAddr, addr common.Address, input []byte, suppliedGas uint64, value *big.Int, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	if remainingGas, err = deductGas(suppliedGas, ComputeGasCost); err != nil {
		return nil, 0, err
	}

	stateDB := evm.GetStateDB()
	revealDeadline := getBig(stateDB, revealDeadlineKey)
	if revealDeadline.Sign() == 0 {
		return nil, remainingGas, ErrNoRandomPartyStarted
	}
	if evm.BlockTime().Cmp(revealDeadline) < 0 {
		return nil, remainingGas, ErrTooEarly
	}

	if len(input) != 0 {
		return nil, remainingGas, fmt.Errorf("invalid input length for compute: %d", len(input))
	}

	reveals := getBig(stateDB, revealPrefix)
	rewardAmount := getBig(stateDB, rewardPrefix)
	eachRewardAmount := common.Big0
	shouldReward := false
	if reveals.Sign() > 0 && rewardAmount.Sign() > 0 {
		eachRewardAmount = new(big.Int).Div(rewardAmount, reveals)
		shouldReward = true
	}
	ri := reveals.Uint64()
	preimages := make([]byte, common.HashLength*ri)
	for i := uint64(0); i < ri; i++ {
		if remainingGas, err = deductGas(remainingGas, ComputeItemCost); err != nil {
			return nil, 0, err
		}
		bi := new(big.Int).SetUint64(i)
		copy(preimages[i:i+common.HashLength], getCounterHash(stateDB, revealPrefix, bi).Bytes())

		if !shouldReward {
			continue
		}

		if remainingGas, err = deductGas(remainingGas, ComputeRewardCost); err != nil {
			return nil, 0, err
		}
		rewardRecipient := getIdxAddress(stateDB, rewardPrefix, bi)
		transfer(stateDB, rewardRecipient, eachRewardAmount)
	}

	if readOnly {
		return nil, remainingGas, vmerrs.ErrWriteProtection
	}

	setBig(stateDB, commitDeadlineKey, common.Big0)
	setBig(stateDB, revealDeadlineKey, common.Big0)
	setBig(stateDB, rewardPrefix, common.Big0)
	addCounterHash(stateDB, resultPrefix, crypto.Keccak256Hash(preimages))
	return []byte{}, remainingGas, nil
}

func result(evm PrecompileAccessibleState, callerAddr, addr common.Address, input []byte, suppliedGas uint64, value *big.Int, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	if remainingGas, err = deductGas(suppliedGas, ResultCost); err != nil {
		return nil, 0, err
	}

	stateDB := evm.GetStateDB()
	round, err := UnpackResult(input)
	if err != nil {
		return nil, remainingGas, err
	}
	return getCounterHash(stateDB, resultPrefix, round).Bytes(), remainingGas, nil
}

func next(evm PrecompileAccessibleState, callerAddr, addr common.Address, input []byte, suppliedGas uint64, value *big.Int, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	if remainingGas, err = deductGas(suppliedGas, NextCost); err != nil {
		return nil, 0, err
	}

	if len(input) != 0 {
		return nil, remainingGas, fmt.Errorf("invalid input length for next: %d", len(input))
	}

	stateDB := evm.GetStateDB()
	return HBigBytes(getBig(stateDB, resultPrefix)), remainingGas, nil
}

// createRandomPartyPrecompile returns a StatefulPrecompiledContrac
func createRandomPartyPrecompile(precompileAddr common.Address) StatefulPrecompiledContract {
	startFunc := newStatefulPrecompileFunction(StartSignature, start)
	sponsorFunc := newStatefulPrecompileFunction(SponsorSignature, sponsor)
	rewardFunc := newStatefulPrecompileFunction(RewardSignature, reward)
	commitFunc := newStatefulPrecompileFunction(CommitSignature, commit)
	revealFunc := newStatefulPrecompileFunction(RevealSignature, reveal)
	computeFunc := newStatefulPrecompileFunction(ComputeSignature, compute)
	resultFunc := newStatefulPrecompileFunction(ResultSignature, result)
	nextFunc := newStatefulPrecompileFunction(NextSignature, next)

	// Construct the contract with no fallback function.
	contract := newStatefulPrecompileWithFunctionSelectors(nil, []*statefulPrecompileFunction{
		startFunc, sponsorFunc, rewardFunc, commitFunc, revealFunc, computeFunc, resultFunc, nextFunc,
	})
	return contract
}
