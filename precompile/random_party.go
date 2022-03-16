// (c) 2019-2020, Ava Labs, Inc. All rights reserved.
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

// -> Start() => commitDeadline=time+1 hour/revealDeadline=time+2 hour; del commits; del reveals; commits=0; reveals=0
// < Commit Deadline (if 0, no ongoing)
// -> Commit(hash) => com1=hash;commits=1 [also deducts commitFee but MM
// doesn't reflect]
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
	startSignature   = CalculateFunctionSelector("start()")
	sponsorSignature = CalculateFunctionSelector("sponsor()")
	rewardSignature  = CalculateFunctionSelector("reward()")
	commitSignature  = CalculateFunctionSelector("commit(bytes32)")
	revealSignature  = CalculateFunctionSelector("reveal(uint256,bytes32)")
	computeSignature = CalculateFunctionSelector("compute()")
	resultSignature  = CalculateFunctionSelector("result(uint256)")
	nextSignature    = CalculateFunctionSelector("next()")

	delim = byte('/')

	ErrRandomPartyUnderway  = errors.New("random party underway")
	ErrNoRandomPartyStarted = errors.New("no random party started")
	ErrTooLate              = errors.New("too late to interact")
	ErrTooEarly             = errors.New("too early")
	ErrDuplicateReveal      = errors.New("duplicate reveal")
	ErrInsufficientFunds    = errors.New("insufficient funds to perform commit")
)

// RandomPartyConfig specifies the configuration of the allow list.
// Specifies the block timestamp at which it goes into effect as well as the initial set of allow list admins.
type RandomPartyConfig struct {
	BlockTimestamp *big.Int `json:"blockTimestamp"`

	PhaseDuration *big.Int `json:"phaseDuration"` // (seconds) recommend 1 hour
	CommitFee     *big.Int `json:"commitFee"`
}

// Address returns the address of the random party contract.
func (c *RandomPartyConfig) Address() common.Address {
	return RandomPartyAddress
}

// Timestamp returns the timestamp at which the allow list should be enabled
func (c *RandomPartyConfig) Timestamp() *big.Int { return c.BlockTimestamp }

// Make public for tests
func SetPhaseDuration(state StateDB, duration *big.Int) {
	setRandomPartyBig(state, phaseDurationKey, duration)
}
func SetCommitFee(state StateDB, fee *big.Int) {
	setRandomPartyBig(state, commitFeeKey, fee)
}

// Configure initializes the address space of [precompileAddr] by initializing the role of each of
// the addresses in [RandomPartyAdmins].
func (c *RandomPartyConfig) Configure(state StateDB) {
	SetPhaseDuration(state, c.PhaseDuration)
	SetCommitFee(state, c.CommitFee)
}

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
	phaseDurationKey  = []byte{0x6}
	commitFeeKey      = []byte{0x7}
	commitOwnerPrefix = []byte{0x8}
	rewardPrefix      = []byte{0x9}
)

func setRandomPartyBig(state StateDB, key []byte, val *big.Int) {
	state.SetState(RandomPartyAddress, common.BytesToHash(key), common.BigToHash(val))
}

func getRandomPartyBig(state StateDB, key []byte) *big.Int {
	h := state.GetState(RandomPartyAddress, common.BytesToHash(key))
	return new(big.Int).SetBytes(h.Bytes())
}

func addCounterHash(state StateDB, prefix []byte, hash common.Hash) *big.Int {
	currV := getRandomPartyBig(state, prefix)
	newV := new(big.Int).Add(currV, common.Big1)
	setRandomPartyBig(state, prefix, newV)
	k := append(prefix, delim)
	k = append(k, currV.Bytes()...)
	state.SetState(RandomPartyAddress, common.BytesToHash(k), hash)
	return currV
}

func getCounterHash(state StateDB, prefix []byte, v *big.Int) common.Hash {
	k := append(prefix, delim)
	k = append(k, v.Bytes()...)
	return state.GetState(RandomPartyAddress, common.BytesToHash(k))
}

func deleteCounterHash(state StateDB, prefix []byte, v *big.Int) {
	k := append(prefix, delim)
	k = append(k, v.Bytes()...)
	state.SetState(RandomPartyAddress, common.BytesToHash(k), common.Hash{})
}

func addResultHash(state StateDB, value common.Hash) {
	currV := getRandomPartyBig(state, resultPrefix)
	newV := new(big.Int).Add(currV, common.Big1)
	setRandomPartyBig(state, resultPrefix, newV)
	k := append(resultPrefix, delim)
	k = append(k, currV.Bytes()...)
	state.SetState(RandomPartyAddress, common.BytesToHash(k), value)
}

func getResultHash(state StateDB, round *big.Int) common.Hash {
	k := append(resultPrefix, delim)
	k = append(k, round.Bytes()...)
	return state.GetState(RandomPartyAddress, common.BytesToHash(k))
}

func setRandomPartyFundRecipient(state StateDB, pfx []byte, idx *big.Int, addr common.Address) {
	k := append(pfx, delim)
	k = append(k, idx.Bytes()...)
	state.SetState(RandomPartyAddress, common.BytesToHash(k), addr.Hash())
}

func getRandomPartyFundRecipient(state StateDB, pfx []byte, idx *big.Int) common.Address {
	k := append(pfx, delim)
	k = append(k, idx.Bytes()...)
	h := state.GetState(RandomPartyAddress, common.BytesToHash(k))
	return common.BytesToAddress(h.Bytes())
}

func deleteRandomPartyFundRecipient(state StateDB, pfx []byte, idx *big.Int) {
	k := append(pfx, delim)
	k = append(k, idx.Bytes()...)
	state.SetState(RandomPartyAddress, common.BytesToHash(k), common.Hash{})
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

// TODO: allow person that spins up a random party to provide an incentive pool
// that is shared equally amongest all revealers
func startRandomParty(evm PrecompileAccessibleState, callerAddr, addr common.Address, input []byte, suppliedGas uint64, value *big.Int, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	if remainingGas, err = deductGas(suppliedGas, StartGasCost); err != nil {
		return nil, 0, err
	}

	if len(input) != 0 {
		return nil, remainingGas, fmt.Errorf("invalid input length for start: %d", len(input))
	}

	stateDB := evm.GetStateDB()
	commitDeadline := getRandomPartyBig(stateDB, commitDeadlineKey)
	if commitDeadline.Sign() != 0 {
		return nil, remainingGas, ErrRandomPartyUnderway
	}

	if readOnly {
		return nil, remainingGas, vmerrs.ErrWriteProtection
	}

	commits := getRandomPartyBig(stateDB, commitPrefix).Uint64() // should never have this many commits
	for i := uint64(0); i < commits; i++ {
		if remainingGas, err = deductGas(remainingGas, DeleteGasCost); err != nil {
			return nil, 0, err
		}
		idx := new(big.Int).SetUint64(i)
		deleteCounterHash(stateDB, commitPrefix, idx)
		deleteRandomPartyFundRecipient(stateDB, commitOwnerPrefix, idx)
	}
	setRandomPartyBig(stateDB, commitPrefix, common.Big0)

	reveals := getRandomPartyBig(stateDB, revealPrefix).Uint64() // should never have this many commits
	for i := uint64(0); i < reveals; i++ {
		if remainingGas, err = deductGas(remainingGas, DeleteGasCost); err != nil {
			return nil, 0, err
		}
		idx := new(big.Int).SetUint64(i)
		deleteCounterHash(stateDB, revealPrefix, idx)
		deleteRandomPartyFundRecipient(stateDB, rewardPrefix, idx)
	}
	setRandomPartyBig(stateDB, revealPrefix, common.Big0)

	phaseDuration := getRandomPartyBig(stateDB, phaseDurationKey)
	commitDeadline = new(big.Int).Add(evm.BlockTime(), phaseDuration)
	setRandomPartyBig(stateDB, commitDeadlineKey, commitDeadline)
	setRandomPartyBig(stateDB, revealDeadlineKey, new(big.Int).Add(commitDeadline, phaseDuration))
	return []byte{}, remainingGas, nil
}

func sponsorRandomParty(evm PrecompileAccessibleState, callerAddr, addr common.Address, input []byte, suppliedGas uint64, value *big.Int, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	if remainingGas, err = deductGas(suppliedGas, SponsorGasCost); err != nil {
		return nil, 0, err
	}

	if len(input) != 0 {
		return nil, remainingGas, fmt.Errorf("invalid input length for reward: %d", len(input))
	}

	stateDB := evm.GetStateDB()
	commitDeadline := getRandomPartyBig(stateDB, commitDeadlineKey)
	if commitDeadline.Sign() == 0 {
		return nil, remainingGas, ErrNoRandomPartyStarted
	}
	// Only allow sponsoring while people are still committing
	if evm.BlockTime().Cmp(commitDeadline) >= 0 {
		return nil, remainingGas, ErrTooLate
	}

	// Make sure value is sufficient
	rewardAmount := getRandomPartyBig(stateDB, rewardPrefix)

	if readOnly {
		return nil, remainingGas, vmerrs.ErrWriteProtection
	}

	setRandomPartyBig(stateDB, rewardPrefix, new(big.Int).Add(rewardAmount, value))
	return []byte{}, remainingGas, nil
}

func rewardRandomParty(evm PrecompileAccessibleState, callerAddr, addr common.Address, input []byte, suppliedGas uint64, value *big.Int, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	if remainingGas, err = deductGas(suppliedGas, RewardGasCost); err != nil {
		return nil, 0, err
	}

	if len(input) != 0 {
		return nil, remainingGas, fmt.Errorf("invalid input length for reward: %d", len(input))
	}

	stateDB := evm.GetStateDB()
	commitDeadline := getRandomPartyBig(stateDB, commitDeadlineKey)
	if commitDeadline.Sign() == 0 {
		return nil, remainingGas, ErrNoRandomPartyStarted
	}

	return common.BigToHash(getRandomPartyBig(stateDB, rewardPrefix)).Bytes(), remainingGas, nil
}

func commitRandomParty(evm PrecompileAccessibleState, callerAddr, addr common.Address, input []byte, suppliedGas uint64, value *big.Int, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	if remainingGas, err = deductGas(suppliedGas, CommitGasCost); err != nil {
		return nil, 0, err
	}

	stateDB := evm.GetStateDB()
	commitDeadline := getRandomPartyBig(stateDB, commitDeadlineKey)
	if commitDeadline.Sign() == 0 {
		return nil, remainingGas, ErrNoRandomPartyStarted
	}
	if evm.BlockTime().Cmp(commitDeadline) >= 0 {
		return nil, remainingGas, ErrTooLate
	}

	h, err := UnpackCommitRandomParty(input)
	if err != nil {
		return nil, remainingGas, err
	}

	// Make sure value is sufficient
	commitFeeAmount := getRandomPartyBig(stateDB, commitFeeKey)
	if value == nil || value.Cmp(commitFeeAmount) < 0 {
		return nil, remainingGas, fmt.Errorf("%w: required %d", ErrInsufficientFunds, commitFeeAmount)
	}

	if readOnly {
		return nil, remainingGas, vmerrs.ErrWriteProtection
	}

	idx := addCounterHash(stateDB, commitPrefix, h)
	setRandomPartyFundRecipient(stateDB, commitOwnerPrefix, idx, callerAddr)
	return common.BigToHash(idx).Bytes(), remainingGas, nil
}

func revealRandomParty(evm PrecompileAccessibleState, callerAddr, addr common.Address, input []byte, suppliedGas uint64, value *big.Int, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	if remainingGas, err = deductGas(suppliedGas, RevealGasCost); err != nil {
		return nil, 0, err
	}

	stateDB := evm.GetStateDB()
	commitDeadline := getRandomPartyBig(stateDB, commitDeadlineKey)
	revealDeadline := getRandomPartyBig(stateDB, revealDeadlineKey)
	if commitDeadline.Sign() == 0 || revealDeadline.Sign() == 0 {
		return nil, remainingGas, ErrNoRandomPartyStarted
	}
	if evm.BlockTime().Cmp(commitDeadline) < 0 {
		return nil, remainingGas, ErrTooEarly
	}
	if evm.BlockTime().Cmp(revealDeadline) >= 0 {
		return nil, remainingGas, ErrTooLate
	}

	idx, preimage, err := UnpackRevealRandomParty(input)
	if err != nil {
		return nil, remainingGas, err
	}
	largestCommit := getRandomPartyBig(stateDB, commitPrefix)
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

	feeRecipient := getRandomPartyFundRecipient(stateDB, commitOwnerPrefix, idx)

	if readOnly {
		return nil, remainingGas, vmerrs.ErrWriteProtection
	}

	if !stateDB.Exist(feeRecipient) {
		stateDB.CreateAccount(feeRecipient) // could've been deleted between interactions
	}
	stateDB.AddBalance(feeRecipient, getRandomPartyBig(stateDB, commitFeeKey))

	// prevent duplicate reveals
	deleteCounterHash(stateDB, commitPrefix, idx)
	deleteRandomPartyFundRecipient(stateDB, commitOwnerPrefix, idx)
	nidx := addCounterHash(stateDB, revealPrefix, preimage)
	setRandomPartyFundRecipient(stateDB, rewardPrefix, nidx, feeRecipient)
	return []byte{}, remainingGas, nil
}

func computeRandomParty(evm PrecompileAccessibleState, callerAddr, addr common.Address, input []byte, suppliedGas uint64, value *big.Int, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	if remainingGas, err = deductGas(suppliedGas, ComputeGasCost); err != nil {
		return nil, 0, err
	}

	stateDB := evm.GetStateDB()
	revealDeadline := getRandomPartyBig(stateDB, revealDeadlineKey)
	if revealDeadline.Sign() == 0 {
		return nil, remainingGas, ErrNoRandomPartyStarted
	}
	if evm.BlockTime().Cmp(revealDeadline) < 0 {
		return nil, remainingGas, ErrTooEarly
	}

	if len(input) != 0 {
		return nil, remainingGas, fmt.Errorf("invalid input length for compute: %d", len(input))
	}

	reveals := getRandomPartyBig(stateDB, revealPrefix)
	rewardAmount := getRandomPartyBig(stateDB, rewardPrefix)
	eachRewardAmount := new(big.Int).Div(rewardAmount, reveals)
	shouldReward := eachRewardAmount.Sign() > 0
	ri := reveals.Uint64()
	preimages := make([]byte, common.HashLength*ri)
	for i := uint64(0); i < ri; i++ {
		if remainingGas, err = deductGas(remainingGas, ComputeItemCost); err != nil {
			return nil, 0, err
		}
		bi := new(big.Int).SetUint64(i)
		copy(preimages[i:i+common.HashLength], getCounterHash(stateDB, revealPrefix, bi).Bytes())
		if shouldReward {
			if remainingGas, err = deductGas(remainingGas, ComputeRewardCost); err != nil {
				return nil, 0, err
			}
			rewardRecipient := getRandomPartyFundRecipient(stateDB, rewardPrefix, bi)
			if !stateDB.Exist(rewardRecipient) {
				stateDB.CreateAccount(rewardRecipient) // could've been deleted between interactions
			}
			stateDB.AddBalance(rewardRecipient, eachRewardAmount)
		}
	}

	if readOnly {
		return nil, remainingGas, vmerrs.ErrWriteProtection
	}

	setRandomPartyBig(stateDB, commitDeadlineKey, common.Big0)
	setRandomPartyBig(stateDB, revealDeadlineKey, common.Big0)
	addResultHash(stateDB, crypto.Keccak256Hash(preimages))
	return []byte{}, remainingGas, nil
}

func resultRandomParty(evm PrecompileAccessibleState, callerAddr, addr common.Address, input []byte, suppliedGas uint64, value *big.Int, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	if remainingGas, err = deductGas(suppliedGas, ResultCost); err != nil {
		return nil, 0, err
	}

	stateDB := evm.GetStateDB()
	round, err := UnpackResultRandomParty(input)
	if err != nil {
		return nil, remainingGas, err
	}

	return getResultHash(stateDB, round).Bytes(), remainingGas, nil
}

func nextRandomParty(evm PrecompileAccessibleState, callerAddr, addr common.Address, input []byte, suppliedGas uint64, value *big.Int, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	if remainingGas, err = deductGas(suppliedGas, NextCost); err != nil {
		return nil, 0, err
	}

	if len(input) != 0 {
		return nil, remainingGas, fmt.Errorf("invalid input length for next: %d", len(input))
	}

	stateDB := evm.GetStateDB()
	return common.BigToHash(getRandomPartyBig(stateDB, resultPrefix)).Bytes(), remainingGas, nil
}

// createRandomPartyPrecompile returns a StatefulPrecompiledContrac
func createRandomPartyPrecompile(precompileAddr common.Address) StatefulPrecompiledContract {
	start := newStatefulPrecompileFunction(startSignature, startRandomParty)
	sponsor := newStatefulPrecompileFunction(sponsorSignature, sponsorRandomParty)
	reward := newStatefulPrecompileFunction(rewardSignature, rewardRandomParty)
	commit := newStatefulPrecompileFunction(commitSignature, commitRandomParty)
	reveal := newStatefulPrecompileFunction(revealSignature, revealRandomParty)
	compute := newStatefulPrecompileFunction(computeSignature, computeRandomParty)
	result := newStatefulPrecompileFunction(resultSignature, resultRandomParty)
	next := newStatefulPrecompileFunction(nextSignature, nextRandomParty)

	// Construct the contract with no fallback function.
	contract := newStatefulPrecompileWithFunctionSelectors(nil, []*statefulPrecompileFunction{
		start, sponsor, reward, commit, reveal, compute, result, next,
	})
	return contract
}
