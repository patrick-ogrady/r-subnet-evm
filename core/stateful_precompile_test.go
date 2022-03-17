// (c) 2019-2020, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package core

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ava-labs/subnet-evm/core/rawdb"
	"github.com/ava-labs/subnet-evm/core/state"
	"github.com/ava-labs/subnet-evm/precompile"
	"github.com/ava-labs/subnet-evm/vmerrs"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
)

type mockAccessibleState struct {
	state     *state.StateDB
	blockTime *big.Int
}

func (m *mockAccessibleState) GetStateDB() precompile.StateDB { return m.state }
func (m *mockAccessibleState) BlockTime() *big.Int            { return m.blockTime }

// This test is added within the core package so that it can import all of the required code
// without creating any import cycles
func TestContractDeployerAllowListRun(t *testing.T) {
	type test struct {
		caller         common.Address
		precompileAddr common.Address
		input          func() []byte
		suppliedGas    uint64
		readOnly       bool

		expectedRes []byte
		expectedErr string

		assertState func(t *testing.T, state *state.StateDB)
	}

	adminAddr := common.HexToAddress("0x8db97C7cEcE249c2b98bDC0226Cc4C2A57BF52FC")
	noRoleAddr := common.HexToAddress("0xF60C45c607D0f41687c94C314d300f483661E13a")

	for name, test := range map[string]test{
		"set admin": {
			caller:         adminAddr,
			precompileAddr: precompile.ContractDeployerAllowListAddress,
			input: func() []byte {
				input, err := precompile.PackModifyAllowList(noRoleAddr, precompile.AllowListAdmin)
				if err != nil {
					panic(err)
				}
				return input
			},
			suppliedGas: precompile.ModifyAllowListGasCost,
			readOnly:    false,
			expectedRes: []byte{},
			assertState: func(t *testing.T, state *state.StateDB) {
				res := precompile.GetContractDeployerAllowListStatus(state, adminAddr)
				assert.Equal(t, precompile.AllowListAdmin, res)

				res = precompile.GetContractDeployerAllowListStatus(state, noRoleAddr)
				assert.Equal(t, precompile.AllowListAdmin, res)
			},
		},
		"set deployer": {
			caller:         adminAddr,
			precompileAddr: precompile.ContractDeployerAllowListAddress,
			input: func() []byte {
				input, err := precompile.PackModifyAllowList(noRoleAddr, precompile.AllowListEnabled)
				if err != nil {
					panic(err)
				}
				return input
			},
			suppliedGas: precompile.ModifyAllowListGasCost,
			readOnly:    false,
			expectedRes: []byte{},
			assertState: func(t *testing.T, state *state.StateDB) {
				res := precompile.GetContractDeployerAllowListStatus(state, adminAddr)
				assert.Equal(t, precompile.AllowListAdmin, res)

				res = precompile.GetContractDeployerAllowListStatus(state, noRoleAddr)
				assert.Equal(t, precompile.AllowListEnabled, res)
			},
		},
		"set no role": {
			caller:         adminAddr,
			precompileAddr: precompile.ContractDeployerAllowListAddress,
			input: func() []byte {
				input, err := precompile.PackModifyAllowList(adminAddr, precompile.AllowListNoRole)
				if err != nil {
					panic(err)
				}
				return input
			},
			suppliedGas: precompile.ModifyAllowListGasCost,
			readOnly:    false,
			expectedRes: []byte{},
			assertState: func(t *testing.T, state *state.StateDB) {
				res := precompile.GetContractDeployerAllowListStatus(state, adminAddr)
				assert.Equal(t, precompile.AllowListNoRole, res)
			},
		},
		"set no role from non-admin": {
			caller:         noRoleAddr,
			precompileAddr: precompile.ContractDeployerAllowListAddress,
			input: func() []byte {
				input, err := precompile.PackModifyAllowList(adminAddr, precompile.AllowListNoRole)
				if err != nil {
					panic(err)
				}
				return input
			},
			suppliedGas: precompile.ModifyAllowListGasCost,
			readOnly:    false,
			expectedErr: precompile.ErrCannotModifyAllowList.Error(),
		},
		"set deployer from non-admin": {
			caller:         noRoleAddr,
			precompileAddr: precompile.ContractDeployerAllowListAddress,
			input: func() []byte {
				input, err := precompile.PackModifyAllowList(adminAddr, precompile.AllowListEnabled)
				if err != nil {
					panic(err)
				}
				return input
			},
			suppliedGas: precompile.ModifyAllowListGasCost,
			readOnly:    false,
			expectedErr: precompile.ErrCannotModifyAllowList.Error(),
		},
		"set admin from non-admin": {
			caller:         noRoleAddr,
			precompileAddr: precompile.ContractDeployerAllowListAddress,
			input: func() []byte {
				input, err := precompile.PackModifyAllowList(adminAddr, precompile.AllowListAdmin)
				if err != nil {
					panic(err)
				}
				return input
			},
			suppliedGas: precompile.ModifyAllowListGasCost,
			readOnly:    false,
			expectedErr: precompile.ErrCannotModifyAllowList.Error(),
		},
		"set no role with readOnly enabled": {
			caller:         adminAddr,
			precompileAddr: precompile.ContractDeployerAllowListAddress,
			input: func() []byte {
				input, err := precompile.PackModifyAllowList(adminAddr, precompile.AllowListNoRole)
				if err != nil {
					panic(err)
				}
				return input
			},
			suppliedGas: precompile.ModifyAllowListGasCost,
			readOnly:    true,
			expectedErr: vmerrs.ErrWriteProtection.Error(),
		},
		"set no role insufficient gas": {
			caller:         adminAddr,
			precompileAddr: precompile.ContractDeployerAllowListAddress,
			input: func() []byte {
				input, err := precompile.PackModifyAllowList(adminAddr, precompile.AllowListNoRole)
				if err != nil {
					panic(err)
				}
				return input
			},
			suppliedGas: precompile.ModifyAllowListGasCost - 1,
			readOnly:    false,
			expectedErr: vmerrs.ErrOutOfGas.Error(),
		},
		"read allow list no role": {
			caller:         noRoleAddr,
			precompileAddr: precompile.ContractDeployerAllowListAddress,
			input: func() []byte {
				return precompile.PackReadAllowList(noRoleAddr)
			},
			suppliedGas: precompile.ReadAllowListGasCost,
			readOnly:    false,
			expectedRes: common.Hash(precompile.AllowListNoRole).Bytes(),
			assertState: func(t *testing.T, state *state.StateDB) {
				res := precompile.GetContractDeployerAllowListStatus(state, noRoleAddr)
				assert.Equal(t, precompile.AllowListNoRole, res)
			},
		},
		"read allow list admin role": {
			caller:         adminAddr,
			precompileAddr: precompile.ContractDeployerAllowListAddress,
			input: func() []byte {
				return precompile.PackReadAllowList(noRoleAddr)
			},
			suppliedGas: precompile.ReadAllowListGasCost,
			readOnly:    false,
			expectedRes: common.Hash(precompile.AllowListNoRole).Bytes(),
			assertState: func(t *testing.T, state *state.StateDB) {
				res := precompile.GetContractDeployerAllowListStatus(state, adminAddr)
				assert.Equal(t, precompile.AllowListAdmin, res)
			},
		},
		"read allow list with readOnly enabled": {
			caller:         adminAddr,
			precompileAddr: precompile.ContractDeployerAllowListAddress,
			input: func() []byte {
				return precompile.PackReadAllowList(noRoleAddr)
			},
			suppliedGas: precompile.ReadAllowListGasCost,
			readOnly:    true,
			expectedRes: common.Hash(precompile.AllowListNoRole).Bytes(),
			assertState: func(t *testing.T, state *state.StateDB) {
				res := precompile.GetContractDeployerAllowListStatus(state, adminAddr)
				assert.Equal(t, precompile.AllowListAdmin, res)
			},
		},
		"read allow list out of gas": {
			caller:         adminAddr,
			precompileAddr: precompile.ContractDeployerAllowListAddress,
			input: func() []byte {
				return precompile.PackReadAllowList(noRoleAddr)
			},
			suppliedGas: precompile.ReadAllowListGasCost - 1,
			readOnly:    true,
			expectedErr: vmerrs.ErrOutOfGas.Error(),
		},
	} {
		t.Run(name, func(t *testing.T) {
			db := rawdb.NewMemoryDatabase()
			state, err := state.New(common.Hash{}, state.NewDatabase(db), nil)
			if err != nil {
				t.Fatal(err)
			}

			// Set up the state so that each address has the expected permissions at the start.
			precompile.SetContractDeployerAllowListStatus(state, adminAddr, precompile.AllowListAdmin)
			precompile.SetContractDeployerAllowListStatus(state, noRoleAddr, precompile.AllowListNoRole)

			ret, remainingGas, err := precompile.ContractDeployerAllowListPrecompile.Run(&mockAccessibleState{state: state}, test.caller, test.precompileAddr, test.input(), test.suppliedGas, nil, test.readOnly)
			if len(test.expectedErr) != 0 {
				if err == nil {
					assert.Failf(t, "run expectedly passed without error", "expected error %q", test.expectedErr)
				} else {
					assert.True(t, strings.Contains(err.Error(), test.expectedErr), "expected error (%s) to contain substring (%s)", err, test.expectedErr)
				}
				return
			}

			if err != nil {
				t.Fatal(err)
			}

			assert.Equal(t, uint64(0), remainingGas)
			assert.Equal(t, test.expectedRes, ret)

			test.assertState(t, state)
		})
	}
}

func TestContractNativeMinterRun(t *testing.T) {
	type test struct {
		caller         common.Address
		precompileAddr common.Address
		input          func() []byte
		suppliedGas    uint64
		readOnly       bool

		expectedRes []byte
		expectedErr string

		assertState func(t *testing.T, state *state.StateDB)
	}

	adminAddr := common.HexToAddress("0x8db97C7cEcE249c2b98bDC0226Cc4C2A57BF52FC")
	allowAddr := common.HexToAddress("0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B")
	noRoleAddr := common.HexToAddress("0xF60C45c607D0f41687c94C314d300f483661E13a")

	for name, test := range map[string]test{
		"mint funds from no role fails": {
			caller:         noRoleAddr,
			precompileAddr: precompile.ContractNativeMinterAddress,
			input: func() []byte {
				input, err := precompile.PackMintInput(noRoleAddr, common.Big1)
				if err != nil {
					panic(err)
				}
				return input
			},
			suppliedGas: precompile.MintGasCost,
			readOnly:    false,
			expectedErr: precompile.ErrCannotMint.Error(),
		},
		"mint funds from allow address": {
			caller:         allowAddr,
			precompileAddr: precompile.ContractNativeMinterAddress,
			input: func() []byte {
				input, err := precompile.PackMintInput(allowAddr, common.Big1)
				if err != nil {
					panic(err)
				}
				return input
			},
			suppliedGas: precompile.MintGasCost,
			readOnly:    false,
			expectedRes: []byte{},
			assertState: func(t *testing.T, state *state.StateDB) {
				res := precompile.GetContractNativeMinterStatus(state, allowAddr)
				assert.Equal(t, precompile.AllowListEnabled, res)

				assert.Equal(t, common.Big1, state.GetBalance(allowAddr), "expected minted funds")
			},
		},
		"mint funds from admin address": {
			caller:         adminAddr,
			precompileAddr: precompile.ContractNativeMinterAddress,
			input: func() []byte {
				input, err := precompile.PackMintInput(adminAddr, common.Big1)
				if err != nil {
					panic(err)
				}
				return input
			},
			suppliedGas: precompile.MintGasCost,
			readOnly:    false,
			expectedRes: []byte{},
			assertState: func(t *testing.T, state *state.StateDB) {
				res := precompile.GetContractNativeMinterStatus(state, adminAddr)
				assert.Equal(t, precompile.AllowListAdmin, res)

				assert.Equal(t, common.Big1, state.GetBalance(adminAddr), "expected minted funds")
			},
		},
		"mint max big funds": {
			caller:         adminAddr,
			precompileAddr: precompile.ContractNativeMinterAddress,
			input: func() []byte {
				input, err := precompile.PackMintInput(adminAddr, math.MaxBig256)
				if err != nil {
					panic(err)
				}
				return input
			},
			suppliedGas: precompile.MintGasCost,
			readOnly:    false,
			expectedRes: []byte{},
			assertState: func(t *testing.T, state *state.StateDB) {
				res := precompile.GetContractNativeMinterStatus(state, adminAddr)
				assert.Equal(t, precompile.AllowListAdmin, res)

				assert.Equal(t, math.MaxBig256, state.GetBalance(adminAddr), "expected minted funds")
			},
		},
		"readOnly mint with noRole fails": {
			caller:         noRoleAddr,
			precompileAddr: precompile.ContractNativeMinterAddress,
			input: func() []byte {
				input, err := precompile.PackMintInput(adminAddr, common.Big1)
				if err != nil {
					panic(err)
				}
				return input
			},
			suppliedGas: precompile.MintGasCost,
			readOnly:    true,
			expectedErr: vmerrs.ErrWriteProtection.Error(),
		},
		"readOnly mint with allow role fails": {
			caller:         allowAddr,
			precompileAddr: precompile.ContractNativeMinterAddress,
			input: func() []byte {
				input, err := precompile.PackMintInput(allowAddr, common.Big1)
				if err != nil {
					panic(err)
				}
				return input
			},
			suppliedGas: precompile.MintGasCost,
			readOnly:    true,
			expectedErr: vmerrs.ErrWriteProtection.Error(),
		},
		"readOnly mint with admin role fails": {
			caller:         adminAddr,
			precompileAddr: precompile.ContractNativeMinterAddress,
			input: func() []byte {
				input, err := precompile.PackMintInput(adminAddr, common.Big1)
				if err != nil {
					panic(err)
				}
				return input
			},
			suppliedGas: precompile.MintGasCost,
			readOnly:    true,
			expectedErr: vmerrs.ErrWriteProtection.Error(),
		},
		"insufficient gas mint from admin": {
			caller:         adminAddr,
			precompileAddr: precompile.ContractNativeMinterAddress,
			input: func() []byte {
				input, err := precompile.PackMintInput(allowAddr, common.Big1)
				if err != nil {
					panic(err)
				}
				return input
			},
			suppliedGas: precompile.MintGasCost - 1,
			readOnly:    false,
			expectedErr: vmerrs.ErrOutOfGas.Error(),
		},
		"read from noRole address": {
			caller:         noRoleAddr,
			precompileAddr: precompile.ContractNativeMinterAddress,
			input: func() []byte {
				return precompile.PackReadAllowList(noRoleAddr)
			},
			suppliedGas: precompile.ReadAllowListGasCost,
			readOnly:    false,
			expectedRes: common.Hash(precompile.AllowListNoRole).Bytes(),
			assertState: func(t *testing.T, state *state.StateDB) {},
		},
		"read from noRole address readOnly enabled": {
			caller:         noRoleAddr,
			precompileAddr: precompile.ContractNativeMinterAddress,
			input: func() []byte {
				return precompile.PackReadAllowList(noRoleAddr)
			},
			suppliedGas: precompile.ReadAllowListGasCost,
			readOnly:    true,
			expectedRes: common.Hash(precompile.AllowListNoRole).Bytes(),
			assertState: func(t *testing.T, state *state.StateDB) {},
		},
		"read from noRole address with insufficient gas": {
			caller:         noRoleAddr,
			precompileAddr: precompile.ContractNativeMinterAddress,
			input: func() []byte {
				return precompile.PackReadAllowList(noRoleAddr)
			},
			suppliedGas: precompile.ReadAllowListGasCost - 1,
			readOnly:    false,
			expectedErr: vmerrs.ErrOutOfGas.Error(),
		},
		"set allow role from admin": {
			caller:         adminAddr,
			precompileAddr: precompile.ContractNativeMinterAddress,
			input: func() []byte {
				input, err := precompile.PackModifyAllowList(noRoleAddr, precompile.AllowListEnabled)
				if err != nil {
					panic(err)
				}
				return input
			},
			suppliedGas: precompile.ModifyAllowListGasCost,
			readOnly:    false,
			expectedRes: []byte{},
			assertState: func(t *testing.T, state *state.StateDB) {
				res := precompile.GetContractNativeMinterStatus(state, adminAddr)
				assert.Equal(t, precompile.AllowListAdmin, res)

				res = precompile.GetContractNativeMinterStatus(state, noRoleAddr)
				assert.Equal(t, precompile.AllowListEnabled, res)
			},
		},
		"set allow role from non-admin fails": {
			caller:         allowAddr,
			precompileAddr: precompile.ContractNativeMinterAddress,
			input: func() []byte {
				input, err := precompile.PackModifyAllowList(noRoleAddr, precompile.AllowListEnabled)
				if err != nil {
					panic(err)
				}
				return input
			},
			suppliedGas: precompile.ModifyAllowListGasCost,
			readOnly:    false,
			expectedErr: precompile.ErrCannotModifyAllowList.Error(),
		},
	} {
		t.Run(name, func(t *testing.T) {
			db := rawdb.NewMemoryDatabase()
			state, err := state.New(common.Hash{}, state.NewDatabase(db), nil)
			if err != nil {
				t.Fatal(err)
			}
			// Set up the state so that each address has the expected permissions at the start.
			precompile.SetContractNativeMinterStatus(state, adminAddr, precompile.AllowListAdmin)
			precompile.SetContractNativeMinterStatus(state, allowAddr, precompile.AllowListEnabled)
			precompile.SetContractNativeMinterStatus(state, noRoleAddr, precompile.AllowListNoRole)

			ret, remainingGas, err := precompile.ContractNativeMinterPrecompile.Run(&mockAccessibleState{state: state}, test.caller, test.precompileAddr, test.input(), test.suppliedGas, nil, test.readOnly)
			if len(test.expectedErr) != 0 {
				if err == nil {
					assert.Failf(t, "run expectedly passed without error", "expected error %q", test.expectedErr)
				} else {
					assert.True(t, strings.Contains(err.Error(), test.expectedErr), "expected error (%s) to contain substring (%s)", err, test.expectedErr)
				}
				return
			}

			if err != nil {
				t.Fatal(err)
			}

			assert.Equal(t, uint64(0), remainingGas)
			assert.Equal(t, test.expectedRes, ret)

			test.assertState(t, state)
		})
	}
}

func createNewRandomState(t *testing.T) *state.StateDB {
	db := rawdb.NewMemoryDatabase()
	state, err := state.New(common.Hash{}, state.NewDatabase(db), nil)
	if err != nil {
		t.Fatal(err)
	}
	precompile.SetPhaseSeconds(state, big.NewInt(3))
	precompile.SetCommitStake(state, big.NewInt(1000))
	return state
}

func TestRandomParty(t *testing.T) {
	anyAddr := common.HexToAddress("0xF60C45c607D0f41687c94C314d300f483661E13a")
	s := createNewRandomState(t)
	s.AddBalance(anyAddr, big.NewInt(100000))

	for _, test := range []struct {
		name  string
		btime *big.Int

		input       func() []byte
		suppliedGas uint64
		value       *big.Int

		expectedRes []byte
		expectedErr string
	}{
		{
			name:  "next",
			btime: common.Big0,
			input: func() []byte {
				return precompile.NextSignature
			},
			suppliedGas: precompile.NextCost,
			expectedRes: precompile.HBigBytes(common.Big0),
		},
		{
			name:  "start party",
			btime: big.NewInt(10),
			input: func() []byte {
				return precompile.StartSignature
			},
			suppliedGas: precompile.StartGasCost,
			expectedRes: []byte{},
		},
		{
			name:  "start party again",
			btime: big.NewInt(10),
			input: func() []byte {
				return precompile.StartSignature
			},
			suppliedGas: precompile.StartGasCost,
			expectedErr: precompile.ErrRandomPartyUnderway.Error(),
		},
		{
			name:  "commit",
			btime: big.NewInt(10),
			value: big.NewInt(1000),
			input: func() []byte {
				preimage := common.BytesToHash([]byte{0x1}).Bytes()
				return precompile.PackCommit(crypto.Keccak256Hash(preimage))
			},
			suppliedGas: precompile.CommitGasCost,
			expectedRes: precompile.HBigBytes(common.Big0),
		},
		{
			name:  "commit insufficient",
			btime: big.NewInt(10),
			value: big.NewInt(999),
			input: func() []byte {
				preimage := common.BytesToHash([]byte{0x2}).Bytes()
				return precompile.PackCommit(crypto.Keccak256Hash(preimage))
			},
			suppliedGas: precompile.CommitGasCost,
			expectedErr: precompile.ErrInsufficientFunds.Error(),
		},
		{
			name:  "commit 2",
			btime: big.NewInt(10),
			value: big.NewInt(1001),
			input: func() []byte {
				preimage := common.BytesToHash([]byte{0x2}).Bytes()
				return precompile.PackCommit(crypto.Keccak256Hash(preimage))
			},
			suppliedGas: precompile.CommitGasCost,
			expectedRes: precompile.HBigBytes(common.Big1),
		},
		{
			name:  "check reward before",
			btime: big.NewInt(10),
			input: func() []byte {
				return precompile.RewardSignature
			},
			suppliedGas: precompile.RewardGasCost,
			expectedRes: precompile.HBigBytes(common.Big0),
		},
		{
			name:  "reveal",
			btime: big.NewInt(10),
			input: func() []byte {
				return precompile.PackReveal(common.Big0, crypto.Keccak256Hash([]byte{0x1}))
			},
			suppliedGas: precompile.RevealGasCost,
			expectedErr: precompile.ErrTooEarly.Error(),
		},
		{
			name:  "sponsor",
			btime: big.NewInt(11),
			value: big.NewInt(10),
			input: func() []byte {
				return precompile.SponsorSignature
			},
			suppliedGas: precompile.SponsorGasCost,
			expectedRes: []byte{},
		},
		{
			name:  "check reward after",
			btime: big.NewInt(10),
			input: func() []byte {
				return precompile.RewardSignature
			},
			suppliedGas: precompile.RewardGasCost,
			expectedRes: precompile.HBigBytes(big.NewInt(10)),
		},
		{
			name:  "commit later",
			btime: big.NewInt(14),
			input: func() []byte {
				return precompile.PackCommit(crypto.Keccak256Hash([]byte{0x1}))
			},
			suppliedGas: precompile.CommitGasCost,
			expectedErr: precompile.ErrTooLate.Error(),
		},
		{
			name:  "reveal later",
			btime: big.NewInt(14),
			input: func() []byte {
				return precompile.PackReveal(common.Big0, common.BytesToHash([]byte{0x1}))
			},
			suppliedGas: precompile.RevealGasCost,
			expectedRes: []byte{},
		},
		{
			name:  "duplicate reveal",
			btime: big.NewInt(14),
			input: func() []byte {
				return precompile.PackReveal(common.Big0, common.BytesToHash([]byte{0x1}))
			},
			suppliedGas: precompile.RevealGasCost,
			expectedErr: precompile.ErrDuplicateReveal.Error(),
		},
		{
			name:  "compute early",
			btime: big.NewInt(10),
			input: func() []byte {
				return precompile.ComputeSignature
			},
			suppliedGas: precompile.ComputeGasCost,
			expectedErr: precompile.ErrTooEarly.Error(),
		},
		{
			name:  "compute still early",
			btime: big.NewInt(14),
			input: func() []byte {
				return precompile.ComputeSignature
			},
			suppliedGas: precompile.ComputeGasCost,
			expectedErr: precompile.ErrTooEarly.Error(),
		},
		{
			name:  "compute",
			btime: big.NewInt(20),
			input: func() []byte {
				return precompile.ComputeSignature
			},
			suppliedGas: precompile.ComputeGasCost + precompile.ComputeItemCost + precompile.ComputeRewardCost,
			expectedRes: []byte{},
		},
		{
			name:  "result",
			btime: big.NewInt(20),
			input: func() []byte {
				return precompile.PackResult(common.Big0)
			},
			suppliedGas: precompile.ResultCost,
			expectedRes: crypto.Keccak256(common.BytesToHash([]byte{0x1}).Bytes()),
		},
		{
			name:  "next",
			btime: big.NewInt(20),
			input: func() []byte {
				return precompile.NextSignature
			},
			suppliedGas: precompile.NextCost,
			expectedRes: common.BigToHash(big.NewInt(1)).Bytes(),
		},
		{
			name:  "compute again",
			btime: big.NewInt(20),
			input: func() []byte {
				return precompile.ComputeSignature
			},
			suppliedGas: precompile.ComputeGasCost + precompile.ComputeItemCost,
			expectedErr: precompile.ErrNoRandomPartyStarted.Error(),
		},
		{
			name:  "check reward before next party",
			btime: big.NewInt(20),
			input: func() []byte {
				return precompile.RewardSignature
			},
			suppliedGas: precompile.RewardGasCost,
			expectedErr: precompile.ErrNoRandomPartyStarted.Error(),
		},
		{
			name:  "start second party",
			btime: big.NewInt(20),
			input: func() []byte {
				return precompile.StartSignature
			},
			suppliedGas: precompile.StartGasCost + precompile.DeleteGasCost*3,
			expectedRes: []byte{},
		},
		{
			name:  "commit second party",
			btime: big.NewInt(20),
			value: big.NewInt(1001),
			input: func() []byte {
				preimage := common.BytesToHash([]byte{0x1}).Bytes()
				return precompile.PackCommit(crypto.Keccak256Hash(preimage))
			},
			suppliedGas: precompile.CommitGasCost,
			expectedRes: common.BigToHash(common.Big0).Bytes(),
		},
		{
			name:  "check reward later",
			btime: big.NewInt(21),
			input: func() []byte {
				return precompile.RewardSignature
			},
			suppliedGas: precompile.RewardGasCost,
			expectedRes: precompile.HBigBytes(common.Big0),
		},
		{
			name:  "reveal old key",
			btime: big.NewInt(24),
			input: func() []byte {
				return precompile.PackReveal(big.NewInt(1), common.BytesToHash([]byte{0x2}))
			},
			suppliedGas: precompile.RevealGasCost,
			expectedErr: "no hash with index 1",
		},
		{
			name:  "start third party",
			btime: big.NewInt(30),
			input: func() []byte {
				return precompile.StartSignature
			},
			suppliedGas: precompile.StartGasCost + precompile.DeleteGasCost,
			expectedErr: precompile.ErrRandomPartyUnderway.Error(),
		},
		{
			name:  "compute old party",
			btime: big.NewInt(40),
			input: func() []byte {
				return precompile.ComputeSignature
			},
			suppliedGas: precompile.ComputeGasCost,
			expectedRes: []byte{},
		},
		{
			name:  "next after reset",
			btime: big.NewInt(100),
			input: func() []byte {
				return precompile.NextSignature
			},
			suppliedGas: precompile.NextCost,
			expectedRes: precompile.HBigBytes(big.NewInt(2)),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ret, remainingGas, err := precompile.RandomPartyPrecompile.Run(&mockAccessibleState{blockTime: test.btime, state: s}, anyAddr, precompile.RandomPartyAddress, test.input(), test.suppliedGas, test.value, false)
			if len(test.expectedErr) != 0 {
				if err == nil {
					assert.Failf(t, "run unexpectedly passed without error", "expected error %q", test.expectedErr)
				} else {
					assert.True(t, strings.Contains(err.Error(), test.expectedErr), "expected error (%s) to contain substring (%s)", err, test.expectedErr)
				}
				return
			}

			if err != nil {
				t.Fatal(err)
			}

			assert.Equal(t, uint64(0), remainingGas)
			assert.Equal(t, test.expectedRes, ret)
		})
	}
}
