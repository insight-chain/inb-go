// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"errors"
	"github.com/insight-chain/inb-go/common"
	"github.com/insight-chain/inb-go/core/types"
	"github.com/insight-chain/inb-go/core/vm"
	"github.com/insight-chain/inb-go/crypto"
	"github.com/insight-chain/inb-go/log"
	"github.com/insight-chain/inb-go/params"
	"math"
	"math/big"
)

var (
	errInsufficientBalanceForGas = errors.New("insufficient balance to pay for gas")

	multiple = big.NewInt(63)
)

/*
The State Transitioning Model

A state transition is a change made when a transaction is applied to the current world state
The state transitioning model does all the necessary work to work out a valid new state root.

1) Nonce handling
2) Pre pay gas
3) Create a new state object if the recipient is \0*32
4) Value transfer
== If contract creation ==
  4a) Attempt to run transaction data
  4b) If valid, use result as code for the new state object
== end ==
5) Run Script section
6) Derive new state root
*/
type StateTransition struct {
	gp  *GasPool
	msg Message
	net uint64
	//gas        uint64
	//gasPrice   *big.Int
	initialGas uint64
	value      *big.Int
	data       []byte
	state      vm.StateDB
	evm        *vm.EVM
}

// Message represents a message sent to a contract.
type Message interface {
	From() common.Address
	//FromFrontier() (common.Address, error)
	To() *common.Address

	//GasPrice() *big.Int
	Gas() uint64
	Value() *big.Int

	Nonce() uint64
	CheckNonce() bool
	Data() []byte
	//achilles repayment add apis
	Types() types.TxType
	ResourcePayer() common.Address
	IsRePayment() bool
	Receive() *big.Int
	Hash() common.Hash
}

// IntrinsicGas computes the 'intrinsic gas' for a message with the given data.
func IntrinsicGas(data []byte, contractCreation, homestead bool) (uint64, error) {
	// Set the starting gas for the raw transaction
	var gas uint64
	if contractCreation && homestead {
		gas = params.TxGasContractCreation
	} else {
		gas = params.TxGas
	}
	// Bump the required gas by the amount of transactional data
	if len(data) > 0 {
		// Zero and non-zero bytes are priced differently
		var nz uint64
		for _, byt := range data {
			if byt != 0 {
				nz++
			}
		}
		// Make sure we don't exceed uint64 for all data combinations
		if (math.MaxUint64-gas)/params.TxDataNonZeroGas < nz {
			return 0, vm.ErrOutOfGas
		}
		gas += nz * params.TxDataNonZeroGas

		z := uint64(len(data)) - nz
		if (math.MaxUint64-gas)/params.TxDataZeroGas < z {
			return 0, vm.ErrOutOfGas
		}
		gas += z * params.TxDataZeroGas
	}
	return gas, nil
}

func IntrinsicRes(data []byte, contractCreation bool) uint64 {
	if contractCreation {
		return params.TxConfig.NetRatio * (uint64(len(data)) + params.ContractRes)
	}
	return params.TxConfig.NetRatio * (uint64(len(data)) + params.TxRes)
}

// NewStateTransition initialises and returns a new state transition object.
func NewStateTransition(evm *vm.EVM, msg Message, gp *GasPool) *StateTransition {
	return &StateTransition{
		gp:  gp,
		evm: evm,
		msg: msg,
		//gasPrice: msg.GasPrice(),
		value: msg.Value(),
		data:  msg.Data(),
		state: evm.StateDB,
	}
}

// ApplyMessage computes the new state by applying the given message
// against the old state within the environment.
//
// ApplyMessage returns the bytes returned by any EVM execution (if it took place),
// the gas used (which includes gas refunds) and an error if it failed. An error always
// indicates a core error meaning that the message would always fail for that particular
// state and would never be accepted within a block.

func ApplyMessage(evm *vm.EVM, msg Message, gp *GasPool) ([]byte, uint64, bool, error, *big.Int) {
	return NewStateTransition(evm, msg, gp).TransitionDb()
}

// to returns the recipient of the message.
func (st *StateTransition) to() common.Address {
	if st.msg == nil || st.msg.To() == nil /* contract creation */ {
		return common.Address{}
	}
	return *st.msg.To()
}

func (st *StateTransition) useGas(amount uint64) error {
	//if st.gas < amount {
	//	return vm.ErrOutOfGas
	//}
	//st.gas -= amount
	//
	//return nil
	return st.useNet(amount)
}

func (st *StateTransition) useNet(amount uint64) error {
	if st.net < amount {
		return vm.ErrOutOfGas
	}
	st.net -= amount

	return nil
}

//achilles use net
//func (st *StateTransition) useNet(amount uint64) error {
//	if st.gas < amount {
//		return vm.ErrOutOfGas
//	}
//	st.gas -= amount
//
//	return nil
//}

func (st *StateTransition) buyGas() error {
	//mgval := new(big.Int).Mul(new(big.Int).SetUint64(st.msg.Gas()), st.gasPrice)
	mgval := new(big.Int).SetUint64(st.msg.Gas())
	//achilles repayment add apis
	payment := st.msg.From()
	//if st.msg.IsRePayment() {
	//	payment = st.msg.ResourcePayer()
	//}
	if st.state.GetBalance(payment).Cmp(mgval) < 0 {
		return errInsufficientBalanceForGas
	}
	if err := st.gp.SubGas(st.msg.Gas()); err != nil {
		return err
	}
	st.net += st.msg.Gas()

	st.initialGas = st.msg.Gas()
	st.state.SubBalance(payment, mgval)
	return nil
}

func (st *StateTransition) preCheck() error {
	// Make sure this transaction's nonce is correct.
	if st.msg.CheckNonce() {
		nonce := st.state.GetNonce(st.msg.From())
		if nonce < st.msg.Nonce() {
			return ErrNonceTooHigh
		} else if nonce > st.msg.Nonce() {
			return ErrNonceTooLow
		}
	}
	return st.buyGas()
}

func (st *StateTransition) preCheckForRes() error {
	// Make sure this transaction's nonce is correct.
	if st.msg.CheckNonce() {
		nonce := st.state.GetNonce(st.msg.From())
		if nonce < st.msg.Nonce() {
			return ErrNonceTooHigh
		} else if nonce > st.msg.Nonce() {
			return ErrNonceTooLow
		}
	}
	return nil
}

// TransitionDb will transition the state by applying the current message and
// returning the result including the used gas. It returns an error if failed.
// An error indicates a consensus issue.

func (st *StateTransition) TransitionDb() (ret []byte, usedRes uint64, failed bool, err error, receive *big.Int) {
	//achilles replace gas with net
	//if err = st.preCheck(); err != nil {
	//	return
	//}

	if st.msg.From()[0] != crypto.PrefixToAddress[0] {
		return nil, 0, false, ErrInvalidAddress, nil
	}
	if err = st.preCheckForRes(); err != nil {
		return nil, 0, false, err, nil
	}

	//achilles repayment add apis
	netPayment := st.msg.From()
	if st.msg.IsRePayment() {
		netPayment = st.msg.ResourcePayer()
	}

	msg := st.msg
	sender := vm.AccountRef(msg.From())
	//homestead := st.evm.ChainConfig().IsHomestead(st.evm.BlockNumber)
	contractCreation := msg.To() == nil && msg.Types() == types.Contract

	// Pay intrinsic gas
	////achilles replace gas with net
	res := IntrinsicRes(st.data, contractCreation)
	//gas, err := IntrinsicGas(st.data, contractCreation, homestead)
	//if err != nil {
	//	return nil, 0, false, err
	//}
	//if err = st.useGas(gas); err != nil {
	//	return nil, 0, false, err
	//}

	//mgval := new(big.Int).SetUint64(st.msg.Gas())

	if !(st.msg.Types() == types.Mortgage || st.msg.Types() == types.Regular || st.msg.Types() == types.Reset || st.msg.Types() == types.Receive || st.msg.Types() == types.SpecialTx || st.msg.Types() == types.Redeem) {

		if st.state.GetNet(netPayment).Cmp(big.NewInt(int64(res))) < 0 {
			return nil, 0, false, errInsufficientBalanceForGas, nil
		}
		st.state.UseRes(netPayment, big.NewInt(int64(res)))
	}

	var (
		evm = st.evm
		// vm errors do not effect consensus and are therefor
		// not assigned to err, except for insufficient balance
		// error.
		vmerr error
	)

	getNet := st.state.GetNet(netPayment)

	if getNet.Cmp(big.NewInt(3174)) > 0 {
		getNet = big.NewInt(3174)
	}

	netpool := big.NewInt(0).Mul(getNet, multiple)

	if contractCreation {
		ret, _, st.net, vmerr = evm.Create(sender, st.data, netpool.Uint64(), st.value)
	} else {
		// Increment the nonce for the next transaction
		st.state.SetNonce(msg.From(), st.state.GetNonce(sender.Address())+1)
		ret, st.net, vmerr, receive = evm.NewCall(sender, st.to(), st.data, netpool.Uint64(), st.value, st.msg.Types(), st.msg.Hash())
	}
	if vmerr != nil {
		log.Debug("VM returned with error", "err", vmerr)
		// The only possible consensus-error would be if there wasn't
		// sufficient balance to make the transfer happen. The first
		// balance transfer may never fail.
		if vmerr == vm.ErrInsufficientBalance {
			return nil, 0, false, vmerr, nil
		}
	}
	//achilles
	//st.refundGas()
	//st.state.AddBalance(st.evm.Coinbase, new(big.Int).Mul(new(big.Int).SetUint64(st.gasUsed()), st.gasPrice))

	//return ret, st.gasUsed(), vmerr != nil, err

	evmUsedRes := big.NewInt(0).Sub(netpool, big.NewInt(0).SetUint64(st.net))

	usedres := big.NewInt(0).Div(evmUsedRes, multiple)

	st.state.UseRes(netPayment, usedres)
	usedRes = big.NewInt(0).Add(usedres, big.NewInt(0).SetUint64(res)).Uint64()
	if st.msg.Types() == types.Mortgage || st.msg.Types() == types.Regular || st.msg.Types() == types.Reset || st.msg.Types() == types.Receive || st.msg.Types() == types.SpecialTx || st.msg.Types() == types.Redeem {
		return nil, 0, vmerr != nil, err, receive
	}
	return ret, usedRes, vmerr != nil, err, receive
}

func (st *StateTransition) refundGas() {
	// Apply refund counter, capped to half of the used gas.
	//refund := st.gasUsed() / 2
	//if refund > st.state.GetRefund() {
	//	refund = st.state.GetRefund()
	//}
	//st.gas += refund
	//
	//// Return ETH for remaining gas, exchanged at the original rate.
	//remaining := new(big.Int).Mul(new(big.Int).SetUint64(st.gas), st.gasPrice)
	////achilles repayment add apis
	////if st.msg.IsRePayment() {
	////	st.state.AddBalance(st.msg.ResourcePayer(), remaining)
	////} else {
	//st.state.AddBalance(st.msg.From(), remaining)
	////}
	//
	//// Also return remaining gas to the block gas counter so it is
	//// available for the next transaction.
	//st.gp.AddGas(st.gas)
}

// gasUsed returns the amount of gas used up by the state transition.
func (st *StateTransition) gasUsed() uint64 {
	//return st.initialGas - st.gas
	return st.initialGas - st.net
}
