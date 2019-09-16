// Copyright 2016 The go-ethereum Authors
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
	"github.com/insight-chain/inb-go/consensus"
	"github.com/insight-chain/inb-go/core/types"
	"github.com/insight-chain/inb-go/core/vm"
	"github.com/insight-chain/inb-go/params"
	"math/big"
)

// ChainContext supports retrieving headers and consensus parameters from the
// current blockchain to be used during transaction processing.
type ChainContext interface {
	// Engine retrieves the chain's consensus engine.
	Engine() consensus.Engine

	// GetHeader returns the hash corresponding to their hash.
	GetHeader(common.Hash, uint64) *types.Header
}

// NewEVMContext creates a new context for use in the EVM.
func NewEVMContext(msg Message, header *types.Header, chain ChainContext, author *common.Address) vm.Context {
	// If we don't have an explicit author (i.e. not mining), extract from the header
	var beneficiary common.Address
	if author == nil {
		beneficiary, _ = chain.Engine().Author(header) // Ignore error, we're past header validation
	} else {
		beneficiary = *author
	}
	return vm.Context{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		//Resource by zc
		MortgageTransfer: MortgageTransfer,
		//Resource by zc
		GetHash:          GetHashFn(header, chain),
		Origin:           msg.From(),
		Coinbase:         beneficiary,
		BlockNumber:      new(big.Int).Set(header.Number),
		Time:             new(big.Int).Set(header.Time),
		SpecialConsensus: header.GetSpecialConsensus(), //2019.7.31 inb by ghy
		Difficulty:       new(big.Int).Set(header.Difficulty),
		GasLimit:         header.ResLimit,
		//GasPrice:              new(big.Int).Set(msg.GasPrice()),
		CanMortgage:           CanMortgage,
		CanRedeem:             CanRedeem,
		CanReset:              CanReset,
		CanReceive:            CanReceive,
		RedeemTransfer:        RedeemTransfer,
		ResetTransfer:         ResetTransfer,
		ReceiveTransfer:       ReceiveTransfer,
		CanReceiveLockedAward: CanReceiveLockedAwardFunc, //2019.7.22 inb by ghy
		ReceiveLockedAward:    ReceiveLockedAwardFunc,    //2019.7.22 inb by ghy
		CanReceiveVoteAward:   CanReceiveVoteAwardFunc,   //2019.7.24 inb by ghy
		ReceiveVoteAward:      ReceiveVoteAwardFunc,      //2019.7.24 inb by ghy
		Vote:                  Vote,                      //2019.7.24 inb by ghy
	}
}

// GetHashFn returns a GetHashFunc which retrieves header hashes by number
func GetHashFn(ref *types.Header, chain ChainContext) func(n uint64) common.Hash {
	var cache map[uint64]common.Hash

	return func(n uint64) common.Hash {
		// If there's no hash cache yet, make one
		if cache == nil {
			cache = map[uint64]common.Hash{
				ref.Number.Uint64() - 1: ref.ParentHash,
			}
		}
		// Try to fulfill the request from the cache
		if hash, ok := cache[n]; ok {
			return hash
		}
		// Not cached, iterate the blocks and cache the hashes
		for header := chain.GetHeader(ref.ParentHash, ref.Number.Uint64()-1); header != nil; header = chain.GetHeader(header.ParentHash, header.Number.Uint64()-1) {
			cache[header.Number.Uint64()-1] = header.ParentHash
			if n == header.Number.Uint64()-1 {
				return header.ParentHash
			}
		}
		return common.Hash{}
	}
}

// CanTransfer checks whether there are enough funds in the address' account to make a transfer.
// This does not take the necessary gas in to account to make the transfer valid.
func CanTransfer(db vm.StateDB, addr common.Address, amount *big.Int) bool {
	return db.GetBalance(addr).Cmp(amount) >= 0
}

// Transfer subtracts amount from sender and adds amount to recipient using the given Db
func Transfer(db vm.StateDB, sender, recipient common.Address, amount *big.Int) {
	db.SubBalance(sender, amount)
	db.AddBalance(recipient, amount)
}

//Resource by zc
func MortgageTransfer(db vm.StateDB, sender, recipient common.Address, amount *big.Int, duration uint, sTime big.Int) *big.Int {
	// db.AddBalance(recipient, amount)
	db.SubBalance(sender, amount)
	return db.MortgageNet(sender, amount, duration, sTime)
}

//achilles0719 regular mortgagtion
func ResetTransfer(db vm.StateDB, sender common.Address, update *big.Int) *big.Int {
	return db.ResetNet(sender, update)
}

//Resource by zc

//2019.7.22 inb by ghy begin
func CanReceiveLockedAwardFunc(db vm.StateDB, from common.Address, nonce int, time *big.Int, specialConsensus types.SpecialConsensus) (error, *big.Int, bool, common.Address) {
	return db.CanReceiveLockedAward(from, nonce, time, specialConsensus)

}

func ReceiveLockedAwardFunc(db vm.StateDB, from common.Address, nonce int, values *big.Int, isAll bool, time *big.Int, toAddress common.Address) {
	db.ReceiveLockedAward(from, nonce, values, isAll, time, toAddress)
}

func CanReceiveVoteAwardFunc(db vm.StateDB, from common.Address, time *big.Int, specialConsensus types.SpecialConsensus) (error, *big.Int, common.Address) {
	return db.CanReceiveVoteAward(from, time, specialConsensus)

}

func ReceiveVoteAwardFunc(db vm.StateDB, from common.Address, values *big.Int, time *big.Int, toAddress common.Address) {
	db.ReceiveVoteAward(from, values, time, toAddress)
}

func Vote(db vm.StateDB, from common.Address, time *big.Int) {
	db.Vote(from, time)
}

//2019.7.22 inb by ghy end
//achilles
func RedeemTransfer(db vm.StateDB, sender, recipient common.Address, amount *big.Int, sTime *big.Int) {
	db.Redeem(sender, amount, sTime)
}

func ReceiveTransfer(db vm.StateDB, sender common.Address, sTime *big.Int) *big.Int {
	return db.Receive(sender, sTime)
}

func CanReset(db vm.StateDB, addr common.Address, now *big.Int) error {
	expire := big.NewInt(0).Add(db.GetDate(addr), params.TxConfig.ResetDuration)
	//now := big.NewInt(time.Now().Unix())
	if expire.Cmp(now) > 0 {
		return errors.New(" before reset time ")
	}
	return nil
}

func CanMortgage(db vm.StateDB, addr common.Address, amount *big.Int, duration uint) error {
	if duration > 0 {
		if count := db.StoreLength(addr); count >= params.TxConfig.RegularLimit {
			return errors.New(" exceeds mortgagtion count limit ")
		}
		if !params.Contains(duration) {
			return errors.New(" wrong duration of mortgagtion ")
		}
	}

	temp := big.NewInt(1).Div(amount, params.TxConfig.WeiOfUseNet)
	if temp.Cmp(big.NewInt(0)) <= 0 {
		return errors.New(" the value for mortgaging is too low ")
	}
	if db.GetBalance(addr).Cmp(amount) < 0 {
		return errors.New(" insufficient balance ")
	}
	return nil
}

func CanRedeem(db vm.StateDB, addr common.Address, amount *big.Int) error {
	mortgaging := db.GetMortgageInbOfNet(addr)
	regular := db.GetRegular(addr)
	value := db.GetRedeem(addr)

	usable := new(big.Int).Sub(mortgaging, regular)
	//usable = new(big.Int).Add(usable, value)
	usable.Sub(usable, value)
	if usable.Cmp(amount) < 0 {
		return errors.New(" insufficient available value of mortgage ")
	}
	return nil
}

func CanReceive(db vm.StateDB, addr common.Address, now *big.Int) error {
	timeLimit := new(big.Int).Add(db.GetRedeemTime(addr), params.TxConfig.RedeemDuration)
	//now := big.NewInt(time.Now().Unix())
	if timeLimit.Cmp(now) > 0 {
		return errors.New(" before receive time ")
	}
	if big.NewInt(0).Cmp(db.GetRedeem(addr)) == 0 {
		return errors.New(" insufficient available value of redeeming ")
	}
	return nil
}
