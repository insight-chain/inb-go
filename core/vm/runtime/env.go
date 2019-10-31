// Copyright 2015 The go-ethereum Authors
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

package runtime

import (
	"github.com/insight-chain/inb-go/common"
	"github.com/insight-chain/inb-go/core"
	"github.com/insight-chain/inb-go/core/vm"
)

func NewEnv(cfg *Config) *vm.EVM {
	context := vm.Context{
		CanTransfer: core.CanTransfer,
		Transfer:    core.Transfer,
		//Resource by zc
		MortgageTransfer: core.MortgageTransfer,
		//Resource by zc
		GetHash: func(uint64) common.Hash { return common.Hash{} },

		Origin:      cfg.Origin,
		Coinbase:    cfg.Coinbase,
		BlockNumber: cfg.BlockNumber,
		Time:        cfg.Time,
		Difficulty:  cfg.Difficulty,
		GasLimit:    cfg.GasLimit,
		GasPrice:    cfg.GasPrice,

		CanReset:              core.CanReset,
		CanMortgage:           core.CanMortgage,
		CanRedeem:             core.CanRedeem,
		CanReceive:            core.CanReceive,
		RedeemTransfer:        core.RedeemTransfer,
		ResetTransfer:         core.ResetTransfer,
		ReceiveTransfer:       core.ReceiveTransfer,
		CanReceiveLockedAward: core.CanReceiveLockedAwardFunc, //2019.7.24 inb by ghy
		ReceiveLockedAward:    core.ReceiveLockedAwardFunc,    //2019.7.22 inb by ghy
		CanReceiveVoteAward:   core.CanReceiveVoteAwardFunc,   //2019.7.24 inb by ghy
		ReceiveVoteAward:      core.ReceiveVoteAwardFunc,      //2019.7.24 inb by ghy
		Vote:                  core.Vote,                      //2019.7.24 inb by ghy
		InsteadMortgageTransfer:  core.InsteadMortgageTransfer, //20190919 added replacement mortgage
		CanInsteadMortgage:       core.CanInsteadMortgage,
		CanUpdateNodeInformation: core.CanUpdateNodeInformation, //2019.10.17 inb by ghy
		CanVote:                  core.CanVote,                  //2019.10.18 inb by ghy
		CanIssueLightToken:       core.CanIssueLightToken,       //2019.10.18 inb by ghy
	}

	return vm.NewEVM(context, cfg.State, cfg.ChainConfig, cfg.EVMConfig)
}
