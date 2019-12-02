// Copyright 2019 The inb-go Authors
// This file is part of the inb-go library.
//
// The inb-go library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software MiningReward, either version 3 of the License, or
// (at your option) any later version.
//
// The inb-go library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the inb-go library. If not, see <http://www.gnu.org/licenses/>.

// Package vdpos implements the delegated-proof-of-stake consensus engine.
package vdpos

import (
	"github.com/insight-chain/inb-go/common"
	"github.com/insight-chain/inb-go/core/state"
	"github.com/insight-chain/inb-go/core/types"
	"github.com/insight-chain/inb-go/params"
	"math/big"
)

type SnapContext struct {
	config       *params.VdposConfig
	statedb      *state.StateDB
	Number       uint64
	ParentHash   common.Hash
	TimeStamp    int64
	VdposContext *types.VdposContext
	SignersPool  []common.Address
}

// get last block number meet the confirm condition
func (s *SnapContext) getLastConfirmedBlockNumber() *big.Int {
	i := s.Number
	for ; i > s.Number-s.config.SignerBlocks*(s.config.MaxSignerCount*2/3+1); i-- {
	}
	return big.NewInt(int64(i))
}
