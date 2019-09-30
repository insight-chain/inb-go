// Copyright 2019 The inb-go Authors
// This file is part of the inb-go library.
//
// The inb-go library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
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
	"fmt"
	"github.com/insight-chain/inb-go/common"
	"github.com/insight-chain/inb-go/consensus"
	"github.com/insight-chain/inb-go/core/types"
	"github.com/insight-chain/inb-go/log"
	"github.com/insight-chain/inb-go/rlp"
	"github.com/insight-chain/inb-go/trie"
)

// API is a user facing RPC API to allow controlling the signer and voting
// mechanisms of the delegated-proof-of-stake scheme.
type API struct {
	chain consensus.ChainReader
	vdpos *Vdpos
}

func (api *API) GetSigners(number uint64) ([]common.Address, error) {
	header := api.chain.GetHeaderByNumber(number)
	if header == nil {
		return nil, errUnknownBlock
	}
	return api.vdpos.getSigners(header)
}

func (api *API) GetSignersAtHash(hash common.Hash) ([]common.Address, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, errUnknownBlock
	}
	return api.vdpos.getSigners(header)
}

func (api *API) GetCandidateNodesInfo() []*types.Tally {
	tallySlice := []*types.Tally{}
	var err error
	header := api.chain.CurrentHeader()

	b := header.Extra[32 : len(header.Extra)-65]
	headerExtra := HeaderExtra{}
	val := &headerExtra
	err = rlp.DecodeBytes(b, val)

	//vdposContext, err := types.NewVdposContext(api.vdpos.db)
	vdposContext, err := types.NewVdposContextFromProto(api.vdpos.db, header.VdposContext)

	if err != nil {
		return nil
	}
	//err = vdposContext.UpdateTallysByNodeInfo(enodeInfoTrie)
	tallyTrie := vdposContext.TallyTrie()

	tallyIterator := trie.NewIterator(tallyTrie.PrefixIterator(nil))

	existTally := tallyIterator.Next()
	if !existTally {
		return nil
	}
	for existTally {
		tallyRLP := tallyIterator.Value
		tally := new(types.Tally)
		if err := rlp.DecodeBytes(tallyRLP, tally); err != nil {
			log.Error("Failed to decode tally")
			return nil
		}

		tallySlice = append(tallySlice, tally)
		existTally = tallyIterator.Next()
	}
	return tallySlice

}

func (api *API) GetSuperNodesInfo() []*types.Tally {
	var err error
	header := api.chain.CurrentHeader()

	b := header.Extra[32 : len(header.Extra)-65]
	headerExtra := HeaderExtra{}
	val := &headerExtra
	err = rlp.DecodeBytes(b, val)

	//vdposContext, err := types.NewVdposContext(api.vdpos.db)
	vdposContext, err := types.NewVdposContextFromProto(api.vdpos.db, header.VdposContext)

	if err != nil {
		return nil
	}
	//err = vdposContext.UpdateTallysByNodeInfo(enodeInfoTrie)
	TallyTrie := vdposContext.TallyTrie()

	nodesInfo := []*types.Tally{}
	for _, addr := range val.SignersPool {
		TallyRLP := TallyTrie.Get(addr[:])
		tally := new(types.Tally)
		if TallyRLP != nil {
			if err := rlp.DecodeBytes(TallyRLP, tally); err != nil {
				fmt.Println(err)
				continue
			}
		} else {
		}
		nodesInfo = append(nodesInfo, tally)
	}
	return nodesInfo
}

func (api *API) GetLightTokenByAddress(address common.Address) *types.LightToken {
	header := api.chain.CurrentHeader()
	if header == nil {
		return nil
	}

	vdposContext, err := types.NewVdposContextFromProto(api.vdpos.db, header.VdposContext)
	if err != nil {
		return nil
	}

	lightToken, err := vdposContext.GetLightToken(address)
	if err != nil {
		return nil
	} else {
		return lightToken
	}
}

func (api *API) GetLightTokenAccountByAccountAddress(address common.Address) *types.LightTokenAccount {
	header := api.chain.CurrentHeader()
	if header == nil {
		return nil
	}

	vdposContext, err := types.NewVdposContextFromProto(api.vdpos.db, header.VdposContext)
	if err != nil {
		return nil
	}

	lightTokenAccount, _ := vdposContext.GetLightTokenAccountByAddress(address)
	return lightTokenAccount
}

func (api *API) GetLightTokenBalanceByAddress(accountAddress common.Address, lightTokenAddress common.Address) string {
	header := api.chain.CurrentHeader()
	if header == nil {
		return ""
	}

	vdposContext, err := types.NewVdposContextFromProto(api.vdpos.db, header.VdposContext)
	if err != nil {
		return ""
	}

	balance, _ := vdposContext.GetLightTokenBalanceByAddress(accountAddress, lightTokenAddress)
	return balance.String()
}
