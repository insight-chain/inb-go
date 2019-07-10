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
	"github.com/insight-chain/inb-go/common"
	"github.com/insight-chain/inb-go/consensus"
	"github.com/insight-chain/inb-go/rlp"
)

// API is a user facing RPC API to allow controlling the signer and voting
// mechanisms of the delegated-proof-of-stake scheme.
type API struct {
	chain consensus.ChainReader
	vdpos *Vdpos
}

// GetSnapshot retrieves the state snapshot at a given block.
func (api *API) GetSnapshot(number uint64) (*Snapshot, error) {
	header := api.chain.GetHeaderByNumber(number)
	if header == nil {
		return nil, errUnknownBlock
	}
	return api.vdpos.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil, nil, defaultLoopCntRecalculateSigners)
}

// GetSnapshotAtHash retrieves the state snapshot at a given block.
func (api *API) GetSnapshotAtHash(hash common.Hash) (*Snapshot, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, errUnknownBlock
	}
	return api.vdpos.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil, nil, defaultLoopCntRecalculateSigners)
}

func (api *API) GetSigners(number uint64) ([]common.Address, error) {
	header := api.chain.GetHeaderByNumber(number)
	if header == nil {
		return nil, errUnknownBlock
	}
	snap, err := api.vdpos.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil, nil, defaultLoopCntRecalculateSigners)
	if err != nil {
		return nil, err
	}
	return snap.signers(), nil
}

// GetSignersAtHash retrieves the list of authorized signers at the specified block.
func (api *API) GetSignersAtHash(hash common.Hash) ([]common.Address, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, errUnknownBlock
	}
	snap, err := api.vdpos.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil, nil, defaultLoopCntRecalculateSigners)
	if err != nil {
		return nil, err
	}
	return snap.signers(), nil
}


//inb by ghy begin
func (api *API) GetCandidateNodesInfo() []common.EnodeInfo {
	var err error
	header:= api.chain.CurrentHeader()

	b := header.Extra[32 : len(header.Extra)-65]
	headerExtra := HeaderExtra{}
	val := &headerExtra
	err = rlp.DecodeBytes(b, val)

	snapshot, err := api.GetSnapshot(header.Number.Uint64())

	newval:= HeaderExtra{}
			for add,vote:=range snapshot.Tally{

				for _,v:=range val.Enodes{
					if add==v.Address&&vote.Uint64()>0{

						v.Vote=vote.Uint64()
						newval.Enodes= append(newval.Enodes,v)
					}
				}

			}

	if err == nil {
		return newval.Enodes
	} else {
		return nil
	}

}


func (api *API) GetSuperNodesInfo() []common.EnodeInfo {
	var err error
	header:= api.chain.CurrentHeader()

	b := header.Extra[32 : len(header.Extra)-65]
	headerExtra := HeaderExtra{}
	val := &headerExtra
	err = rlp.DecodeBytes(b, val)

	snapshot, err := api.GetSnapshot(header.Number.Uint64())

	newval:= HeaderExtra{}
	for _,addr:=range snapshot.Signers{

		//for _,v:=range val.Enodes{
		//	if *addr==v.Address{
		//		newval.Enodes= append(newval.Enodes,v)
		//	}
		//}
		for add,vote:=range snapshot.Tally{
			if add==*addr{
				for _,v:=range val.Enodes{
					if add==v.Address&&vote.Uint64()>0{
						v.Vote=vote.Uint64()
						newval.Enodes= append(newval.Enodes,v)
		}
	}
}
		}

	}

	if err == nil {
		return newval.Enodes
	} else {
		return nil
	}
}
//inb by ghy end