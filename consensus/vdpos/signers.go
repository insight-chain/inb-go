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
	"bytes"
	"github.com/insight-chain/inb-go/log"
	"math/big"
	"sort"

	"github.com/insight-chain/inb-go/common"
)

type TallyItem struct {
	addr  common.Address
	stake *big.Int
}
type TallySlice []TallyItem

func (s TallySlice) Len() int      { return len(s) }
func (s TallySlice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s TallySlice) Less(i, j int) bool {
	isLess := s[i].stake.Cmp(s[j].stake)
	if isLess > 0 {
		return true

	} else if isLess < 0 {
		return false
	}
	return bytes.Compare(s[i].addr.Bytes(), s[j].addr.Bytes()) > 0
}

type SignerItem struct {
	addr common.Address
	hash common.Hash
}
type SignerSlice []SignerItem

func (s SignerSlice) Len() int      { return len(s) }
func (s SignerSlice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s SignerSlice) Less(i, j int) bool {
	return bytes.Compare(s[i].hash.Bytes(), s[j].hash.Bytes()) > 0
}

// verify the SignerQueue base on block hash
func (s *Snapshot) verifySignersPool(signersPool []common.Address) error {

	if len(signersPool) > int(s.config.MaxSignerCount) {
		return errInvalidSignersPool
	}
	sq, err := s.createSignersPool()
	if err != nil {
		return err
	}
	if len(sq) == 0 || len(sq) != len(signersPool) {
		return errInvalidSignersPool
	}
	for i, signer := range signersPool {
		if signer != sq[i] {
			return errInvalidSignersPool
		}
	}

	return nil
}

func (s *Snapshot) buildTallySlice() TallySlice {
	var tallySlice TallySlice
	for address, stake := range s.Tally {
		if !candidateNeedPD || s.isCandidate(address) {
			if _, ok := s.Punished[address]; ok {
				var creditWeight uint64
				if s.Punished[address] > defaultFullCredit-minCalSignersPoolCredit {
					creditWeight = minCalSignersPoolCredit
				} else {
					creditWeight = defaultFullCredit - s.Punished[address]
				}
				tallySlice = append(tallySlice, TallyItem{address, new(big.Int).Mul(stake, big.NewInt(int64(creditWeight)))})
			} else {
				tallySlice = append(tallySlice, TallyItem{address, new(big.Int).Mul(stake, big.NewInt(defaultFullCredit))})
			}
		}
	}
	return tallySlice
}

func (s *Snapshot) createSignersPool() ([]common.Address, error) {

	if (s.Number+1)%(s.config.MaxSignerCount*s.config.SignerBlocks) != 0 || s.Hash != s.HistoryHash[len(s.HistoryHash)-1] {
		return nil, errCreateSignersPoolNotAllowed
	}

	var signerSlice SignerSlice
	var topStakeAddress []common.Address

	if (s.Number+1)%(s.config.MaxSignerCount*s.config.SignerBlocks*s.LCRS) == 0 {
		// before recalculate the signers, clear the candidate is not in snap.Candidates
		// only recalculate signers from to tally per 10 loop,
		// other loop end just reset the order of signers by block hash (nearly random)
		log.Debug("~~~~~~~~~~~~~~~~~~~now we recreate signers~~~~~~~~~~~")
		tallySlice := s.buildTallySlice()
		sort.Sort(TallySlice(tallySlice))
		log.Debug("~~~~~~~~~~~~~~~~~~~tallySlice begin~~~~~~~~~~~~~~~~~~")
		for _, item := range tallySlice {
			log.Debug(item.addr.Hex())
		}
		log.Debug("~~~~~~~~~~~~~~~~~~~tallySlice end~~~~~~~~~~~~~~~~~~~~")

		poolLength := int(s.config.MaxSignerCount)
		if poolLength > len(tallySlice) {
			poolLength = len(tallySlice)
		}
		for i, tallyItem := range tallySlice[:poolLength] {
			signerSlice = append(signerSlice, SignerItem{tallyItem.addr, s.HistoryHash[len(s.HistoryHash)-1-i]})
		}
		log.Debug("~~~~~~~~~~~~~~~~~~~signerSlice begin~~~~~~~~~~~~~~~~~~")
		for _, itemx := range signerSlice {
			log.Debug(itemx.addr.Hex())
		}
		log.Debug("~~~~~~~~~~~~~~~~~~~signerSlice end~~~~~~~~~~~~~~~~~~~~")
	} else {
		for i, signer := range s.Signers {
			signerSlice = append(signerSlice, SignerItem{*signer, s.HistoryHash[len(s.HistoryHash)-1-i]})
		}
	}

	sort.Sort(SignerSlice(signerSlice))
	// Set the top candidates in random order base on block hash
	if len(signerSlice) == 0 {
		return nil, errSignersPoolEmpty
	}
	for i := 0; i < int(s.config.MaxSignerCount); i++ {
		topStakeAddress = append(topStakeAddress, signerSlice[i%len(signerSlice)].addr)
	}

	return topStakeAddress, nil

}
