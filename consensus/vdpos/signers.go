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
	"encoding/binary"
	"fmt"
	"github.com/insight-chain/inb-go/common"
	"github.com/insight-chain/inb-go/core/types"
	"github.com/insight-chain/inb-go/crypto"
	"github.com/insight-chain/inb-go/log"
	"github.com/insight-chain/inb-go/params"
	"github.com/insight-chain/inb-go/rlp"
	"github.com/insight-chain/inb-go/trie"
	"math/big"
	"math/rand"
	"sort"
)

const (
	candidateMaxLen   = 50 //max lenth of candidate
	defaultFullCredit = 1  //default rate of stake
)

type TallyItem struct {
	addr       common.Address
	votesValue *big.Int
}
type TallySlice []TallyItem

func (s TallySlice) Len() int      { return len(s) }
func (s TallySlice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s TallySlice) Less(i, j int) bool {
	isLess := s[i].votesValue.Cmp(s[j].votesValue)
	if isLess > 0 {
		return true

	} else if isLess < 0 {
		return false
	}
	return bytes.Compare(s[i].addr.Bytes(), s[j].addr.Bytes()) > 0
}

// verify the SignersPool base on block hash
func (s *SnapContext) verifySignersPool(signersPool []common.Address) error {

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

// build TallySlice from TallyTrie
func (s *SnapContext) buildTallySlice() TallySlice {
	var tallySlice TallySlice
	tallTrie := s.VdposContext.TallyTrie()
	// use trie iterator
	tallyIterator := trie.NewIterator(tallTrie.PrefixIterator(nil))
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
		address := tally.Address
		tlsv := tally.TimeLimitedStakingValue
		if tlsv.Cmp(new(big.Int).Mul(big.NewInt(1000000), big.NewInt(params.Inber))) >= 0 {
			votesValue := tally.VotesValue
			tallySlice = append(tallySlice, TallyItem{address, new(big.Int).Mul(votesValue, big.NewInt(defaultFullCredit))})
		}
		existTally = tallyIterator.Next()
	}

	return tallySlice
}

func (s *SnapContext) createSignersPool() ([]common.Address, error) {
	// check up if we really need to create signersPool
	if (s.Number+1)%(s.config.MaxSignerCount*s.config.SignerBlocks) != 0 {
		return nil, errCreateSignersPoolNotAllowed
	}

	var topStakeAddress []common.Address
	var tallySliceOrder TallySlice

	// use parent block hash as seed so that every signers can use the same one
	seed := int64(binary.LittleEndian.Uint32(crypto.Keccak512(s.ParentHash.Bytes())))

	// only recalculate signers from to tally per defaultLoopCntRecalculateSigners loop,
	// other loop end just random the order of signers base on parent block hash
	if (s.Number+1)%(s.config.MaxSignerCount*s.config.SignerBlocks*s.config.LoopCntRecalculate) == 0 {
		tallySlice := s.buildTallySlice()
		if tallySlice != nil {
			sort.Sort(TallySlice(tallySlice))
			// remove minimum tickets tally beyond candidateMaxLen
			s.removeExtraCandidate(&tallySlice)
			for _, item := range tallySlice {
				log.Debug(item.addr.Hex())
			}
			poolLength := int(s.config.MaxSignerCount)
			if poolLength > len(tallySlice) {
				poolLength = len(tallySlice)
			}
			tallySliceOrder = tallySlice[:poolLength]
			s.random(tallySliceOrder, seed)
			for _, itemx := range tallySliceOrder {
				log.Debug(itemx.addr.Hex())
			}
		}
	} else {
		if s.SignersPool == nil {
			return nil, errCreateSignersPoolNotAllowed
		}
		tallTrie := s.VdposContext.TallyTrie()
		for _, signer := range s.SignersPool {
			tallyRLP := tallTrie.Get(signer[:])
			if tallyRLP != nil {
				tally := new(types.Tally)
				if err := rlp.DecodeBytes(tallyRLP, tally); err != nil {
					return nil, fmt.Errorf("failed to decode tally: %s", err)
				}
				tallyItem := TallyItem{
					addr:       tally.Address,
					votesValue: tally.VotesValue,
				}
				tallySliceOrder = append(tallySliceOrder, tallyItem)
			}
		}
		s.random(tallySliceOrder, seed)
		for _, itemx := range tallySliceOrder {
			log.Debug(itemx.addr.Hex())
		}
	}

	// Set the top signers in random order base on parent block hash
	if len(tallySliceOrder) == 0 {
		//return nil, errSignersPoolEmpty
		log.Error("signers pool is empty when createSignersPool")
		return s.SignersPool, nil
	}
	for i := 0; i < int(s.config.MaxSignerCount); i++ {
		topStakeAddress = append(topStakeAddress, tallySliceOrder[i%len(tallySliceOrder)].addr)
	}

	return topStakeAddress, nil

}

func (s *SnapContext) random(arr TallySlice, seed int64) {
	if len(arr) <= 0 {
		return
	}
	rand.Seed(seed)
	for i := len(arr) - 1; i >= 0; i-- {
		num := rand.Intn(len(arr))
		arr[i], arr[num] = arr[num], arr[i]
	}
	return
}

// inturn returns if a signer at a given block height is in-turn or not.
func (s *SnapContext) inturn(signer common.Address, header *types.Header, parent *types.Header) bool {
	if header.Number.Uint64() == 1 {
		parent = header
	}
	parentExtra := HeaderExtra{}
	err := decodeHeaderExtra(parent.Extra[extraVanity:len(parent.Extra)-extraSeal], &parentExtra)
	if err != nil {
		log.Error("Fail to decode header", "err", err)
		return false
	}
	headerTime := header.Time.Uint64()
	loopStartTime := parentExtra.LoopStartTime
	signers := parentExtra.SignersPool
	if signersCount := len(signers); signersCount > 0 {
		// handle config.Period != config.SignerPeriod
		if loopIndex := ((headerTime - loopStartTime) / (s.config.Period*(s.config.SignerBlocks-1) + s.config.SignerPeriod)) % uint64(signersCount); signers[loopIndex] == signer {
			return true
		}
	}
	return false
}

func (s *SnapContext) removeExtraCandidate(tally *TallySlice) {
	tallySlice := *tally
	if len(tallySlice) > candidateMaxLen {
		needRemoveTally := tallySlice[candidateMaxLen:]
		for _, tallySlice := range needRemoveTally {
			s.VdposContext.TallyTrie().Delete(tallySlice.addr[:])
		}
	}
}
