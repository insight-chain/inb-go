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

package types

import (
	"fmt"
	"github.com/insight-chain/inb-go/common"
	"github.com/insight-chain/inb-go/crypto/sha3"
	"github.com/insight-chain/inb-go/ethdb"
	"github.com/insight-chain/inb-go/rlp"
	"github.com/insight-chain/inb-go/trie"
	"math/big"
)

type VdposContext struct {
	voteTrie  *trie.Trie
	tallyTrie *trie.Trie

	db     ethdb.Database
	triedb *trie.Database
}

type Tally struct {
	Address  common.Address
	Stake    *big.Int
	NodeInfo common.EnodesInfo //2019.9.4 inb by ghy
}

type Votes struct {
	Voter     common.Address
	Candidate []common.Address
	Stake     *big.Int
}

var (
	votePrefix  = []byte("vote-")
	tallyPrefix = []byte("tally-")
)

func NewVoteTrie(root common.Hash, triedb *trie.Database) (*trie.Trie, error) {
	return trie.NewTrieWithPrefix(root, votePrefix, triedb)
}

func NewTallyTrie(root common.Hash, triedb *trie.Database) (*trie.Trie, error) {
	return trie.NewTrieWithPrefix(root, tallyPrefix, triedb)
}

func NewVdposContext(db ethdb.Database) (*VdposContext, error) {
	triedb := trie.NewDatabase(db)
	voteTrie, err := NewVoteTrie(common.Hash{}, triedb)
	if err != nil {
		return nil, err
	}
	tallyTrie, err := NewTallyTrie(common.Hash{}, triedb)
	if err != nil {
		return nil, err
	}
	return &VdposContext{
		voteTrie:  voteTrie,
		tallyTrie: tallyTrie,
		db:        db,
		triedb:    triedb,
	}, nil
}

func NewVdposContextFromProto(db ethdb.Database, ctxProto *VdposContextProto) (*VdposContext, error) {
	triedb := trie.NewDatabase(db)
	voteTrie, err := NewVoteTrie(ctxProto.VoteHash, triedb)
	if err != nil {
		return nil, err
	}
	tallyTrie, err := NewTallyTrie(ctxProto.TallyHash, triedb)
	if err != nil {
		return nil, err
	}
	return &VdposContext{
		voteTrie:  voteTrie,
		tallyTrie: tallyTrie,
		db:        db,
		triedb:    triedb,
	}, nil
}

func (vc *VdposContext) Copy() *VdposContext {
	voteTrie := *vc.voteTrie
	tallyTrie := *vc.tallyTrie
	return &VdposContext{
		voteTrie:  &voteTrie,
		tallyTrie: &tallyTrie,
	}
}

func (vc *VdposContext) Root() (h common.Hash) {
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, vc.voteTrie.Hash())
	rlp.Encode(hw, vc.tallyTrie.Hash())
	hw.Sum(h[:0])
	return h
}

func (vc *VdposContext) Snapshot() *VdposContext {
	return vc.Copy()
}

func (vc *VdposContext) RevertToSnapShot(snapshot *VdposContext) {
	vc.voteTrie = snapshot.voteTrie
	vc.tallyTrie = snapshot.tallyTrie
}

func (vc *VdposContext) FromProto(dcp *VdposContextProto) error {
	var err error
	vc.voteTrie, err = NewVoteTrie(dcp.VoteHash, vc.triedb)
	if err != nil {
		return err
	}
	vc.tallyTrie, err = NewTallyTrie(dcp.TallyHash, vc.triedb)
	return err
}

type VdposContextProto struct {
	VoteHash  common.Hash `json:"voteRoot"         gencodec:"required"`
	TallyHash common.Hash `json:"tallyRoot"        gencodec:"required"`
}

func (vc *VdposContext) ToProto() *VdposContextProto {
	return &VdposContextProto{
		VoteHash:  vc.voteTrie.Hash(),
		TallyHash: vc.tallyTrie.Hash(),
	}
}

func (p *VdposContextProto) Root() (h common.Hash) {
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, p.VoteHash)
	rlp.Encode(hw, p.TallyHash)
	hw.Sum(h[:0])
	return h
}

func (vc *VdposContext) Commit() (*VdposContextProto, error) {
	voteRoot, err := vc.voteTrie.Commit(nil)
	if err != nil {
		return nil, err
	}
	err = vc.triedb.Commit(voteRoot, false)
	if err != nil {
		return nil, err
	}

	tallyRoot, err := vc.tallyTrie.Commit(nil)
	if err != nil {
		return nil, err
	}
	err = vc.triedb.Commit(tallyRoot, false)
	if err != nil {
		return nil, err
	}

	return &VdposContextProto{
		VoteHash:  voteRoot,
		TallyHash: tallyRoot,
	}, nil
}

func (vc *VdposContext) VoteTrie() *trie.Trie      { return vc.voteTrie }
func (vc *VdposContext) TallyTrie() *trie.Trie     { return vc.tallyTrie }
func (vc *VdposContext) GetDB() ethdb.Database     { return vc.db }
func (vc *VdposContext) SetDB(db ethdb.Database)   { vc.db = db }
func (vc *VdposContext) SetVote(vote *trie.Trie)   { vc.voteTrie = vote }
func (vc *VdposContext) SetTally(tally *trie.Trie) { vc.tallyTrie = tally }

func (vc *VdposContext) UpdateTallys(tally *Tally) error {
	addr := tally.Address
	tallyRLP, err := rlp.EncodeToBytes(tally)
	if err != nil {
		return fmt.Errorf("failed to encode tally to rlp bytes: %s", err)
	}
	vc.tallyTrie.Update(addr[:], tallyRLP)
	return nil
}

func (vc *VdposContext) UpdateVotes(vote *Votes) error {
	addr := vote.Voter
	voteRLP, err := rlp.EncodeToBytes(vote)
	if err != nil {
		return fmt.Errorf("failed to encode tally to rlp bytes: %s", err)
	}
	vc.voteTrie.Update(addr[:], voteRLP)
	return nil
}

func (vc *VdposContext) UpdateTallysByVotes(vote *Votes) error {
	voteAddr := vote.Voter
	voteRLP := vc.voteTrie.Get(voteAddr[:])
	if voteRLP != nil {
		oldVote := new(Votes)
		if err := rlp.DecodeBytes(voteRLP, oldVote); err != nil {
			return fmt.Errorf("failed to decode votes: %s", err)
		}
		for _, candidate := range oldVote.Candidate {
			oldTallyRLP := vc.tallyTrie.Get(candidate[:])
			if oldTallyRLP != nil {
				tally := new(Tally)
				if err := rlp.DecodeBytes(oldTallyRLP, tally); err != nil {
					return fmt.Errorf("failed to decode tally: %s", err)
				}
				if tally.Stake.Cmp(vote.Stake) == -1 {
					tally.Stake = big.NewInt(0)
				} else {
					tally.Stake = tally.Stake.Sub(tally.Stake, vote.Stake)
				}
				newTallyRLP, err := rlp.EncodeToBytes(tally)
				if err != nil {
					return fmt.Errorf("failed to encode tally to rlp bytes: %s", err)
				}
				vc.tallyTrie.Update(candidate[:], newTallyRLP)
			}
		}
	}
	for _, candidate := range vote.Candidate {
		oldTallyRLP := vc.tallyTrie.Get(candidate[:])
		tally := new(Tally)
		if oldTallyRLP != nil {
			if err := rlp.DecodeBytes(oldTallyRLP, tally); err != nil {
				return fmt.Errorf("failed to decode tally: %s", err)
			}
			tally.Stake = tally.Stake.Add(tally.Stake, vote.Stake)
		} else {
			tally = &Tally{
				Address: candidate,
				Stake:   vote.Stake,
			}
		}
		newTallyRLP, err := rlp.EncodeToBytes(tally)
		if err != nil {
			return fmt.Errorf("failed to encode tally to rlp bytes: %s", err)
		}
		vc.tallyTrie.Update(candidate[:], newTallyRLP)
	}
	return nil
}

//2019.9.4 inb by ghy begin
func (vc *VdposContext) UpdateTallysByNodeInfo(nodeInfo common.EnodesInfo) error {
	Addr := nodeInfo.Address
	tallyRLP := vc.tallyTrie.Get(Addr[:])
	tally := new(Tally)
	if tallyRLP != nil {
		if err := rlp.DecodeBytes(tallyRLP, tally); err != nil {
			return fmt.Errorf("failed to decode tally: %s", err)
		}
		tally.NodeInfo = nodeInfo

	} else {
		tally.Address = Addr
		tally.NodeInfo = nodeInfo

	}
	newTallyRLP, err := rlp.EncodeToBytes(tally)

	if err != nil {
		return fmt.Errorf("failed to encode tally to rlp bytes: %s", err)
	}

	vc.tallyTrie.Update(Addr[:], newTallyRLP)

	return nil
}

//2019.9.4 inb by ghy end

func (vc *VdposContext) UpdateTallysAndVotesByMPV(voter common.Address, stake *big.Int) error {
	voteRLP := vc.voteTrie.Get(voter[:])
	if voteRLP != nil {
		oldVote := new(Votes)
		if err := rlp.DecodeBytes(voteRLP, oldVote); err != nil {
			return fmt.Errorf("failed to decode votes: %s", err)
		}
		for _, candidate := range oldVote.Candidate {
			oldTallyRLP := vc.tallyTrie.Get(candidate[:])
			if oldTallyRLP != nil {
				tally := new(Tally)
				if err := rlp.DecodeBytes(oldTallyRLP, tally); err != nil {
					return fmt.Errorf("failed to decode tally: %s", err)
				}
				if tally.Stake.Cmp(oldVote.Stake) == -1 {
					tally.Stake = big.NewInt(0)
				} else {
					tally.Stake = tally.Stake.Sub(tally.Stake, oldVote.Stake)
				}
				tally.Stake = tally.Stake.Add(tally.Stake, stake)
				newTallyRLP, err := rlp.EncodeToBytes(tally)
				if err != nil {
					return fmt.Errorf("failed to encode tally to rlp bytes: %s", err)
				}
				vc.tallyTrie.Update(candidate[:], newTallyRLP)
			}
		}
		newVote := &Votes{
			Voter:     voter,
			Candidate: oldVote.Candidate,
			Stake:     stake,
		}
		err := vc.UpdateVotes(newVote)
		if err != nil {
			return fmt.Errorf("failed to update votes %s", err)
		}
	}
	return nil
}
