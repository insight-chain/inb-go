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
	"github.com/insight-chain/inb-go/log"
	"github.com/insight-chain/inb-go/rlp"
	"github.com/insight-chain/inb-go/trie"
	"math/big"
)

type GetState interface {
	GetMortgageInbOfINB(addr common.Address) *big.Int
	GetRegular(addr common.Address) *big.Int
}

type VdposContext struct {
	voteTrie              *trie.Trie
	tallyTrie             *trie.Trie
	lightTokenTrie        *trie.Trie
	lightTokenAccountTrie *trie.Trie

	db     ethdb.Database
	triedb *trie.Database
}

type Tally struct {
	Address  common.Address
	Stake    *big.Int
	Mortgage *big.Int
	Regular  *big.Int
	NodeInfo common.EnodesInfo //2019.9.4 inb by ghy
}

type Votes struct {
	Voter     common.Address
	Candidate []common.Address
	Stake     *big.Int
}

type LightTokenChangeType uint8

const (
	Add LightTokenChangeType = iota
	Sub
)

type LightToken struct {
	Address             common.Address
	Name                string
	Symbol              string
	Decimals            uint8
	TotalSupply         *big.Int
	IssueAccountAddress common.Address
	IssueTxHash         common.Hash
	Owner               common.Address
	PayForInb           *big.Int
}

type ApproveInfo struct {
	Receiver common.Address
	Balance  *big.Int
	State    uint8
}

type LightTokenState struct {
	LightTokenAddress common.Address
	LT                *LightToken
	Balance           *big.Int
	ApproveInfos      []*ApproveInfo
	State             uint8
}

type LightTokenAccount struct {
	Address     common.Address
	LightTokens []*LightTokenState
}

type LightTokenChange struct {
	AccountAddress    common.Address
	LightTokenAddress common.Address
	LT                *LightToken
	ChangeBalance     *big.Int
	ChangeType        LightTokenChangeType
}

type LightTokenChanges struct {
	LTCs []*LightTokenChange
}

var (
	votePrefix              = []byte("vote-")
	tallyPrefix             = []byte("tally-")
	lightTokenPrefix        = []byte("lt-")
	lightTokenAccountPrefix = []byte("lta-")
)

func NewVoteTrie(root common.Hash, triedb *trie.Database) (*trie.Trie, error) {
	return trie.NewTrieWithPrefix(root, votePrefix, triedb)
}

func NewTallyTrie(root common.Hash, triedb *trie.Database) (*trie.Trie, error) {
	return trie.NewTrieWithPrefix(root, tallyPrefix, triedb)
}

func NewLightTokenTrie(root common.Hash, triedb *trie.Database) (*trie.Trie, error) {
	return trie.NewTrieWithPrefix(root, lightTokenPrefix, triedb)
}

func NewLightTokenAccountTrie(root common.Hash, triedb *trie.Database) (*trie.Trie, error) {
	return trie.NewTrieWithPrefix(root, lightTokenAccountPrefix, triedb)
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
	lightTokenTrie, err := NewLightTokenTrie(common.Hash{}, triedb)
	if err != nil {
		return nil, err
	}
	lightTokenAccountTrie, err := NewLightTokenAccountTrie(common.Hash{}, triedb)
	if err != nil {
		return nil, err
	}
	return &VdposContext{
		voteTrie:              voteTrie,
		tallyTrie:             tallyTrie,
		lightTokenTrie:        lightTokenTrie,
		lightTokenAccountTrie: lightTokenAccountTrie,
		db:     db,
		triedb: triedb,
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
	lightTokenTrie, err := NewLightTokenTrie(ctxProto.LightTokenHash, triedb)
	if err != nil {
		return nil, err
	}
	lightTokenAccountTrie, err := NewLightTokenAccountTrie(ctxProto.LightTokenAccountHash, triedb)
	if err != nil {
		return nil, err
	}
	return &VdposContext{
		voteTrie:              voteTrie,
		tallyTrie:             tallyTrie,
		lightTokenTrie:        lightTokenTrie,
		lightTokenAccountTrie: lightTokenAccountTrie,
		db:     db,
		triedb: triedb,
	}, nil
}

func (vc *VdposContext) Copy() *VdposContext {
	voteTrie := *vc.voteTrie
	tallyTrie := *vc.tallyTrie
	lightTokenTrie := *vc.lightTokenTrie
	lightTokenAccountTrie := *vc.lightTokenAccountTrie
	return &VdposContext{
		voteTrie:              &voteTrie,
		tallyTrie:             &tallyTrie,
		lightTokenTrie:        &lightTokenTrie,
		lightTokenAccountTrie: &lightTokenAccountTrie,
	}
}

func (vc *VdposContext) Root() (h common.Hash) {
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, vc.voteTrie.Hash())
	rlp.Encode(hw, vc.tallyTrie.Hash())
	rlp.Encode(hw, vc.lightTokenTrie.Hash())
	rlp.Encode(hw, vc.lightTokenAccountTrie.Hash())
	hw.Sum(h[:0])
	return h
}

func (vc *VdposContext) Snapshot() *VdposContext {
	return vc.Copy()
}

func (vc *VdposContext) RevertToSnapShot(snapshot *VdposContext) {
	vc.voteTrie = snapshot.voteTrie
	vc.tallyTrie = snapshot.tallyTrie
	vc.lightTokenTrie = snapshot.lightTokenTrie
	vc.lightTokenAccountTrie = snapshot.lightTokenAccountTrie
}

func (vc *VdposContext) FromProto(dcp *VdposContextProto) error {
	var err error
	vc.voteTrie, err = NewVoteTrie(dcp.VoteHash, vc.triedb)
	if err != nil {
		return err
	}
	vc.tallyTrie, err = NewTallyTrie(dcp.TallyHash, vc.triedb)
	if err != nil {
		return err
	}
	vc.lightTokenTrie, err = NewLightTokenTrie(dcp.LightTokenHash, vc.triedb)
	if err != nil {
		return err
	}
	vc.lightTokenAccountTrie, err = NewLightTokenAccountTrie(dcp.LightTokenAccountHash, vc.triedb)
	return err
}

type VdposContextProto struct {
	VoteHash              common.Hash `json:"voteRoot"                  gencodec:"required"`
	TallyHash             common.Hash `json:"tallyRoot"                 gencodec:"required"`
	LightTokenHash        common.Hash `json:"lightTokenRoot"            gencodec:"required"`
	LightTokenAccountHash common.Hash `json:"lightTokenAccountRoot"     gencodec:"required"`
}

func (vc *VdposContext) ToProto() *VdposContextProto {
	return &VdposContextProto{
		VoteHash:              vc.voteTrie.Hash(),
		TallyHash:             vc.tallyTrie.Hash(),
		LightTokenHash:        vc.lightTokenTrie.Hash(),
		LightTokenAccountHash: vc.lightTokenAccountTrie.Hash(),
	}
}

func (p *VdposContextProto) Root() (h common.Hash) {
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, p.VoteHash)
	rlp.Encode(hw, p.TallyHash)
	rlp.Encode(hw, p.LightTokenHash)
	rlp.Encode(hw, p.LightTokenAccountHash)
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

	lightTokenRoot, err := vc.lightTokenTrie.Commit(nil)
	if err != nil {
		return nil, err
	}
	err = vc.triedb.Commit(lightTokenRoot, false)
	if err != nil {
		return nil, err
	}

	lightTokenAccountRoot, err := vc.lightTokenAccountTrie.Commit(nil)
	if err != nil {
		return nil, err
	}
	err = vc.triedb.Commit(lightTokenAccountRoot, false)
	if err != nil {
		return nil, err
	}

	return &VdposContextProto{
		VoteHash:              voteRoot,
		TallyHash:             tallyRoot,
		LightTokenHash:        lightTokenRoot,
		LightTokenAccountHash: lightTokenAccountRoot,
	}, nil
}

func (vc *VdposContext) GetDB() ethdb.Database               { return vc.db }
func (vc *VdposContext) SetDB(db ethdb.Database)             { vc.db = db }
func (vc *VdposContext) VoteTrie() *trie.Trie                { return vc.voteTrie }
func (vc *VdposContext) TallyTrie() *trie.Trie               { return vc.tallyTrie }
func (vc *VdposContext) SetVote(vote *trie.Trie)             { vc.voteTrie = vote }
func (vc *VdposContext) SetTally(tally *trie.Trie)           { vc.tallyTrie = tally }
func (vc *VdposContext) LightTokenTrie() *trie.Trie          { return vc.lightTokenTrie }
func (vc *VdposContext) LightTokenAccountTrie() *trie.Trie   { return vc.lightTokenAccountTrie }
func (vc *VdposContext) SetLightToken(lightToken *trie.Trie) { vc.lightTokenTrie = lightToken }
func (vc *VdposContext) SetLightTokenAccount(lightTokenAccount *trie.Trie) {
	vc.lightTokenAccountTrie = lightTokenAccount
}

func (vc *VdposContext) UpdateTallysByNewState(addr common.Address, state GetState) error {
	oldTallyRLP := vc.tallyTrie.Get(addr[:])
	if oldTallyRLP != nil {
		tally := new(Tally)
		if err := rlp.DecodeBytes(oldTallyRLP, tally); err != nil {
			return fmt.Errorf("failed to decode tally: %s", err)
		}
		tally.Mortgage = state.GetMortgageInbOfINB(addr)
		tally.Regular = state.GetRegular(addr)
		newTallyRLP, err := rlp.EncodeToBytes(tally)
		if err != nil {
			return fmt.Errorf("failed to encode tally to rlp bytes: %s", err)
		}
		vc.tallyTrie.Update(addr[:], newTallyRLP)
	}
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

func (vc *VdposContext) UpdateTallysByVotes(vote *Votes, state GetState) error {
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
			mortgage := new(big.Int)
			regular := new(big.Int)
			if state == nil {
				fmt.Println("state==nil,我来也")
				mortgage.SetUint64(0)
				regular.SetUint64(0)
			} else {
				fmt.Println("state!=nil,我来也")
				fmt.Println(state.GetMortgageInbOfINB(candidate).String())
				fmt.Println(state.GetRegular(candidate).String())
				mortgage.Set(state.GetMortgageInbOfINB(candidate))
				regular.Set(state.GetRegular(candidate))
			}

			tally = &Tally{
				Address:  candidate,
				Stake:    vote.Stake,
				Mortgage: mortgage,
				Regular:  regular,
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
		if oldVote.Stake.Cmp(stake) == 0 {
			log.Debug("Just do nothing because the stake remains unchanged")
			return nil
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

func (vc *VdposContext) GetLightToken(address common.Address) (*LightToken, error) {
	lightTokenRLP := vc.lightTokenTrie.Get(address[:])
	if lightTokenRLP != nil {
		lightToken := new(LightToken)
		if err := rlp.DecodeBytes(lightTokenRLP, lightToken); err != nil {
			return nil, fmt.Errorf("failed to decode lightToken: %s", err)
		}
		return lightToken, nil
	} else {
		return nil, nil
	}
}

func (vc *VdposContext) GetLightTokenAccountByAddress(address common.Address) (*LightTokenAccount, error) {
	lightTokenAccountRLP := vc.lightTokenAccountTrie.Get(address[:])
	if lightTokenAccountRLP == nil {
		return nil, fmt.Errorf("this account has none of lightTokens")
	} else {
		lightTokenAccount := new(LightTokenAccount)
		if err := rlp.DecodeBytes(lightTokenAccountRLP, lightTokenAccount); err != nil {
			return nil, fmt.Errorf("failed to decode lightTokenAccount: %s", err)
		}
		return lightTokenAccount, nil
	}
}

func (vc *VdposContext) GetLightTokenBalanceByAddress(accountAddress common.Address, lightTokenAddress common.Address) (*big.Int, error) {
	lightTokenAccountRLP := vc.lightTokenAccountTrie.Get(accountAddress[:])
	if lightTokenAccountRLP == nil {
		return big.NewInt(0), fmt.Errorf("this account has none of lightTokens")
	} else {
		lightTokenAccount := new(LightTokenAccount)
		if err := rlp.DecodeBytes(lightTokenAccountRLP, lightTokenAccount); err != nil {
			return big.NewInt(0), fmt.Errorf("failed to decode lightTokenAccount: %s", err)
		}
		place := vc.IsLightTokenExistInAccount(lightTokenAddress, lightTokenAccount.LightTokens)
		if place == -1 {
			return big.NewInt(0), fmt.Errorf("this account do not has this lightToken")
		} else {
			return lightTokenAccount.LightTokens[place].Balance, nil
		}
	}
}

func (vc *VdposContext) UpdateLightToken(lightToken *LightToken) error {
	address := lightToken.Address[:]
	lightTokenRLP, err := rlp.EncodeToBytes(lightToken)
	if err != nil {
		return fmt.Errorf("failed to encode lightToken to rlp bytes: %s", err)
	}
	vc.lightTokenTrie.Update(address, lightTokenRLP)
	return nil
}

func (vc *VdposContext) UpdateLightTokenAccount(lightTokenChanges *LightTokenChanges) error {

	for _, lightTokenChange := range lightTokenChanges.LTCs {

		oldLightTokenAccountRLP := vc.lightTokenAccountTrie.Get(lightTokenChange.AccountAddress[:])
		if oldLightTokenAccountRLP != nil {
			lightTokenAccount := new(LightTokenAccount)
			if err := rlp.DecodeBytes(oldLightTokenAccountRLP, lightTokenAccount); err != nil {
				return fmt.Errorf("failed to decode lightTokenAccount: %s", err)
			}
			place := vc.IsLightTokenExistInAccount(lightTokenChange.LightTokenAddress, lightTokenAccount.LightTokens)
			if lightTokenChange.ChangeType == Add {
				if place != -1 {
					balance := lightTokenAccount.LightTokens[place].Balance
					lightTokenAccount.LightTokens[place].Balance = balance.Add(balance, lightTokenChange.ChangeBalance)
				} else {
					lightTokenAccount.LightTokens = append(lightTokenAccount.LightTokens, &LightTokenState{
						LightTokenAddress: lightTokenChange.LightTokenAddress,
						LT:                lightTokenChange.LT,
						Balance:           lightTokenChange.ChangeBalance,
						State:             0,
					})
				}
			} else if lightTokenChange.ChangeType == Sub {
				if place != -1 {
					balance := lightTokenAccount.LightTokens[place].Balance
					if balance.Cmp(lightTokenChange.ChangeBalance) == -1 {
						log.Debug("Not enough balance")
						continue
					} else {
						lightTokenAccount.LightTokens[place].Balance = balance.Sub(balance, lightTokenChange.ChangeBalance)
					}
				} else {
					log.Debug("Not found token,so do't need to sub")
					continue
				}
			}

			newLightTokenAccountRLP, err := rlp.EncodeToBytes(lightTokenAccount)
			if err != nil {
				return fmt.Errorf("failed to encode lightTokenAccount to rlp bytes: %s", err)
			}
			vc.lightTokenAccountTrie.Update(lightTokenChange.AccountAddress[:], newLightTokenAccountRLP)
		} else {
			if lightTokenChange.ChangeType == Add {
				lightTokenAccount := new(LightTokenAccount)
				lightTokenAccount.Address = lightTokenChange.AccountAddress
				lightTokenAccount.LightTokens = append(lightTokenAccount.LightTokens, &LightTokenState{
					LightTokenAddress: lightTokenChange.LightTokenAddress,
					LT:                lightTokenChange.LT,
					Balance:           lightTokenChange.ChangeBalance,
					State:             0,
				})
				newLightTokenAccountRLP, err := rlp.EncodeToBytes(lightTokenAccount)
				if err != nil {
					return fmt.Errorf("failed to encode lightTokenAccount to rlp bytes: %s", err)
				}
				vc.lightTokenAccountTrie.Update(lightTokenChange.AccountAddress[:], newLightTokenAccountRLP)
			} else if lightTokenChange.ChangeType == Sub {
				log.Debug("Not found account,so do't need to sub")
				continue
			}
		}

	}
	return nil
}

func (vc *VdposContext) IsLightTokenExistInAccount(lightTokenAddress common.Address, lightTokenStates []*LightTokenState) int {
	for i, lightTokenState := range lightTokenStates {
		if lightTokenAddress == lightTokenState.LightTokenAddress {
			return i
		}
	}
	return -1
}
