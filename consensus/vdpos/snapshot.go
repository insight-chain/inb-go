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
	"encoding/json"
	lru "github.com/hashicorp/golang-lru"
	"github.com/insight-chain/inb-go/common"
	"github.com/insight-chain/inb-go/core/types"
	"github.com/insight-chain/inb-go/ethdb"
	"github.com/insight-chain/inb-go/params"
	"math/big"
	"sort"
	"time"
)

const (
	defaultFullCredit       = 28800 // no punished
	missingPublishCredit    = 100   // punished for missing one block seal
	signRewardCredit        = 10    // seal one block
	autoRewardCredit        = 1     // credit auto recover for each block
	minCalSignersPoolCredit = 10000 // when calculate the signersPool

	maxUncheckBalanceVoteCount = 10000 // not check current balance when calculate expired
	// the credit of one signer is at least minCalSignersPoolCredit
	candidateStateNormal = 1
	candidateMaxLen      = 500 // if candidateNeedPD is false and candidate is more than candidateMaxLen, then minimum tickets candidates will be remove in each LCRS*loop

	// proposal refund
	proposalRefundDelayLoopCount   = 0
	proposalRefundExpiredLoopCount = proposalRefundDelayLoopCount + 2
)

// Snapshot is the state of the authorization voting at a given point in time.
type Snapshot struct {
	config   *params.VdposConfig // Consensus engine parameters to fine tune behavior
	sigcache *lru.ARCCache       // Cache of recent block signatures to speed up ecrecover
	LCRS     uint64              // Loop count to recreate signers from top tally

	Period          uint64                                 `json:"period"`          // Period of seal each block
	Number          uint64                                 `json:"number"`          // Block number where the snapshot was created
	ConfirmedNumber uint64                                 `json:"confirmedNumber"` // Block number confirmed when the snapshot was created
	Hash            common.Hash                            `json:"hash"`            // Block hash where the snapshot was created
	HistoryHash     []common.Hash                          `json:"historyHash"`     // Block hash list for two recent loop
	Signers         []*common.Address                      `json:"signers"`         // SignersPool in current header
	Votes           map[common.Address]*Vote               `json:"votes"`           // All validate votes from genesis block
	Tally           map[common.Address]*big.Int            `json:"tally"`           // Stake for each candidate address
	Voters          map[common.Address]*big.Int            `json:"voters"`          // Block number for each voter address
	Candidates      map[common.Address]uint64              `json:"candidates"`      // Candidates for Signers (0- adding procedure 1- normal 2- removing procedure)
	Punished        map[common.Address]uint64              `json:"punished"`        // The signer be punished count cause of missing seal
	Confirmations   map[uint64][]*common.Address           `json:"confirms"`        // The signer confirm given block number
	Proposals       map[common.Hash]*Proposal              `json:"proposals"`       // The Proposals going or success (failed proposal will be removed)
	HeaderTime      uint64                                 `json:"headerTime"`      // Time of the current header
	LoopStartTime   uint64                                 `json:"loopStartTime"`   // Start Time of the current loop
	ProposalRefund  map[uint64]map[common.Address]*big.Int `json:"proposalRefund"`  // Refund proposal deposit
}

// newSnapshot creates a new snapshot with the specified startup parameters. only ever use if for
// the genesis block.
func newSnapshot(config *params.VdposConfig, sigcache *lru.ARCCache, hash common.Hash, votes []*Vote, lcrs uint64) *Snapshot {

	snap := &Snapshot{
		config:          config,
		sigcache:        sigcache,
		LCRS:            lcrs,
		Period:          config.Period,
		Number:          0,
		ConfirmedNumber: 0,
		Hash:            hash,
		HistoryHash:     []common.Hash{},
		Signers:         []*common.Address{},
		Votes:           make(map[common.Address]*Vote),
		Tally:           make(map[common.Address]*big.Int),
		Voters:          make(map[common.Address]*big.Int),
		Punished:        make(map[common.Address]uint64),
		Candidates:      make(map[common.Address]uint64),
		Confirmations:   make(map[uint64][]*common.Address),
		Proposals:       make(map[common.Hash]*Proposal),
		HeaderTime:      uint64(time.Now().Unix()) - 1,
		LoopStartTime:   config.GenesisTimestamp,
		ProposalRefund:  make(map[uint64]map[common.Address]*big.Int),
	}
	snap.HistoryHash = append(snap.HistoryHash, hash)

	for _, vote := range votes {
		// init Votes from each vote
		snap.Votes[vote.Voter] = vote
		// init Tally
		_, ok := snap.Tally[vote.Candidate]
		if !ok {
			snap.Tally[vote.Candidate] = big.NewInt(0)
		}
		snap.Tally[vote.Candidate].Add(snap.Tally[vote.Candidate], vote.Stake)
		// init Voters
		snap.Voters[vote.Voter] = big.NewInt(0) // block number is 0 , vote in genesis block
		// init Candidates
		snap.Candidates[vote.Voter] = candidateStateNormal
	}

	if len(config.SelfVoteSigners) > 0 {
		var prefixSelfVoteSigners []common.Address
		for _, unPrefixSelfVoteSigners := range config.SelfVoteSigners {
			prefixSelfVoteSigners = append(prefixSelfVoteSigners, common.Address(unPrefixSelfVoteSigners))
		}
		for i := 0; i < int(config.MaxSignerCount); i++ {
			snap.Signers = append(snap.Signers, &prefixSelfVoteSigners[i%len(prefixSelfVoteSigners)])
		}
	}

	return snap
}

// loadSnapshot loads an existing snapshot from the database.
func loadSnapshot(config *params.VdposConfig, sigcache *lru.ARCCache, db ethdb.Database, hash common.Hash) (*Snapshot, error) {
	blob, err := db.Get(append([]byte("vdpos-"), hash[:]...))
	if err != nil {
		return nil, err
	}
	snap := new(Snapshot)
	if err := json.Unmarshal(blob, snap); err != nil {
		return nil, err
	}
	snap.config = config
	snap.sigcache = sigcache
	return snap, nil
}

// store inserts the snapshot into the database.
func (s *Snapshot) store(db ethdb.Database) error {
	blob, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return db.Put(append([]byte("vdpos-"), s.Hash[:]...), blob)
}

// copy creates a deep copy of the snapshot, though not the individual votes.
func (s *Snapshot) copy() *Snapshot {
	cpy := &Snapshot{
		config:          s.config,
		sigcache:        s.sigcache,
		LCRS:            s.LCRS,
		Period:          s.Period,
		Number:          s.Number,
		ConfirmedNumber: s.ConfirmedNumber,
		Hash:            s.Hash,
		HistoryHash:     make([]common.Hash, len(s.HistoryHash)),

		Signers:       make([]*common.Address, len(s.Signers)),
		Votes:         make(map[common.Address]*Vote),
		Tally:         make(map[common.Address]*big.Int),
		Voters:        make(map[common.Address]*big.Int),
		Candidates:    make(map[common.Address]uint64),
		Punished:      make(map[common.Address]uint64),
		Proposals:     make(map[common.Hash]*Proposal),
		Confirmations: make(map[uint64][]*common.Address),

		HeaderTime:     s.HeaderTime,
		LoopStartTime:  s.LoopStartTime,
		ProposalRefund: make(map[uint64]map[common.Address]*big.Int),
	}
	copy(cpy.HistoryHash, s.HistoryHash)
	copy(cpy.Signers, s.Signers)
	for voter, vote := range s.Votes {
		cpy.Votes[voter] = &Vote{
			Voter:     vote.Voter,
			Candidate: vote.Candidate,
			Stake:     new(big.Int).Set(vote.Stake),
		}
	}
	for candidate, tally := range s.Tally {
		cpy.Tally[candidate] = new(big.Int).Set(tally)
	}
	for voter, number := range s.Voters {
		cpy.Voters[voter] = new(big.Int).Set(number)
	}
	for candidate, state := range s.Candidates {
		cpy.Candidates[candidate] = state
	}
	for signer, cnt := range s.Punished {
		cpy.Punished[signer] = cnt
	}
	for blockNumber, confirmers := range s.Confirmations {
		cpy.Confirmations[blockNumber] = make([]*common.Address, len(confirmers))
		copy(cpy.Confirmations[blockNumber], confirmers)
	}
	for txHash, proposal := range s.Proposals {
		cpy.Proposals[txHash] = proposal.copy()
	}
	for number, refund := range s.ProposalRefund {
		cpy.ProposalRefund[number] = make(map[common.Address]*big.Int)
		for proposer, deposit := range refund {
			cpy.ProposalRefund[number][proposer] = new(big.Int).Set(deposit)
		}
	}

	return cpy
}

// apply creates a new authorization snapshot by applying the given headers to
// the original one.
func (s *Snapshot) apply(headers []*types.Header) (*Snapshot, error) {
	// Allow passing in no headers for cleaner code
	if len(headers) == 0 {
		return s, nil
	}
	// Sanity check that the headers can be applied
	for i := 0; i < len(headers)-1; i++ {
		if headers[i+1].Number.Uint64() != headers[i].Number.Uint64()+1 {
			return nil, errInvalidVotingChain
		}
	}
	if headers[0].Number.Uint64() != s.Number+1 {
		return nil, errInvalidVotingChain
	}
	// Iterate through the headers and create a new snapshot
	snap := s.copy()

	for _, header := range headers {
		// Resolve the authorization key and check against signers
		coinbase, err := ecrecover(header, s.sigcache)
		if err != nil {
			return nil, err
		}
		if coinbase.Str() != header.Coinbase.Str() {
			return nil, errUnauthorizedSigner
		}

		headerExtra := HeaderExtra{}
		err = decodeHeaderExtra(header.Extra[extraVanity:len(header.Extra)-extraSeal], &headerExtra)
		if err != nil {
			return nil, err
		}
		snap.HeaderTime = header.Time.Uint64()
		snap.LoopStartTime = headerExtra.LoopStartTime
		snap.Signers = nil
		for i := range headerExtra.SignersPool {
			snap.Signers = append(snap.Signers, &headerExtra.SignersPool[i])
		}

		snap.ConfirmedNumber = headerExtra.ConfirmedBlockNumber

		if len(snap.HistoryHash) >= int(s.config.MaxSignerCount)*2 {
			snap.HistoryHash = snap.HistoryHash[1 : int(s.config.MaxSignerCount)*2]
		}
		snap.HistoryHash = append(snap.HistoryHash, header.Hash())

		// deal the new confirmation in this block
		snap.updateSnapshotByConfirmations(headerExtra.CurrentBlockConfirmations)

		// deal the new vote from voter
		snap.updateSnapshotByVotes(headerExtra.CurrentBlockVotes, header.Number)

		// deal the voter which balance modified
		snap.updateSnapshotByMPVotes(headerExtra.ModifyPredecessorVotes)

		// deal the snap related with punished
		snap.updateSnapshotForPunish(headerExtra.SignerMissing, header.Number, header.Coinbase)

		// deal proposals
		snap.updateSnapshotByProposals(headerExtra.CurrentBlockProposals, header.Number)

		// deal declares
		snap.updateSnapshotByDeclares(headerExtra.CurrentBlockDeclares, header.Number)

		// deal trantor upgrade
		if snap.Period == 0 {
			snap.Period = snap.config.Period
		}

		// calculate proposal result
		snap.calculateProposalResult(header.Number)

		// check the len of candidate if not candidateNeedPD
		if !candidateNeedPD && (snap.Number+1)%(snap.config.MaxSignerCount*snap.config.SignerBlocks*snap.LCRS) == 0 && len(snap.Candidates) > candidateMaxLen {
			snap.removeExtraCandidate()
		}
		snap.updateSnapshotForExpired(header.Number)
	}
	snap.Number += uint64(len(headers))
	snap.Hash = headers[len(headers)-1].Hash()

	err := snap.verifyTallyCnt()
	if err != nil {
		return nil, err
	}
	return snap, nil
}

//func (s *Snapshot) removeExtraCandidate() {
//	// remove minimum tickets tally beyond candidateMaxLen
//	tallySlice := s.buildTallySlice()
//	sort.Sort(TallySlice(tallySlice))
//	if len(tallySlice) > candidateMaxLen {
//		removeNeedTally := tallySlice[candidateMaxLen:]
//		for _, tallySlice := range removeNeedTally {
//			delete(s.Candidates, tallySlice.addr)
//		}
//	}
//}
//
//func (s *Snapshot) verifyTallyCnt() error {
//
//	tallyTarget := make(map[common.Address]*big.Int)
//	for _, v := range s.Votes {
//		if _, ok := tallyTarget[v.Candidate]; ok {
//			tallyTarget[v.Candidate].Add(tallyTarget[v.Candidate], v.Stake)
//		} else {
//			tallyTarget[v.Candidate] = new(big.Int).Set(v.Stake)
//		}
//	}
//
//	for address, tally := range s.Tally {
//		if targetTally, ok := tallyTarget[address]; ok && targetTally.Cmp(tally) == 0 {
//			continue
//		} else {
//			return errIncorrectTallyCount
//		}
//	}
//
//	return nil
//}

func (s *Snapshot) updateSnapshotByDeclares(declares []Declare, headerNumber *big.Int) {
	for _, declare := range declares {
		if proposal, ok := s.Proposals[declare.ProposalHash]; ok {
			// check the proposal enable status and valid block number
			if proposal.ReceivedNumber.Uint64()+proposal.ValidationLoopCnt*s.config.MaxSignerCount*s.config.SignerBlocks < headerNumber.Uint64() || !s.isCandidate(declare.Declarer) {
				continue
			}
			// check if this signer already declare on this proposal
			alreadyDeclare := false
			for _, v := range proposal.Declares {
				if v.Declarer.Str() == declare.Declarer.Str() {
					// this declarer already declare for this proposal
					alreadyDeclare = true
					break
				}
			}
			if alreadyDeclare {
				continue
			}
			// add declare to proposal
			s.Proposals[declare.ProposalHash].Declares = append(s.Proposals[declare.ProposalHash].Declares,
				&Declare{declare.ProposalHash, declare.Declarer, declare.Decision})

		}
	}
}

//TODO change MaxSignerBlocks
func (s *Snapshot) calculateProposalResult(headerNumber *big.Int) {
	// process the expire proposal refund record
	expiredHeaderNumber := headerNumber.Uint64() - proposalRefundExpiredLoopCount*s.config.MaxSignerCount*s.config.SignerBlocks
	if _, ok := s.ProposalRefund[expiredHeaderNumber]; ok {
		delete(s.ProposalRefund, expiredHeaderNumber)
	}

	for hashKey, proposal := range s.Proposals {
		// the result will be calculate at receiverdNumber + vlcnt + 1
		if proposal.ReceivedNumber.Uint64()+proposal.ValidationLoopCnt*s.config.MaxSignerCount*s.config.SignerBlocks+1 == headerNumber.Uint64() {
			//return deposit for proposal
			if _, ok := s.ProposalRefund[headerNumber.Uint64()]; !ok {
				s.ProposalRefund[headerNumber.Uint64()] = make(map[common.Address]*big.Int)
			}
			if _, ok := s.ProposalRefund[headerNumber.Uint64()][proposal.Proposer]; !ok {
				s.ProposalRefund[headerNumber.Uint64()][proposal.Proposer] = new(big.Int).Set(proposal.CurrentDeposit)
			} else {
				s.ProposalRefund[headerNumber.Uint64()][proposal.Proposer].Add(s.ProposalRefund[headerNumber.Uint64()][proposal.Proposer], proposal.CurrentDeposit)
			}

			// calculate the current stake of this proposal
			judgementStake := big.NewInt(0)
			for _, tally := range s.Tally {
				judgementStake.Add(judgementStake, tally)
			}
			judgementStake.Mul(judgementStake, big.NewInt(2))
			judgementStake.Div(judgementStake, big.NewInt(3))
			// calculate declare stake
			yesDeclareStake := big.NewInt(0)
			for _, declare := range proposal.Declares {
				if declare.Decision {
					if _, ok := s.Tally[declare.Declarer]; ok {
						yesDeclareStake.Add(yesDeclareStake, s.Tally[declare.Declarer])
					}
				}
			}
			if yesDeclareStake.Cmp(judgementStake) > 0 {
				// process add candidate
				switch proposal.ProposalType {
				case proposalTypeCandidateAdd:
					if candidateNeedPD {
						s.Candidates[proposal.TargetAddress] = candidateStateNormal
					}
				case proposalTypeCandidateRemove:
					if _, ok := s.Candidates[proposal.TargetAddress]; ok && candidateNeedPD {
						delete(s.Candidates, proposal.TargetAddress)
					}
				case proposalTypeMinVoterBalanceModify:
					minVoterBalance = new(big.Int).Mul(new(big.Int).SetUint64(s.Proposals[hashKey].MinVoterBalance), big.NewInt(1e+18))
				case proposalTypeProposalDepositModify:
					proposalDeposit = new(big.Int).Mul(new(big.Int).SetUint64(s.Proposals[hashKey].ProposalDeposit), big.NewInt(1e+18))
				default:
					// TODO
				}
			}
			// remove all proposal
			delete(s.Proposals, hashKey)
		}

	}

}

func (s *Snapshot) updateSnapshotByProposals(proposals []Proposal, headerNumber *big.Int) {
	for _, proposal := range proposals {
		proposal.ReceivedNumber = new(big.Int).Set(headerNumber)
		s.Proposals[proposal.Hash] = &proposal
	}
}

func (s *Snapshot) updateSnapshotForExpired(headerNumber *big.Int) {

	// deal the expired vote
	var expiredVotes []*Vote
	checkBalance := false
	if len(s.Voters) > maxUncheckBalanceVoteCount {
		checkBalance = true
	}

	for voterAddress, voteNumber := range s.Voters {
		// clear the vote
		if expiredVote, ok := s.Votes[voterAddress]; ok {
			if headerNumber.Uint64()-voteNumber.Uint64() > s.config.Epoch || (checkBalance && s.Votes[voterAddress].Stake.Cmp(minVoterBalance) < 0) {
				expiredVotes = append(expiredVotes, expiredVote)
			}
		}
	}
	// remove expiredVotes only enough voters left
	if uint64(len(s.Voters)-len(expiredVotes)) >= s.config.MaxSignerCount {
		for _, expiredVote := range expiredVotes {
			if _, ok := s.Tally[expiredVote.Candidate]; ok {
				s.Tally[expiredVote.Candidate].Sub(s.Tally[expiredVote.Candidate], expiredVote.Stake)
				if s.Tally[expiredVote.Candidate].Cmp(big.NewInt(0)) == 0 {
					delete(s.Tally, expiredVote.Candidate)
				}
			}
			delete(s.Votes, expiredVote.Voter)
			delete(s.Voters, expiredVote.Voter)
		}
	}

	// deal the expired confirmation
	for blockNumber := range s.Confirmations {
		if headerNumber.Uint64()-blockNumber > s.config.MaxSignerCount*s.config.SignerBlocks {
			delete(s.Confirmations, blockNumber)
		}
	}

	// remove 0 stake tally
	for address, tally := range s.Tally {
		if tally.Cmp(big.NewInt(0)) <= 0 {
			delete(s.Tally, address)
		}
	}
}

func (s *Snapshot) updateSnapshotByConfirmations(confirmations []Confirmation) {
	for _, confirmation := range confirmations {
		_, ok := s.Confirmations[confirmation.BlockNumber.Uint64()]
		if !ok {
			s.Confirmations[confirmation.BlockNumber.Uint64()] = []*common.Address{}
		}
		addConfirmation := true
		for _, address := range s.Confirmations[confirmation.BlockNumber.Uint64()] {
			if confirmation.Signer.Str() == address.Str() {
				addConfirmation = false
				break
			}
		}
		if addConfirmation == true {
			var confirmSigner common.Address
			confirmSigner.Set(confirmation.Signer)
			s.Confirmations[confirmation.BlockNumber.Uint64()] = append(s.Confirmations[confirmation.BlockNumber.Uint64()], &confirmSigner)
		}
	}
}

func (s *Snapshot) updateSnapshotByVotes(votes []Vote, headerNumber *big.Int) {
	for _, vote := range votes {
		// update Votes, Tally, Voters data
		if lastVote, ok := s.Votes[vote.Voter]; ok {
			s.Tally[lastVote.Candidate].Sub(s.Tally[lastVote.Candidate], lastVote.Stake)
		}
		if _, ok := s.Tally[vote.Candidate]; ok {
			s.Tally[vote.Candidate].Add(s.Tally[vote.Candidate], vote.Stake)
		} else {
			s.Tally[vote.Candidate] = vote.Stake
			if !candidateNeedPD {
				s.Candidates[vote.Candidate] = candidateStateNormal
			}
		}

		s.Votes[vote.Voter] = &Vote{vote.Voter, vote.Candidate, vote.Stake}
		s.Voters[vote.Voter] = headerNumber
	}
}

func (s *Snapshot) updateSnapshotByMPVotes(votes []Vote) {
	for _, txVote := range votes {

		if lastVote, ok := s.Votes[txVote.Voter]; ok {
			s.Tally[lastVote.Candidate].Sub(s.Tally[lastVote.Candidate], lastVote.Stake)
			s.Tally[lastVote.Candidate].Add(s.Tally[lastVote.Candidate], txVote.Stake)
			s.Votes[txVote.Voter] = &Vote{Voter: txVote.Voter, Candidate: lastVote.Candidate, Stake: txVote.Stake}
			// do not modify header number of snap.Voters
		}
	}
}

func (s *Snapshot) updateSnapshotForPunish(signerMissing []common.Address, headerNumber *big.Int, coinbase common.Address) {
	// set punished count to half of origin in Epoch
	/*
		if headerNumber.Uint64()%s.config.Epoch == 0 {
			for bePublished := range s.Punished {
				if count := s.Punished[bePublished] / 2; count > 0 {
					s.Punished[bePublished] = count
				} else {
					delete(s.Punished, bePublished)
				}
			}
		}
	*/
	// punish the missing signer
	for _, signerEach := range signerMissing {
		if _, ok := s.Punished[signerEach]; ok {
			// 10 times of defaultFullCredit is big enough for calculate signer order
			if s.Punished[signerEach] <= 10*defaultFullCredit {
				s.Punished[signerEach] += missingPublishCredit
			}
		} else {
			s.Punished[signerEach] = missingPublishCredit
		}
	}
	// reduce the punish of sign signer
	if _, ok := s.Punished[coinbase]; ok {

		if s.Punished[coinbase] > signRewardCredit {
			s.Punished[coinbase] -= signRewardCredit
		} else {
			delete(s.Punished, coinbase)
		}
	}
	// reduce the punish for all punished
	for signerEach := range s.Punished {
		if s.Punished[signerEach] > autoRewardCredit {
			s.Punished[signerEach] -= autoRewardCredit
		} else {
			delete(s.Punished, signerEach)
		}
	}
}

// signers retrieves the list of signers
func (s *Snapshot) signers() []common.Address {
	sigs := make([]common.Address, 0, len(s.Signers))
	for _, sig := range s.Signers {
		sigs = append(sigs, *sig)
	}
	return sigs
}

// inturn returns if a signer at a given block height is in-turn or not.
func (s *Snapshot) inturn(signer common.Address, headerTime uint64) bool {
	if signersCount := len(s.Signers); signersCount > 0 {
		if loopIndex := ((headerTime - s.LoopStartTime) / (s.config.Period * s.config.SignerBlocks)) % uint64(signersCount); *s.Signers[loopIndex] == signer {
			return true
		}
	}
	return false
}

// check if address belong to voter
func (s *Snapshot) isVoter(address common.Address) bool {
	if _, ok := s.Voters[address]; ok {
		return true
	}
	return false
}

// check if address belong to candidate
func (s *Snapshot) isCandidate(address common.Address) bool {
	if _, ok := s.Candidates[address]; ok {
		return true
	}
	return false
}

// get last block number meet the confirm condition
func (s *Snapshot) getLastConfirmedBlockNumber(confirmations []Confirmation) *big.Int {

	cpyConfirmations := make(map[uint64][]*common.Address)
	for blockNumber, confirmers := range s.Confirmations {
		cpyConfirmations[blockNumber] = make([]*common.Address, len(confirmers))
		copy(cpyConfirmations[blockNumber], confirmers)
	}
	// update confirmation into snapshot
	for _, confirmation := range confirmations {
		_, ok := cpyConfirmations[confirmation.BlockNumber.Uint64()]
		if !ok {
			cpyConfirmations[confirmation.BlockNumber.Uint64()] = []*common.Address{}
		}
		addConfirmation := true
		for _, address := range cpyConfirmations[confirmation.BlockNumber.Uint64()] {
			if confirmation.Signer.Str() == address.Str() {
				addConfirmation = false
				break
			}
		}
		if addConfirmation == true {
			var confirmSigner common.Address
			confirmSigner.Set(confirmation.Signer)
			cpyConfirmations[confirmation.BlockNumber.Uint64()] = append(cpyConfirmations[confirmation.BlockNumber.Uint64()], &confirmSigner)
		}
	}

	i := s.Number
	for ; i > s.Number-s.config.MaxSignerCount*2/3+1; i-- {
		if confirmers, ok := cpyConfirmations[i]; ok {
			if len(confirmers) > int(s.config.MaxSignerCount*2/3) {
				return big.NewInt(int64(i))
			}
		}
	}
	return big.NewInt(int64(i))
}
