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
	"math/big"
	"strconv"
	"strings"

	"github.com/insight-chain/inb-go/common"
	"github.com/insight-chain/inb-go/consensus"
	"github.com/insight-chain/inb-go/core/state"
	"github.com/insight-chain/inb-go/core/types"
	"github.com/insight-chain/inb-go/log"
	"github.com/insight-chain/inb-go/rlp"
)

const (
	/*
	 *  inb:version:category:action/data
	 */
	inbPrefix             = "inb"
	inbVersion            = "1"
	inbCategoryEvent      = "event"
	inbEventVote          = "vote"
	inbEventConfirm       = "confirm"
	inbEventProposal      = "proposal"
	inbEventDeclare       = "declare"
	inbMinSplitLen        = 3
	posPrefix             = 0
	posVersion            = 1
	posCategory           = 2
	posEventVote          = 3
	posEventConfirm       = 3
	posEventProposal      = 3
	posEventDeclare       = 3
	posEventConfirmNumber = 4

	/*
	 *  proposal type
	 */
	proposalTypeCandidateAdd          = 1
	proposalTypeCandidateRemove       = 2
	proposalTypeMinVoterBalanceModify = 3
	proposalTypeProposalDepositModify = 4

	/*
	 * proposal related
	 */
	maxValidationLoopCnt     = 50000  // About one month if period = 3 & 21 super nodes
	minValidationLoopCnt     = 4      // for test, Note: 12350  About three days if seal each block per second & 21 super nodes
	defaultValidationLoopCnt = 10000  // About one week if period = 3 & 21 super nodes
	maxProposalDeposit       = 100000 // If no limit on max proposal deposit and 1 billion TTC deposit success passed, then no new proposal.

)

// RefundGas :
// refund gas to tx sender
type RefundGas map[common.Address]*big.Int

// RefundPair :
type RefundPair struct {
	Sender   common.Address
	GasPrice *big.Int
}

// RefundHash :
type RefundHash map[common.Hash]RefundPair

// Vote :
// vote come from custom tx which data like "inb:1:event:vote"
// Sender of tx is Voter, the tx.to is Candidate
// Stake is the balance of Voter when create this vote
type Vote struct {
	Voter     common.Address
	Candidate common.Address
	Stake     *big.Int
}

// Confirmation :
// confirmation come from custom tx which data like "inb:1:event:confirm:123"
// 123 is the block number be confirmed
// Sender of tx is Signer only if the signer in the SignersPool for block number 123
type Confirmation struct {
	Signer      common.Address
	BlockNumber *big.Int
}

// Proposal :
// proposal come from custom tx which data like "inb:1:event:proposal:candidate:add:address" or "inb:1:event:proposal:percentage:60"
// proposal only come from the current candidates
// not only candidate add/remove , current signer can proposal for params modify like percentage of reward distribution ...
type Proposal struct {
	Hash              common.Hash    // tx hash
	ReceivedNumber    *big.Int       // block number of proposal received
	CurrentDeposit    *big.Int       // received deposit for this proposal
	ValidationLoopCnt uint64         // validation block number length of this proposal from the received block number
	ProposalType      uint64         // type of proposal 1 - add candidate 2 - remove candidate ...
	Proposer          common.Address // proposer
	TargetAddress     common.Address // candidate need to add/remove if candidateNeedPD == true
	MinerReward       *big.Int       // reward of miner
	Declares          []*Declare     // Declare this proposal received (always empty in block header)
	MinVoterBalance   uint64         // value of minVoterBalance , need to mul big.Int(1e+18)
	ProposalDeposit   uint64         // The deposit need to be frozen during before the proposal get final conclusion.
}

func (p *Proposal) copy() *Proposal {
	cpy := &Proposal{
		Hash:              p.Hash,
		ReceivedNumber:    new(big.Int).Set(p.ReceivedNumber),
		CurrentDeposit:    new(big.Int).Set(p.CurrentDeposit),
		ValidationLoopCnt: p.ValidationLoopCnt,
		ProposalType:      p.ProposalType,
		Proposer:          p.Proposer,
		TargetAddress:     p.TargetAddress,
		MinerReward:       p.MinerReward,
		Declares:          make([]*Declare, len(p.Declares)),
		MinVoterBalance:   p.MinVoterBalance,
		ProposalDeposit:   p.ProposalDeposit,
	}

	copy(cpy.Declares, p.Declares)
	return cpy
}

// Declare :
// declare come from custom tx which data like "inb:1:event:declare:hash:yes"
// declare only come from the current candidates
// hash is the hash of proposal tx
type Declare struct {
	ProposalHash common.Hash
	Declarer     common.Address
	Decision     bool
}

// HeaderExtra is the struct of info in header.Extra[extraVanity:len(header.extra)-extraSeal]
// HeaderExtra is the current struct
type HeaderExtra struct {
	CurrentBlockConfirmations []Confirmation
	CurrentBlockVotes         []Vote
	CurrentBlockProposals     []Proposal
	CurrentBlockDeclares      []Declare
	ModifyPredecessorVotes    []Vote
	LoopStartTime             uint64
	SignersPool               []common.Address
	SignerMissing             []common.Address
	ConfirmedBlockNumber      uint64
}

// Encode HeaderExtra
//func encodeHeaderExtra(config *params.VdposConfig, number *big.Int, val HeaderExtra) ([]byte, error) {
//
//	var headerExtra interface{}
//	switch {
//	//case config.IsTrantor(number):
//
//	default:
//		headerExtra = val
//	}
//	return rlp.EncodeToBytes(headerExtra)
//
//}

func encodeHeaderExtra(val HeaderExtra) ([]byte, error) {
	var headerExtra interface{}
	headerExtra = val
	return rlp.EncodeToBytes(headerExtra)

}

// Decode HeaderExtra
//func decodeHeaderExtra(config *params.VdposConfig, number *big.Int, b []byte, val *HeaderExtra) error {
//	var err error
//	switch {
//	//case config.IsTrantor(number):
//	default:
//		err = rlp.DecodeBytes(b, val)
//	}
//	return err
//}

func decodeHeaderExtra(b []byte, val *HeaderExtra) error {
	var err error
	err = rlp.DecodeBytes(b, val)
	return err
}

// Calculate Votes from transaction in this block, write into header.Extra
func (v *Vdpos) processCustomTx(headerExtra HeaderExtra, chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, receipts []*types.Receipt) (HeaderExtra, RefundGas, error) {
	// if predecessor voter make transaction and vote in this block,
	// just process as vote, do it in snapshot.apply
	var (
		snap       *Snapshot
		err        error
		number     uint64
		refundGas  RefundGas
		refundHash RefundHash
	)
	refundGas = make(map[common.Address]*big.Int)
	refundHash = make(map[common.Hash]RefundPair)
	number = header.Number.Uint64()
	if number > 1 {
		snap, err = v.snapshot(chain, number-1, header.ParentHash, nil, nil, defaultLoopCntRecalculateSigners)
		if err != nil {
			return headerExtra, nil, err
		}
	}

	for _, tx := range txs {

		txSender, err := types.Sender(types.NewEIP155Signer(tx.ChainId()), tx)
		if err != nil {
			continue
		}

		if len(string(tx.Data())) >= len(inbPrefix) {
			txData := string(tx.Data())
			txDataInfo := strings.Split(txData, ":")
			if len(txDataInfo) >= inbMinSplitLen {
				if txDataInfo[posPrefix] == inbPrefix {
					if txDataInfo[posVersion] == inbVersion {
						// process vote event
						if txDataInfo[posCategory] == inbCategoryEvent {
							if len(txDataInfo) > inbMinSplitLen {
								// check is vote or not
								if txDataInfo[posEventVote] == inbEventVote && (!candidateNeedPD || snap.isCandidate(*tx.To())) {
									headerExtra.CurrentBlockVotes = v.processEventVote(headerExtra.CurrentBlockVotes, state, tx, txSender)
								} else if txDataInfo[posEventConfirm] == inbEventConfirm && snap.isCandidate(txSender) {
									headerExtra.CurrentBlockConfirmations, refundHash = v.processEventConfirm(headerExtra.CurrentBlockConfirmations, chain, txDataInfo, number, tx, txSender, refundHash)
								} else if txDataInfo[posEventProposal] == inbEventProposal {
									headerExtra.CurrentBlockProposals = v.processEventProposal(headerExtra.CurrentBlockProposals, txDataInfo, state, tx, txSender, snap)
								} else if txDataInfo[posEventDeclare] == inbEventDeclare && snap.isCandidate(txSender) {
									headerExtra.CurrentBlockDeclares = v.processEventDeclare(headerExtra.CurrentBlockDeclares, txDataInfo, tx, txSender)
								}
							} else {
								// todo : leave this transaction to process as normal transaction
							}
						}
					}
				}
			}
		}
		// check each address
		if number > 1 {
			headerExtra.ModifyPredecessorVotes = v.processPredecessorVoter(headerExtra.ModifyPredecessorVotes, state, tx, txSender, snap)
		}

	}

	for _, receipt := range receipts {
		if pair, ok := refundHash[receipt.TxHash]; ok && receipt.Status == 1 {
			pair.GasPrice.Mul(pair.GasPrice, big.NewInt(int64(receipt.GasUsed)))
			refundGas = v.refundAddGas(refundGas, pair.Sender, pair.GasPrice)
		}
	}
	return headerExtra, refundGas, nil
}

func (v *Vdpos) refundAddGas(refundGas RefundGas, address common.Address, value *big.Int) RefundGas {
	if _, ok := refundGas[address]; ok {
		refundGas[address].Add(refundGas[address], value)
	} else {
		refundGas[address] = value
	}

	return refundGas
}

func (v *Vdpos) processEventProposal(currentBlockProposals []Proposal, txDataInfo []string, state *state.StateDB, tx *types.Transaction, proposer common.Address, snap *Snapshot) []Proposal {
	// sample for declare
	// eth.sendTransaction({from:eth.accounts[0],to:eth.accounts[0],value:0,data:web3.toHex("inb:1:event:declare:hash:0x853e10706e6b9d39c5f4719018aa2417e8b852dec8ad18f9c592d526db64c725:decision:yes")})
	if len(txDataInfo) <= posEventProposal+2 {
		return currentBlockProposals
	}

	proposal := Proposal{
		Hash:              tx.Hash(),
		ReceivedNumber:    big.NewInt(0),
		CurrentDeposit:    proposalDeposit, // for all type of deposit
		ValidationLoopCnt: defaultValidationLoopCnt,
		ProposalType:      proposalTypeCandidateAdd,
		Proposer:          proposer,
		TargetAddress:     common.Address{},
		MinerReward:       defaultMinerReward,
		Declares:          []*Declare{},
		MinVoterBalance:   new(big.Int).Div(minVoterBalance, big.NewInt(1e+18)).Uint64(),
		ProposalDeposit:   new(big.Int).Div(proposalDeposit, big.NewInt(1e+18)).Uint64(), // default value
	}

	for i := 0; i < len(txDataInfo[posEventProposal+1:])/2; i++ {
		k, v := txDataInfo[posEventProposal+1+i*2], txDataInfo[posEventProposal+2+i*2]
		switch k {
		case "vlcnt":
			// If vlcnt is missing then user default value, but if the vlcnt is beyond the min/max value then ignore this proposal
			if validationLoopCnt, err := strconv.Atoi(v); err != nil || validationLoopCnt < minValidationLoopCnt || validationLoopCnt > maxValidationLoopCnt {
				return currentBlockProposals
			} else {
				proposal.ValidationLoopCnt = uint64(validationLoopCnt)
			}
		case "proposal_type":
			if proposalType, err := strconv.Atoi(v); err != nil {
				return currentBlockProposals
			} else {
				proposal.ProposalType = uint64(proposalType)
			}
		case "candidate":
			proposal.TargetAddress.UnmarshalText([]byte(v))
		case "mvb":
			// minVoterBalance
			if mvb, err := strconv.Atoi(v); err != nil || mvb <= 0 {
				return currentBlockProposals
			} else {
				proposal.MinVoterBalance = uint64(mvb)
			}
		case "mpd":
			// proposalDeposit
			if mpd, err := strconv.Atoi(v); err != nil || mpd <= 0 || mpd > maxProposalDeposit {
				return currentBlockProposals
			} else {
				proposal.ProposalDeposit = uint64(mpd)
			}
		}
	}
	// now the proposal is built
	currentProposalPay := new(big.Int).Set(proposalDeposit)
	// check enough balance for deposit
	if state.GetBalance(proposer).Cmp(currentProposalPay) < 0 {
		return currentBlockProposals
	}
	// collection the fee for this proposal (deposit and other fee , sc rent fee ...)
	state.SetBalance(proposer, new(big.Int).Sub(state.GetBalance(proposer), currentProposalPay))

	return append(currentBlockProposals, proposal)
}

//func (v *Vdpos) processEventDeclare(currentBlockDeclares []Declare, txDataInfo []string, tx *types.Transaction, declarer common.Address) []Declare {
//	if len(txDataInfo) <= posEventDeclare+2 {
//		return currentBlockDeclares
//	}
//	declare := Declare{
//		ProposalHash: common.Hash{},
//		Declarer:     declarer,
//		Decision:     true,
//	}
//	for i := 0; i < len(txDataInfo[posEventDeclare+1:])/2; i++ {
//		k, v := txDataInfo[posEventDeclare+1+i*2], txDataInfo[posEventDeclare+2+i*2]
//		switch k {
//		case "hash":
//			declare.ProposalHash.UnmarshalText([]byte(v))
//		case "decision":
//			if v == "yes" {
//				declare.Decision = true
//			} else if v == "no" {
//				declare.Decision = false
//			} else {
//				return currentBlockDeclares
//			}
//		}
//	}
//
//	return append(currentBlockDeclares, declare)
//}

func (v *Vdpos) processEventVote(currentBlockVotes []Vote, state *state.StateDB, tx *types.Transaction, voter common.Address) []Vote {
	if state.GetBalance(voter).Cmp(minVoterBalance) > 0 {

		v.lock.RLock()
		stake := state.GetBalance(voter)
		v.lock.RUnlock()

		currentBlockVotes = append(currentBlockVotes, Vote{
			Voter:     voter,
			Candidate: *tx.To(),
			Stake:     stake,
		})
	}

	return currentBlockVotes
}

func (v *Vdpos) processEventConfirm(currentBlockConfirmations []Confirmation, chain consensus.ChainReader, txDataInfo []string, number uint64, tx *types.Transaction, confirm common.Address, refundHash RefundHash) ([]Confirmation, RefundHash) {
	if len(txDataInfo) > posEventConfirmNumber {
		confirmedBlockNumber := new(big.Int)
		err := confirmedBlockNumber.UnmarshalText([]byte(txDataInfo[posEventConfirmNumber]))
		if err != nil || number-confirmedBlockNumber.Uint64() > v.config.MaxSignerCount*v.config.SignerBlocks || number-confirmedBlockNumber.Uint64() < 0 {
			return currentBlockConfirmations, refundHash
		}
		// check if the voter is in block
		confirmedHeader := chain.GetHeaderByNumber(confirmedBlockNumber.Uint64())
		if confirmedHeader == nil {
			return currentBlockConfirmations, refundHash
		}
		confirmedHeaderExtra := HeaderExtra{}
		if extraVanity+extraSeal > len(confirmedHeader.Extra) {
			return currentBlockConfirmations, refundHash
		}
		err = decodeHeaderExtra(confirmedHeader.Extra[extraVanity:len(confirmedHeader.Extra)-extraSeal], &confirmedHeaderExtra)
		if err != nil {
			log.Info("Fail to decode parent header", "err", err)
			return currentBlockConfirmations, refundHash
		}
		for _, s := range confirmedHeaderExtra.SignersPool {
			if s == confirm {
				currentBlockConfirmations = append(currentBlockConfirmations, Confirmation{
					Signer:      confirm,
					BlockNumber: new(big.Int).Set(confirmedBlockNumber),
				})
				refundHash[tx.Hash()] = RefundPair{confirm, tx.GasPrice()}
				break
			}
		}
	}

	return currentBlockConfirmations, refundHash
}

func (v *Vdpos) processPredecessorVoter(modifyPredecessorVotes []Vote, state *state.StateDB, tx *types.Transaction, voter common.Address, snap *Snapshot) []Vote {
	// process normal transaction which relate to voter
	if tx.Value().Cmp(big.NewInt(0)) > 0 {
		if snap.isVoter(voter) {
			v.lock.RLock()
			stake := state.GetBalance(voter)
			v.lock.RUnlock()
			modifyPredecessorVotes = append(modifyPredecessorVotes, Vote{
				Voter:     voter,
				Candidate: common.Address{},
				Stake:     stake,
			})
		}
		if snap.isVoter(*tx.To()) {
			v.lock.RLock()
			stake := state.GetBalance(*tx.To())
			v.lock.RUnlock()
			modifyPredecessorVotes = append(modifyPredecessorVotes, Vote{
				Voter:     *tx.To(),
				Candidate: common.Address{},
				Stake:     stake,
			})
		}

	}
	return modifyPredecessorVotes
}
