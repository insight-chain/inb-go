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
	"github.com/insight-chain/inb-go/params"
	"github.com/pkg/errors"
	"math/big"
	"strings"

	"github.com/insight-chain/inb-go/common"
	"github.com/insight-chain/inb-go/consensus"
	"github.com/insight-chain/inb-go/core/state"
	"github.com/insight-chain/inb-go/core/types"
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
	inbEventDeclare       = "declare"
	inbMinSplitLen        = 3
	posPrefix             = 0
	posVersion            = 1
	posCategory           = 2
	posEventVote          = 3
	posEventDeclare       = 3
	posEventConfirmNumber = 4
	posEventDeclareInfo   = 4

	posEventDeclareInfoSplitLen = 3
	posEventDeclareInfoId       = 0
	posEventDeclareInfoIp       = 1
	posEventDeclareInfoPort     = 2
	//inb by ghy begin
	posEventDeclareInfoName    = 3
	posEventDeclareInfoNation  = 4
	posEventDeclareInfoCity    = 5
	posEventDeclareInfoImage   = 6
	posEventDeclareInfoWebsite = 7
	posEventDeclareInfoEmail   = 8
	posEventDeclareInfodata    = 9
	//inb by ghy end
)

// Vote :
// vote come from custom tx which data like "inb:1:event:vote"
// Sender of tx is Voter, the tx.to is Candidate
// Stake is the balance of Voter when create this vote
type Vote struct {
	Voter common.Address
	//achilles
	Candidate []common.Address
	Stake     *big.Int
}

// HeaderExtra is the struct of info in header.Extra[extraVanity:len(header.extra)-extraSeal]
// HeaderExtra is the current struct
type HeaderExtra struct {
	CurrentBlockVotes      []Vote
	ModifyPredecessorVotes []Vote
	LoopStartTime          uint64
	SignersPool            []common.Address
	SignerMissing          []common.Address
	ConfirmedBlockNumber   uint64

	//inb by ssh begin
	Enodes []common.EnodeInfo
	//inb by ssh end

	//inb by ghy begin
	Enode []string
	//inb by ghy end
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
func (v *Vdpos) processCustomTx(headerExtra HeaderExtra, chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, vdposContext *types.VdposContext) (HeaderExtra, error) {

	for _, tx := range txs {

		txSender, err := types.Sender(types.NewEIP155Signer(tx.ChainId()), tx)
		if err != nil {
			continue
		}

		txData := string(tx.Data())
		//achilles config
		if strings.Contains(txData, "candidates") {
			var candidates []common.Address
			txDataInfo := strings.Split(txData, ":")
			if txDataInfo[0] == "candidates" {
				candidatesStr := strings.Split(txDataInfo[1], ",")
				for _, value := range candidatesStr {
					address := common.HexToAddress(value)
					candidates = append(candidates, address)
				}
				if params.TxConfig.CandidateSize < uint64(len(candidates)) {
					return headerExtra, errors.Errorf("candidates over size")
				}
				headerExtra.CurrentBlockVotes = v.processEventVote(headerExtra.CurrentBlockVotes, state, txSender, candidates, vdposContext)
			}
		}

		if len(txData) >= len(inbPrefix) {
			txDataInfo := strings.Split(txData, "|")
			if len(txDataInfo) >= inbMinSplitLen {
				if txDataInfo[posPrefix] == inbPrefix {
					if txDataInfo[posVersion] == inbVersion {
						// process vote event
						if txDataInfo[posCategory] == inbCategoryEvent {
							if len(txDataInfo) > inbMinSplitLen {
								// check is vote or not
								if txDataInfo[posEventVote] == inbEventVote {

								} else if txDataInfo[posEventDeclare] == inbEventDeclare {
									account := state.GetAccountInfo(txSender)
									if account.Resources.NET.MortgagteINB.Cmp(BeVotedNeedINB) == 1 {
										headerExtra.Enodes = v.processEventDeclare(headerExtra.Enodes, txDataInfo, txSender)
									} else {
										return headerExtra, errors.Errorf("Account mortgageINB must be greater than 100000")
									}
								}
							}
						}
					}
				}
			}
		}
		// check each address
		//if number > 1 {
		//	headerExtra.ModifyPredecessorVotes = v.processPredecessorVoter(headerExtra.ModifyPredecessorVotes, state, tx, txSender, snap)
		//}

	}
	return headerExtra, nil
}

func (v *Vdpos) processEventDeclare(currentEnodeInfos []common.EnodeInfo, txDataInfo []string, declarer common.Address) []common.EnodeInfo {

	if len(txDataInfo) > posEventDeclareInfo {
		midEnodeInfo := strings.Split(txDataInfo[posEventDeclareInfo], "~")
		if len(midEnodeInfo) >= posEventDeclareInfoSplitLen {
			enodeInfo := common.EnodeInfo{
				Id:      midEnodeInfo[posEventDeclareInfoId],
				Ip:      midEnodeInfo[posEventDeclareInfoIp],
				Port:    midEnodeInfo[posEventDeclareInfoPort],
				Address: declarer,
			}
			//inb by ghy begin
			if len(midEnodeInfo) >= 4 {
				enodeInfo.Name = midEnodeInfo[posEventDeclareInfoName]
			}

			if len(midEnodeInfo) >= 5 {
				enodeInfo.Nation = midEnodeInfo[posEventDeclareInfoNation]
			}

			if len(midEnodeInfo) >= 6 {
				enodeInfo.City = midEnodeInfo[posEventDeclareInfoCity]

			}

			if len(midEnodeInfo) >= 7 {
				enodeInfo.Image = midEnodeInfo[posEventDeclareInfoImage]

			}
			if len(midEnodeInfo) >= 8 {
				enodeInfo.Website = midEnodeInfo[posEventDeclareInfoWebsite]
			}
			if len(midEnodeInfo) >= 9 {
				enodeInfo.Email = midEnodeInfo[posEventDeclareInfoEmail]
			}

			data := `{`
			if len(midEnodeInfo) >= 10 {
				enodeData := strings.Split(midEnodeInfo[posEventDeclareInfodata], "-")
				for _, v := range enodeData {
					split := strings.Split(v, "/")
					if len(split) == 2 {
						data += `"` + split[0] + `":"` + split[1] + `",`
					}
				}
				data = strings.TrimRight(data, ",")
			}
			data += `}`
			enodeInfo.Data = data

			//inb by ghy end
			flag := false
			for i, enode := range currentEnodeInfos {
				if enode.Address == declarer {
					flag = true
					currentEnodeInfos[i] = enodeInfo
					break
				}
			}
			if !flag {
				currentEnodeInfos = append(currentEnodeInfos, enodeInfo)
			}
		}
	}
	return currentEnodeInfos
}

func (v *Vdpos) processEventVote(currentBlockVotes []Vote, state *state.StateDB, voter common.Address, candidates []common.Address, vdposContext *types.VdposContext) []Vote {
	//if state.GetMortgageInbOfNet(voter).Cmp(minVoterBalance) > 0 {
	v.lock.RLock()
	stake := state.GetMortgageInbOfNet(voter)
	v.lock.RUnlock()

	vote := &types.Votes{
		Voter:     voter,
		Candidate: candidates,
		Stake:     stake,
	}

	currentBlockVotes = append(currentBlockVotes, Vote{
		Voter:     voter,
		Candidate: candidates,
		Stake:     stake,
	})
	vdposContext.UpdateVotes(vote)
	vdposContext.UpdateTallysByVotes(vote)

	//}
	//state.AddVoteRecord(voter,stake)

	return currentBlockVotes
}

//func (v *Vdpos) processPredecessorVoter(modifyPredecessorVotes []Vote, state *state.StateDB, tx *types.Transaction, voter common.Address, snap *Snapshot) []Vote {
//	// process normal transaction which relate to voter
//	if tx.Value().Cmp(big.NewInt(0)) > 0 {
//		if snap.isVoter(voter) {
//			v.lock.RLock()
//			stake := state.GetMortgageInbOfNet(voter)
//			v.lock.RUnlock()
//			modifyPredecessorVotes = append(modifyPredecessorVotes, Vote{
//				Voter:     voter,
//				Candidate: []common.Address{voter},
//				Stake:     stake,
//			})
//		}
//		if snap.isVoter(*tx.To()) {
//			v.lock.RLock()
//			stake := state.GetMortgageInbOfNet(*tx.To())
//			v.lock.RUnlock()
//			modifyPredecessorVotes = append(modifyPredecessorVotes, Vote{
//				Voter:     *tx.To(),
//				Candidate: []common.Address{voter},
//				Stake:     stake,
//			})
//		}
//
//	}
//	return modifyPredecessorVotes
//}
