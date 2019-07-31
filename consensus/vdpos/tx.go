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
	"github.com/insight-chain/inb-go/log"
	"github.com/insight-chain/inb-go/rlp"
)

const (
	/*
	 *  inb:version:category:action/data
	 */
	inbPrefix              = "inb"
	inbVersion             = "1"
	inbCategoryEvent       = "event"
	inbEventVote           = "vote"
	inbEventVoteCandidates = "candidates"
	inbEventConfirm        = "confirm"
	inbEventDeclare        = "declare"
	inbMinSplitLen         = 3
	posPrefix              = 0
	posVersion             = 1
	posCategory            = 2
	posEventVote           = 3
	posEventConfirm        = 3
	posEventDeclare        = 3
	posEventConfirmNumber  = 4
	posEventDeclareInfo    = 4
	//achilles
	posEventVoteCandidates       = 4
	posEventVoteCandidatesNumber = 5

	posEventDeclareInfoSplitLen = 3
	posEventDeclareInfoId       = 0
	posEventDeclareInfoIp       = 1
	posEventDeclareInfoPort     = 2
	//inb by ghy begin
	posEventDeclareInfoName     = 3
	posEventDeclareInfoNation   = 4
	posEventDeclareInfoCity     = 5
	posEventDeclareInfoImage    = 6
	posEventDeclareInfoWebsite  = 7
	posEventDeclareInfoEmail    = 8
	posEventDeclareInfodata     = 9
	//inb by ghy end
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
	Voter common.Address
	//achilles
	Candidate []common.Address
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



// HeaderExtra is the struct of info in header.Extra[extraVanity:len(header.extra)-extraSeal]
// HeaderExtra is the current struct
type HeaderExtra struct {
	CurrentBlockConfirmations []Confirmation
	CurrentBlockVotes         []Vote
	ModifyPredecessorVotes    []Vote
	LoopStartTime             uint64
	SignersPool               []common.Address
	SignerMissing             []common.Address
	ConfirmedBlockNumber      uint64

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
					return headerExtra, nil, errors.Errorf("candidates over size")
				}
				headerExtra.CurrentBlockVotes = v.processEventVote(headerExtra.CurrentBlockVotes, state, txSender, candidates)
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
									//var candidates []common.Address
									////achilles vote
									//if txDataInfo[posEventVoteCandidates] == inbEventVoteCandidates {
									//	candidatesStr := strings.Split(txDataInfo[posEventVoteCandidatesNumber], ",")
									//	for _, value := range candidatesStr {
									//		address := common.HexToAddress(value)
									//		candidates = append(candidates, address)
									//	}
									//	if core.DefaultTxPoolConfig.CandidateSize < uint64(len(candidates)) {
									//		return headerExtra,nil,errors.Errorf("candidates of vote length over size")
									//	}
									//}
									//headerExtra.CurrentBlockVotes = v.processEventVote(headerExtra.CurrentBlockVotes, state, txSender, candidates)
								} else if txDataInfo[posEventConfirm] == inbEventConfirm && snap.isCandidate(txSender) {
									headerExtra.CurrentBlockConfirmations, refundHash = v.processEventConfirm(headerExtra.CurrentBlockConfirmations, chain, txDataInfo, number, tx, txSender, refundHash)
								} else if txDataInfo[posEventDeclare] == inbEventDeclare {
									account := state.GetAccountInfo(txSender)
									if account.Resources.NET.MortgagteINB.Cmp(BeVotedNeedINB)==1{
										headerExtra.Enodes = v.processEventDeclare(headerExtra.Enodes, txDataInfo, txSender)
									}else {
										return headerExtra, nil, errors.Errorf("Account mortgageINB must be greater than 100000")
									}
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
		//if number > 1 {
		//	headerExtra.ModifyPredecessorVotes = v.processPredecessorVoter(headerExtra.ModifyPredecessorVotes, state, tx, txSender, snap)
		//}

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
			if len(midEnodeInfo) >=4{
				enodeInfo.Name=midEnodeInfo[posEventDeclareInfoName]
			}

			if len(midEnodeInfo) >=5{
				enodeInfo.Nation=midEnodeInfo[posEventDeclareInfoNation]
			}

			if len(midEnodeInfo) >=6{
				enodeInfo.City=midEnodeInfo[posEventDeclareInfoCity]

			}

			if len(midEnodeInfo) >=7{
				enodeInfo.Image=midEnodeInfo[posEventDeclareInfoImage]

			}
			if len(midEnodeInfo) >=8{
				enodeInfo.Website=midEnodeInfo[posEventDeclareInfoWebsite]
			}
			if len(midEnodeInfo) >=9{
				enodeInfo.Email=midEnodeInfo[posEventDeclareInfoEmail]
			}

			data:=`{`
			if len(midEnodeInfo) >=10{
				enodeData:=strings.Split(midEnodeInfo[posEventDeclareInfodata], "-")
				for _,v:=range enodeData{
					split := strings.Split(v, "/")
					if len(split)==2{
						data+=`"`+split[0]+`":"`+split[1]+`",`
					}
				}
						data=strings.TrimRight(data,",")
			}
			data+=`}`
			enodeInfo.Data=data

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

func (v *Vdpos) processEventVote(currentBlockVotes []Vote, state *state.StateDB, voter common.Address, candidates []common.Address) []Vote {
	//if state.GetMortgageInbOfNet(voter).Cmp(minVoterBalance) > 0 {
	v.lock.RLock()
	stake := state.GetMortgageInbOfNet(voter)
	v.lock.RUnlock()

	currentBlockVotes = append(currentBlockVotes, Vote{
		Voter:     voter,
		Candidate: candidates,
		Stake:     stake,
	})
	//}
	//state.AddVoteRecord(voter,stake)

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
			stake := state.GetMortgageInbOfNet(voter)
			v.lock.RUnlock()
			modifyPredecessorVotes = append(modifyPredecessorVotes, Vote{
				Voter:     voter,
				Candidate: []common.Address{voter},
				Stake:     stake,
			})
		}
		if snap.isVoter(*tx.To()) {
			v.lock.RLock()
			stake := state.GetMortgageInbOfNet(*tx.To())
			v.lock.RUnlock()
			modifyPredecessorVotes = append(modifyPredecessorVotes, Vote{
				Voter:     *tx.To(),
				Candidate: []common.Address{voter},
				Stake:     stake,
			})
		}

	}
	return modifyPredecessorVotes
}
