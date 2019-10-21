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
	"github.com/insight-chain/inb-go/log"
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
	PosEventIssueLightTokenSplitLen    = 4
	PosEventIssueLightTokenName        = 0
	PosEventIssueLightTokenSymbol      = 1
	PosEventIssueLightTokenDecimals    = 2
	PosEventIssueLightTokenTotalSupply = 3
)

// HeaderExtra is the struct of info in header.Extra[extraVanity:len(header.extra)-extraSeal]
// HeaderExtra is the current struct
type HeaderExtra struct {
	LoopStartTime        uint64
	SignersPool          []common.Address
	SignerMissing        []common.Address
	ConfirmedBlockNumber uint64
	//Enodes               []common.SuperNode
}

func encodeHeaderExtra(val HeaderExtra) ([]byte, error) {
	var headerExtra interface{}
	headerExtra = val
	return rlp.EncodeToBytes(headerExtra)

}

func decodeHeaderExtra(b []byte, val *HeaderExtra) error {
	var err error
	err = rlp.DecodeBytes(b, val)
	return err
}

// Calculate Votes from transaction in this block, write into header.Extra
func (v *Vdpos) processCustomTx(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, vdposContext *types.VdposContext) error {

	for _, tx := range txs {
		txSender, err := types.Sender(types.NewEIP155Signer(tx.ChainId()), tx)
		if err != nil {
			log.Error("Fail to get txSender", "err", err)
			continue
		}

		txData := string(tx.Data())
		//2019.8.5 inb mod by ghy begin
		if tx.WhichTypes(types.Vote) {
			var candidates []common.Address
			candidatesStr := strings.Split(txData, ",")
			for _, value := range candidatesStr {
				address := common.HexToAddress(value)
				candidates = append(candidates, address)
			}
			if params.TxConfig.CandidateSize < uint64(len(candidates)) {
				log.Error("Candidates over size")
				continue
			}
			err = v.processEventVote(state, txSender, candidates, vdposContext)
			if err != nil {
				log.Error("Fail in Vdpos.processEventVote()", "err", err)
				continue
			}

		}

		if tx.WhichTypes(types.UpdateNodeInformation) {
			if state.GetStakingValue(txSender).Cmp(BeVotedNeedINB) == 1 {
				err = v.processEventDeclare(tx.Data(), txSender, vdposContext)
				if err != nil {
					log.Error("Fail in Vdpos.processEventDeclare()", "err", err)
					continue
				}
			} else {
				log.Error("Update node info account mortgage less than %v inb", BeVotedNeedINB)
				continue
			}
		}

		if tx.WhichTypes(types.IssueLightToken) {
			err = v.processEventIssueLightToken(tx, txSender, vdposContext)
			if err != nil {
				log.Error("Fail in Vdpos.processEventIssueLightToken()", "err", err)
				continue
			}
		}

		if tx.WhichTypes(types.TransferLightToken) {
			txReceiver := *tx.To()
			value := tx.Value()
			err = v.processEventTransferLightToken(txData, txSender, txReceiver, value, vdposContext)
			if err != nil {
				log.Error("Fail in Vdpos.processEventTransferLightToken()", "err", err)
				continue
			}
		}

		// check each address
		number := header.Number.Uint64()
		if number > 1 {
			err = v.processPredecessorVoter(state, tx, txSender, vdposContext)
			if err != nil {
				log.Error("Fail in Vdpos.processPredecessorVoter()", "err", err)
				continue
			}
		}

	}

	//2019.8.5 inb mod by ghy end

	return nil
}

func (v *Vdpos) processEventVote(state *state.StateDB, voter common.Address, candidates []common.Address, vdposContext *types.VdposContext) error {
	v.lock.RLock()
	stakingValue := state.GetStakingValue(voter)
	v.lock.RUnlock()

	vote := &types.Votes{
		Voter:        voter,
		Candidate:    candidates,
		StakingValue: stakingValue,
	}

	err := vdposContext.UpdateTallysByVotes(vote, state)
	if err != nil {
		return err
	}
	err = vdposContext.UpdateVotes(vote)
	if err != nil {
		return err
	}

	return nil
}

func (v *Vdpos) processEventDeclare(txDataInfo []byte, declarer common.Address, vdposContext *types.VdposContext) error {

	//inb by ghy begin
	nodeInfo := new(common.SuperNodeExtra)
	if err := json.Unmarshal(txDataInfo, nodeInfo); err != nil {
		return err
	}
	enodeInfo := common.SuperNode{
		Id:            nodeInfo.Id,
		Ip:            nodeInfo.Ip,
		Port:          nodeInfo.Port,
		Address:       declarer,
		RewardAccount: nodeInfo.RewardAccount,
	}

	nodeInfo.Address = declarer

	//enodeInfo.Id = midEnodeInfo[PosEventDeclareInfoId]
	//enodeInfo.Ip = midEnodeInfo[PosEventDeclareInfoIp]
	//enodeInfo.Port = midEnodeInfo[PosEventDeclareInfoPort]
	//enodeInfo.Address = declarer

	//data := `{`
	//if len(midEnodeInfo) >= 10 {
	//	enodeData := strings.Split(midEnodeInfo[PosEventDeclareInfoData], "-")
	//	for _, v := range enodeData {
	//		split := strings.Split(v, "/")
	//		if len(split) == 2 {
	//			data += `"` + split[0] + `":"` + split[1] + `",`
	//		}
	//	}
	//	data = strings.TrimRight(data, ",")
	//}
	//data += `}`
	//enodeInfoTrie.ExtraData = data

	//2019.9.4 mod by ghy
	err := vdposContext.UpdateTallysByNodeInfo(*nodeInfo)
	if err != nil {
		return err
	}
	//inb by ghy end

	currentEnodeInfos, err := vdposContext.GetSuperNodesFromTrie()
	if err != nil {
		return err
	}
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
	err = vdposContext.SetSuperNodesToTrie(currentEnodeInfos)
	if err != nil {
		return err
	}

	return nil
}

//inb by ghy end

// inb by ssh 190904 begin
func (v *Vdpos) processPredecessorVoter(state *state.StateDB, tx *types.Transaction, txSender common.Address, vdposContext *types.VdposContext) error {
	// process 5 kinds of transactions which relate to voter
	if tx.Value().Cmp(big.NewInt(0)) > 0 {
		if tx.WhichTypes(types.Mortgage) || tx.WhichTypes(types.Regular) || tx.WhichTypes(types.Redeem) {
			v.lock.RLock()
			stake := state.GetStakingValue(txSender)
			v.lock.RUnlock()
			err := vdposContext.UpdateTallysByNewState(txSender, state)
			if err != nil {
				return err
			}
			err = vdposContext.UpdateTallysAndVotesByMPV(txSender, stake)
			if err != nil {
				return err
			}
		}
	}
	if tx.WhichTypes(types.ReceiveLockedAward) {
		v.lock.RLock()
		stake := state.GetStakingValue(txSender)
		v.lock.RUnlock()
		err := vdposContext.UpdateTallysByNewState(txSender, state)
		if err != nil {
			return err
		}
		err = vdposContext.UpdateTallysAndVotesByMPV(txSender, stake)
		if err != nil {
			return err
		}
	}
	if tx.WhichTypes(types.InsteadMortgage) {
		txReceiver := *tx.To()
		v.lock.RLock()
		stake := state.GetStakingValue(txReceiver)
		v.lock.RUnlock()
		err := vdposContext.UpdateTallysByNewState(txReceiver, state)
		if err != nil {
			return err
		}
		err = vdposContext.UpdateTallysAndVotesByMPV(txReceiver, stake)
		if err != nil {
			return err
		}
	}

	return nil
}

// inb by ssh 190904 end

func (v *Vdpos) processEventIssueLightToken(tx *types.Transaction, txSender common.Address, vdposContext *types.VdposContext) error {
	lightTokenJson := new(types.LightTokenJson)
	if err := json.Unmarshal(tx.Data(), lightTokenJson); err != nil {
		return err
	}

	//txDataInfo := string(tx.Data())
	//lightTokenInfo := strings.Split(txDataInfo, "~")
	//if len(lightTokenInfo) < PosEventIssueLightTokenSplitLen {
	//	return errors.Errorf("issue lightToken need 4 parameter")
	//} else {
	//	name := lightTokenInfo[PosEventIssueLightTokenName]
	//	symbol := lightTokenInfo[PosEventIssueLightTokenSymbol]
	//	decimalsStr := lightTokenInfo[PosEventIssueLightTokenDecimals]
	//	decimalsNum, err := strconv.ParseUint(decimalsStr, 10, 64)
	//	if err != nil {
	//		return errors.Errorf("decimals is not uint8")
	//	} else if decimalsNum > 5 {
	//		return errors.Errorf("decimals must from 0~5")
	//	}
	//	decimals := uint8(decimalsNum)
	//	totalSupplyStr := lightTokenInfo[PosEventIssueLightTokenTotalSupply]
	//	totalSupply, ok := new(big.Int).SetString(totalSupplyStr, 10)
	//	if !ok {
	//		return errors.Errorf("unable to convert string to big integer: %v", totalSupplyStr)
	//	}
	txHash := tx.Hash()
	lightTokenAddressBytes := append([]byte{149}, txHash[:19]...)
	lightTokenAddress := common.BytesToAddress(lightTokenAddressBytes)

	// first update lightTokenTrie
	lightToken := &types.LightToken{
		Address:              lightTokenAddress,
		Name:                 lightTokenJson.Name,
		Symbol:               lightTokenJson.Symbol,
		Decimals:             lightTokenJson.Decimals,
		TotalSupply:          lightTokenJson.TotalSupply,
		IssuedAccountAddress: txSender,
		IssuedTxHash:         txHash,
		Owner:                txSender,
		PayForInb:            tx.Value(),
		Type:                 1,
	}
	//lightTokenExist, err := vdposContext.GetLightToken(lightTokenAddress)
	//if lightTokenExist != nil {
	//	if err != nil {
	//		return errors.Errorf("err in vdposContext.GetLightToken()")
	//	} else {
	//		return errors.Errorf("this lightToken has already exist")
	//	}
	//}
	err := vdposContext.UpdateLightToken(lightToken)
	if err != nil {
		return err
	}

	// second update lightTokenAccountTrie
	lightTokenChanges := new(types.LightTokenChanges)
	lightTokenChanges.LTCs = append(lightTokenChanges.LTCs, &types.LightTokenChange{
		AccountAddress:    txSender,
		LightTokenAddress: lightTokenAddress,
		LT:                lightToken,
		ChangeBalance:     lightTokenJson.TotalSupply,
		ChangeType:        types.Add,
	})
	err = vdposContext.UpdateLightTokenAccount(lightTokenChanges)
	if err != nil {
		return err
	}

	return nil
}

func (v *Vdpos) processEventTransferLightToken(txData string, txSender common.Address, txReceiver common.Address, value *big.Int, vdposContext *types.VdposContext) error {
	lightTokenAddress := common.HexToAddress(txData)
	// check up if lightToken exist
	lightTokenExist, err := vdposContext.GetLightToken(lightTokenAddress)
	if lightTokenExist == nil {
		return errors.Errorf("this lightToken do not exist")
	} else {
		if err != nil {
			return errors.Errorf("err in vdposContext.GetLightToken()")
		}
	}

	// check up if balance is enough
	senderBalance, err := vdposContext.GetLightTokenBalanceByAddress(txSender, lightTokenAddress)
	if err != nil {
		return errors.Errorf("err in vdposContext.GetLightTokenBalanceByAddress()")
	} else {
		if senderBalance.Cmp(value) == -1 {
			return errors.Errorf("not enough lightToken balance to transfer")
		} else {
			lightTokenChanges := new(types.LightTokenChanges)
			lightTokenChanges.LTCs = append(lightTokenChanges.LTCs, &types.LightTokenChange{
				AccountAddress:    txSender,
				LightTokenAddress: lightTokenAddress,
				LT:                lightTokenExist,
				ChangeBalance:     value,
				ChangeType:        types.Sub,
			}, &types.LightTokenChange{
				AccountAddress:    txReceiver,
				LightTokenAddress: lightTokenAddress,
				LT:                lightTokenExist,
				ChangeBalance:     value,
				ChangeType:        types.Add,
			})
			err = vdposContext.UpdateLightTokenAccount(lightTokenChanges)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
