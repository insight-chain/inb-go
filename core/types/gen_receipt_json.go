// Code generated by github.com/fjl/gencodec. DO NOT EDIT.

package types

import (
	"encoding/json"
	"errors"
	"github.com/insight-chain/inb-go/common"
	"github.com/insight-chain/inb-go/common/hexutil"
	"math/big"
)

var _ = (*receiptMarshaling)(nil)

// MarshalJSON marshals as JSON.
func (r Receipt) MarshalJSON() ([]byte, error) {
	type Receipt struct {
		PostState         hexutil.Bytes  `json:"root"`
		Status            hexutil.Uint64 `json:"status"`
		CumulativeResUsed hexutil.Uint64 `json:"cumulativeResUsed" gencodec:"required"`
		Bloom             Bloom          `json:"logsBloom"         gencodec:"required"`
		Logs              []*Log         `json:"logs"              gencodec:"required"`
		TxHash            common.Hash    `json:"transactionHash" gencodec:"required"`
		ContractAddress   common.Address `json:"contractAddress"`
		IncomeClaimed     *big.Int       `json:"incomeClaimed" gencodec:"required"` //2019.8.1 inb by ghy
		ResUsed           hexutil.Uint64 `json:"resUsed" gencodec:"required"`
	}
	var enc Receipt
	enc.PostState = r.PostState
	enc.Status = hexutil.Uint64(r.Status)
	enc.CumulativeResUsed = hexutil.Uint64(r.CumulativeResUsed)
	enc.Bloom = r.Bloom
	enc.Logs = r.Logs
	enc.TxHash = r.TxHash
	enc.ContractAddress = r.ContractAddress
	enc.IncomeClaimed = r.IncomeClaimed //2019.8.1 inb by ghy
	enc.ResUsed = hexutil.Uint64(r.ResUsed)

	return json.Marshal(&enc)
}

// UnmarshalJSON unmarshals from JSON.
func (r *Receipt) UnmarshalJSON(input []byte) error {
	type Receipt struct {
		PostState         *hexutil.Bytes  `json:"root"`
		Status            *hexutil.Uint64 `json:"status"`
		CumulativeResUsed *hexutil.Uint64 `json:"cumulativeResUsed" gencodec:"required"`
		Bloom             *Bloom          `json:"logsBloom"         gencodec:"required"`
		Logs              []*Log          `json:"logs"              gencodec:"required"`
		TxHash            *common.Hash    `json:"transactionHash" gencodec:"required"`
		ContractAddress   *common.Address `json:"contractAddress"`
		IncomeClaimed     *big.Int        `json:"incomeClaimed" gencodec:"required"` //2019.8.1 inb by ghy
		ResUsed           *hexutil.Uint64 `json:"resUsed" gencodec:"required"`
	}
	var dec Receipt
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.PostState != nil {
		r.PostState = *dec.PostState
	}
	if dec.Status != nil {
		r.Status = uint64(*dec.Status)
	}
	if dec.CumulativeResUsed == nil {
		return errors.New("missing required field 'cumulativeResUsed' for Receipt")
	}
	r.CumulativeResUsed = uint64(*dec.CumulativeResUsed)
	if dec.Bloom == nil {
		return errors.New("missing required field 'logsBloom' for Receipt")
	}
	r.Bloom = *dec.Bloom
	if dec.Logs == nil {
		return errors.New("missing required field 'logs' for Receipt")
	}
	r.Logs = dec.Logs
	if dec.TxHash == nil {
		return errors.New("missing required field 'transactionHash' for Receipt")
	}
	r.TxHash = *dec.TxHash
	if dec.ContractAddress != nil {
		r.ContractAddress = *dec.ContractAddress
	}
	if dec.ResUsed == nil {
		return errors.New("missing required field 'resUsed' for Receipt")
	}
	r.ResUsed = uint64(*dec.ResUsed)
	if dec.IncomeClaimed == nil {
		return errors.New("missing required field 'incomeClaimed' for Receipt")
	}
	r.IncomeClaimed = dec.IncomeClaimed //2019.8.1 inb by ghy

	return nil
}
