// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package ethclient provides a client for the Ethereum RPC API.
package ethclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/insight-chain/inb-go"
	"github.com/insight-chain/inb-go/common"
	"github.com/insight-chain/inb-go/common/hexutil"
	"github.com/insight-chain/inb-go/core/types"
	"github.com/insight-chain/inb-go/rlp"
	"github.com/insight-chain/inb-go/rpc"

	"encoding/hex"
	"github.com/insight-chain/inb-go/core/state"
	"github.com/insight-chain/inb-go/crypto"
	"log"
)

//var SdkRpcTx *RpcTransaction
// Client defines typed wrappers for the Ethereum RPC API.
type Client struct {
	c *rpc.Client
}

//Client received transaction
type SdkTransaction struct {
	Nonce       uint64
	FromAddress common.Address
	ToAddress   common.Address
	Amount      *big.Int
	//	gasLimit uint64
	Data   []byte
	TxType types.TxType
}

// sdk recevieve SdkHeader
type SdkHeader struct {
	ParentHash       common.Hash      `json:"parentHash"       gencodec:"required"`
	UncleHash        common.Hash      `json:"sha3Uncles"       gencodec:"required"`
	Coinbase         common.Address   `json:"miner"            gencodec:"required"`
	Root             common.Hash      `json:"stateRoot"        gencodec:"required"`
	TxHash           common.Hash      `json:"transactionsRoot" gencodec:"required"`
	ReceiptHash      common.Hash      `json:"receiptsRoot"     gencodec:"required"`
	Bloom            types.Bloom      `json:"logsBloom"        gencodec:"required"`
	Difficulty       *hexutil.Big     `json:"difficulty"       gencodec:"required"`
	Number           *hexutil.Big     `json:"number"           gencodec:"required"`
	ResLimit         hexutil.Uint64   `json:"resLimit"         gencodec:"required"`
	ResUsed          hexutil.Uint64   `json:"resUsed"          gencodec:"required"`
	Time             *hexutil.Big     `json:"timestamp"        gencodec:"required"`
	Extra            hexutil.Bytes    `json:"extraData"        gencodec:"required"`
	MixDigest        common.Hash      `json:"mixHash"`
	Nonce            types.BlockNonce `json:"nonce"`
	DataRoot         common.Hash      `json:"dataRoot"`
	Reward           string           `json:"reward"           gencodec:"required"`
	SpecialConsensus []byte           `json:"specialConsensus"  gencodec:"required"`
	//VdposContext     *VdposContextProto `json:"vdposContext"     gencodec:"required"`
	Hash common.Hash `json:"hash"`
}

//SignTransactionResult
type SignTransactionResult struct {
	Raw hexutil.Bytes      `json:"raw"`
	Tx  *types.Transaction `json:"tx"`
}

// Dial connects a client to the given URL.
func Dial(rawurl string) (*Client, error) {
	return DialContext(context.Background(), rawurl)
}

func DialContext(ctx context.Context, rawurl string) (*Client, error) {
	c, err := rpc.DialContext(ctx, rawurl)
	if err != nil {
		return nil, err
	}
	return NewClient(c), nil
}

// NewClient creates a client that uses the given RPC client.
func NewClient(c *rpc.Client) *Client {
	return &Client{c}
}

func (ec *Client) Close() {
	ec.c.Close()
}

// Blockchain Access

// BlockByHash returns the given full block.
//
// Note that loading full blocks requires two requests. Use HeaderByHash
// if you don't need all transactions or uncle headers.
func (ec *Client) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	return ec.getBlock(ctx, "inb_getBlockByHash", hash, true)
}

// BlockByNumber returns a block from the current canonical chain. If number is nil, the
// latest known block is returned.
//
// Note that loading full blocks requires two requests. Use HeaderByNumber
// if you don't need all transactions or uncle headers.
func (ec *Client) BlockByNumber(ctx context.Context, number *big.Int) (*types.Block, error) {
	return ec.getBlock(ctx, "inb_getBlockByNumber", toBlockNumArg(number), true)
}

type rpcBlock struct {
	Hash         common.Hash      `json:"hash"`
	Transactions []RpcTransaction `json:"transactions"`
	UncleHashes  []common.Hash    `json:"uncles"`
}

func (ec *Client) getBlock(ctx context.Context, method string, args ...interface{}) (*types.Block, error) {
	var raw json.RawMessage
	err := ec.c.CallContext(ctx, &raw, method, args...)
	if err != nil {
		return nil, err
	} else if len(raw) == 0 {
		return nil, ethereum.NotFound
	}
	// Decode header and transactions.
	var head *types.Header
	var body rpcBlock
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	// Quick-verify transaction and uncle lists. This mostly helps with debugging the server.
	if head.UncleHash == types.EmptyUncleHash && len(body.UncleHashes) > 0 {
		return nil, fmt.Errorf("server returned non-empty uncle list but block header indicates no uncles")
	}
	if head.UncleHash != types.EmptyUncleHash && len(body.UncleHashes) == 0 {
		return nil, fmt.Errorf("server returned empty uncle list but block header indicates uncles")
	}
	if head.TxHash == types.EmptyRootHash && len(body.Transactions) > 0 {
		return nil, fmt.Errorf("server returned non-empty transaction list but block header indicates no transactions")
	}
	if head.TxHash != types.EmptyRootHash && len(body.Transactions) == 0 {
		return nil, fmt.Errorf("server returned empty transaction list but block header indicates transactions")
	}
	// Load uncles because they are not included in the block response.
	var uncles []*types.Header
	if len(body.UncleHashes) > 0 {
		uncles = make([]*types.Header, len(body.UncleHashes))
		reqs := make([]rpc.BatchElem, len(body.UncleHashes))
		for i := range reqs {
			reqs[i] = rpc.BatchElem{
				Method: "inb_getUncleByBlockHashAndIndex",
				Args:   []interface{}{body.Hash, hexutil.EncodeUint64(uint64(i))},
				Result: &uncles[i],
			}
		}
		if err := ec.c.BatchCallContext(ctx, reqs); err != nil {
			return nil, err
		}
		for i := range reqs {
			if reqs[i].Error != nil {
				return nil, reqs[i].Error
			}
			if uncles[i] == nil {
				return nil, fmt.Errorf("got null header for uncle %d of block %x", i, body.Hash[:])
			}
		}
	}
	// Fill the sender cache of transactions in the block.
	txs := make([]*types.Transaction, len(body.Transactions))
	for i, tx := range body.Transactions {
		if tx.From != nil {
			setSenderFromServer(tx.tx, *tx.From, body.Hash)
		}
		txs[i] = tx.tx
	}
	return types.NewBlockWithHeader(head).WithBody(txs, uncles), nil
}

// HeaderByHash returns the block header with the given hash.
func (ec *Client) HeaderByHash(ctx context.Context, hash common.Hash) (*SdkHeader, error) {
	var head *SdkHeader
	err := ec.c.CallContext(ctx, &head, "inb_getBlockByHash", hash, false)
	if err == nil && head == nil {
		err = ethereum.NotFound
	}
	return head, err
}

// start by cq
//get account balance
/*func (ec *Client) GetBalance(address string) string {
	toAddress := common.HexToAddress(address)
	balance, err := ec.BalanceAt(context.Background(), toAddress, nil)
	if err != nil {
		log.Fatal(err)
	}
	return balance.String()
}*/
func (ec *Client) NewTransaction(chainId *big.Int, nonce uint64, priv string, to string, value *big.Int, data string, txtype types.TxType) (*types.Transaction, error) {
	txdata := []byte(data)
	var tx = new(types.Transaction)
	if common.IsHexAddress(to) {
		toaddr := common.HexToAddress(to)
		tx = types.NewTransaction(nonce, toaddr, value, 0, txdata, txtype)
	} else {
		tx = types.NewNilToTransaction(nonce, value, 0, txdata, txtype)
	}
	key, err := crypto.HexToECDSA(priv)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainId), key)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	return signedTx, nil
}

//special Transaction for receive ReceiveLockedAward
func (ec *Client) NewTransactionForRLA(chainId *big.Int, nonce uint64, priv string, to string, value *big.Int, data []byte, txtype types.TxType) (*types.Transaction, error) {
	//txdata := []byte(data)
	var tx = new(types.Transaction)
	if common.IsHexAddress(to) {
		toaddr := common.HexToAddress(to)
		tx = types.NewTransaction(nonce, toaddr, value, 0, data, txtype)
	} else {
		tx = types.NewNilToTransaction(nonce, value, 0, data, txtype)
	}
	key, err := crypto.HexToECDSA(priv)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainId), key)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	return signedTx, nil
}

//create a raw transaction
func (ec *Client) NewRawTx(chainId *big.Int, nonce uint64, priv, to, resourcePayer string, value *big.Int, data string, txtype types.TxType) (string, error) {
	txdata := []byte(data)
	payment := common.HexToAddress(resourcePayer)
	tx := types.NewTransaction4Payment(nonce, common.HexToAddress(to), value, 0, txdata, txtype, &payment)
	privKey, err := crypto.HexToECDSA(priv)
	if err != nil {
		log.Fatal(err)
		return "", err
	}
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainId), privKey)
	ts := types.Transactions{signedTx}
	rawTxBytes := ts.GetRlp(0)
	rawTx := &types.Transaction{}
	if err := rlp.DecodeBytes(rawTxBytes, rawTx); err != nil {
		return "", err
	}
	rawTxHex := hex.EncodeToString(rawTxBytes)
	//fmt.Println("rawTx_str:", hex.EncodeToString(rawTxBytes))
	return rawTxHex, nil
}

//send signPayTX
func (ec *Client) SignPaymentTx(chainId *big.Int, rawTxHex string, resourcePayerPriv string) (*SignTransactionResult, error) {
	rawTxBytes, err := hex.DecodeString(rawTxHex)
	tx := new(types.Transaction)
	if err := rlp.DecodeBytes(rawTxBytes, tx); err != nil {
		return nil, err
	}
	key, err := crypto.HexToECDSA(resourcePayerPriv)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	//sign for rawTx.......
	payTx, err := types.SignTx(tx, types.NewEIP155Signer(chainId), key)

	if err != nil {
		return nil, err
	}
	returnData, err := rlp.EncodeToBytes(payTx)
	if err != nil {
		return nil, err
	}
	return &SignTransactionResult{returnData, payTx}, nil
}

//send raw Transaction
func (ec *Client) SendRawTx(rawTx string) (string, error) {
	rawTxT := rawTx[2:]
	rawTxBytes, err := hex.DecodeString(rawTxT)
	if err != nil {
		log.Fatal(err)
		return "", err
	}
	tx := new(types.Transaction)
	rlp.DecodeBytes(rawTxBytes, &tx)
	err = ec.SendTransaction(context.Background(), tx)
	if err != nil {
		log.Fatal(err)
		return "", err
	}
	return tx.Hash().Hex(), nil
}

//test rawTx
func (ec *Client) RawTransaction(chainId *big.Int, nonce uint64, priv string, to string, value *big.Int, data string, txtype types.TxType) (*types.Transaction, error) {
	txdata := []byte(data)
	var tx = new(types.Transaction)
	if common.IsHexAddress(to) {
		toaddr := common.HexToAddress(to)
		tx = types.NewTransaction(nonce, toaddr, value, 0, txdata, txtype)
	} else {
		tx = types.NewNilToTransaction(nonce, value, 0, txdata, txtype)
	}
	key, err := crypto.HexToECDSA(priv)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainId), key)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	return signedTx, nil
}

//get account info
func (ec *Client) AccountInfo(ctx context.Context, account common.Address) (*state.Account, error) {
	var accountInfo *state.Account
	err := ec.c.CallContext(ctx, &accountInfo, "inb_getAccountInfo", account)
	if err == nil && accountInfo == nil {
		err = ethereum.NotFound
	}
	return accountInfo, err
}

//send wrapped transaction
func (ec *Client) SdkSendTransaction(tx *types.Transaction) (string, error) {
	err := ec.SendTransaction(context.Background(), tx)
	if err != nil {
		return "", err
	}
	return tx.Hash().Hex(), nil
}

//end by cq

// HeaderByNumber returns a block header from the current canonical chain. If number is
// nil, the latest known header is returned.
func (ec *Client) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	var head *types.Header
	err := ec.c.CallContext(ctx, &head, "inb_getBlockByNumber", toBlockNumArg(number), false)
	if err == nil && head == nil {
		err = ethereum.NotFound
	}
	return head, err
}

/*type SdkRpcTransaction struct {
	tx *types.Transaction
	txExtraInfo
}*/

/*type SdkTxExtraInfo struct {
	BlockNumber *string         `json:"blockNumber,omitempty"`
	BlockHash   *common.Hash    `json:"blockHash,omitempty"`
	From        *common.Address `json:"from,omitempty"`
}*/
type RpcTransaction struct {
	tx *types.Transaction
	txExtraInfo
}

type txExtraInfo struct {
	BlockNumber *string         `json:"blockNumber,omitempty"`
	BlockHash   *common.Hash    `json:"blockHash,omitempty"`
	From        *common.Address `json:"from,omitempty"`
}

func (tx *RpcTransaction) UnmarshalJSON(msg []byte) error {
	if err := json.Unmarshal(msg, &tx.tx); err != nil {
		return err
	}
	return json.Unmarshal(msg, &tx.txExtraInfo)
}

// TransactionByHash returns the transaction with the given hash.
func (ec *Client) TransactionByHash(ctx context.Context, hash common.Hash) (tx *RpcTransaction, isPending bool, err error) {
	var json *RpcTransaction
	err = ec.c.CallContext(ctx, &json, "inb_getTransactionByHash", hash)
	fmt.Println()
	if err != nil {
		return nil, false, err
	} else if json == nil {
		return nil, false, ethereum.NotFound
	} else if _, r, _ := json.tx.RawSignatureValues(); r == nil {
		return nil, false, fmt.Errorf("server returned transaction without signature")
	}
	if json.From != nil && json.BlockHash != nil {
		setSenderFromServer(json.tx, *json.From, *json.BlockHash)
	}
	return json, json.BlockNumber == nil, nil
}

// TransactionSender returns the sender address of the given transaction. The transaction
// must be known to the remote node and included in the blockchain at the given block and
// index. The sender is the one derived by the protocol at the time of inclusion.
//
// There is a fast-path for transactions retrieved by TransactionByHash and
// TransactionInBlock. Getting their sender address can be done without an RPC interaction.
func (ec *Client) TransactionSender(ctx context.Context, tx *types.Transaction, block common.Hash, index uint) (common.Address, error) {
	// Try to load the address from the cache.
	sender, err := types.Sender(&senderFromServer{blockhash: block}, tx)
	if err == nil {
		return sender, nil
	}
	var meta struct {
		Hash common.Hash
		From common.Address
	}
	if err = ec.c.CallContext(ctx, &meta, "inb_getTransactionByBlockHashAndIndex", block, hexutil.Uint64(index)); err != nil {
		return common.Address{}, err
	}
	if meta.Hash == (common.Hash{}) || meta.Hash != tx.Hash() {
		return common.Address{}, errors.New("wrong inclusion block/index")
	}
	return meta.From, nil
}

// TransactionCount returns the total number of transactions in the given block.
func (ec *Client) TransactionCount(ctx context.Context, blockHash common.Hash) (uint, error) {
	var num hexutil.Uint
	err := ec.c.CallContext(ctx, &num, "inb_getBlockTransactionCountByHash", blockHash)
	return uint(num), err
}

// TransactionInBlock returns a single transaction at index in the given block.
func (ec *Client) TransactionInBlock(ctx context.Context, blockHash common.Hash, index uint) (*types.Transaction, error) {
	var json *RpcTransaction
	err := ec.c.CallContext(ctx, &json, "inb_getTransactionByBlockHashAndIndex", blockHash, hexutil.Uint64(index))
	if err == nil {
		if json == nil {
			return nil, ethereum.NotFound
		} else if _, r, _ := json.tx.RawSignatureValues(); r == nil {
			return nil, fmt.Errorf("server returned transaction without signature")
		}
	}
	if json.From != nil && json.BlockHash != nil {
		setSenderFromServer(json.tx, *json.From, *json.BlockHash)
	}
	return json.tx, err
}

// TransactionReceipt returns the receipt of a transaction by transaction hash.
// Note that the receipt is not available for pending transactions.
func (ec *Client) TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
	var r *types.Receipt
	err := ec.c.CallContext(ctx, &r, "inb_getTransactionReceipt", txHash)
	if err == nil {
		if r == nil {
			return nil, ethereum.NotFound
		}
	}
	return r, err
}

func toBlockNumArg(number *big.Int) string {
	if number == nil {
		return "latest"
	}
	return hexutil.EncodeBig(number)
}

type rpcProgress struct {
	StartingBlock hexutil.Uint64
	CurrentBlock  hexutil.Uint64
	HighestBlock  hexutil.Uint64
	PulledStates  hexutil.Uint64
	KnownStates   hexutil.Uint64
}

// SyncProgress retrieves the current progress of the sync algorithm. If there's
// no sync currently running, it returns nil.
func (ec *Client) SyncProgress(ctx context.Context) (*ethereum.SyncProgress, error) {
	var raw json.RawMessage
	if err := ec.c.CallContext(ctx, &raw, "inb_syncing"); err != nil {
		return nil, err
	}
	// Handle the possible response types
	var syncing bool
	if err := json.Unmarshal(raw, &syncing); err == nil {
		return nil, nil // Not syncing (always false)
	}
	var progress *rpcProgress
	if err := json.Unmarshal(raw, &progress); err != nil {
		return nil, err
	}
	return &ethereum.SyncProgress{
		StartingBlock: uint64(progress.StartingBlock),
		CurrentBlock:  uint64(progress.CurrentBlock),
		HighestBlock:  uint64(progress.HighestBlock),
		PulledStates:  uint64(progress.PulledStates),
		KnownStates:   uint64(progress.KnownStates),
	}, nil
}

// SubscribeNewHead subscribes to notifications about the current blockchain head
// on the given channel.
func (ec *Client) SubscribeNewHead(ctx context.Context, ch chan<- *types.Header) (ethereum.Subscription, error) {
	return ec.c.EthSubscribe(ctx, ch, "newHeads")
}

// State Access

// NetworkID returns the network ID (also known as the chain ID) for this chain.
func (ec *Client) NetworkID(ctx context.Context) (*big.Int, error) {
	version := new(big.Int)
	var ver string
	if err := ec.c.CallContext(ctx, &ver, "net_version"); err != nil {
		return nil, err
	}
	if _, ok := version.SetString(ver, 10); !ok {
		return nil, fmt.Errorf("invalid net_version result %q", ver)
	}
	return version, nil
}

// BalanceAt returns the wei balance of the given account.
// The block number can be nil, in which case the balance is taken from the latest known block.
func (ec *Client) BalanceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (*big.Int, error) {
	var result hexutil.Big
	err := ec.c.CallContext(ctx, &result, "inb_getBalance", account, toBlockNumArg(blockNumber))
	return (*big.Int)(&result), err
}

//Resource  by zc
func (ec *Client) NetAt(ctx context.Context, account common.Address, blockNumber *big.Int) (*big.Int, error) {
	var result hexutil.Big
	err := ec.c.CallContext(ctx, &result, "inb_getRes", account, toBlockNumArg(blockNumber))
	return (*big.Int)(&result), err
}

//Resource  by zc
// StorageAt returns the value of key in the contract storage of the given account.
// The block number can be nil, in which case the value is taken from the latest known block.
func (ec *Client) StorageAt(ctx context.Context, account common.Address, key common.Hash, blockNumber *big.Int) ([]byte, error) {
	var result hexutil.Bytes
	err := ec.c.CallContext(ctx, &result, "inb_getStorageAt", account, key, toBlockNumArg(blockNumber))
	return result, err
}

// CodeAt returns the contract code of the given account.
// The block number can be nil, in which case the code is taken from the latest known block.
func (ec *Client) CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error) {
	var result hexutil.Bytes
	err := ec.c.CallContext(ctx, &result, "inb_getCode", account, toBlockNumArg(blockNumber))
	return result, err
}

// NonceAt returns the account nonce of the given account.
// The block number can be nil, in which case the nonce is taken from the latest known block.
func (ec *Client) NonceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (uint64, error) {
	var result hexutil.Uint64
	err := ec.c.CallContext(ctx, &result, "inb_getTransactionCount", account, toBlockNumArg(blockNumber))
	return uint64(result), err
}

// Filters

// FilterLogs executes a filter query.
func (ec *Client) FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	var result []types.Log
	arg, err := toFilterArg(q)
	if err != nil {
		return nil, err
	}
	err = ec.c.CallContext(ctx, &result, "inb_getLogs", arg)
	return result, err
}

// SubscribeFilterLogs subscribes to the results of a streaming filter query.
func (ec *Client) SubscribeFilterLogs(ctx context.Context, q ethereum.FilterQuery, ch chan<- types.Log) (ethereum.Subscription, error) {
	arg, err := toFilterArg(q)
	if err != nil {
		return nil, err
	}
	return ec.c.EthSubscribe(ctx, ch, "logs", arg)
}

func toFilterArg(q ethereum.FilterQuery) (interface{}, error) {
	arg := map[string]interface{}{
		"address": q.Addresses,
		"topics":  q.Topics,
	}
	if q.BlockHash != nil {
		arg["blockHash"] = *q.BlockHash
		if q.FromBlock != nil || q.ToBlock != nil {
			return nil, fmt.Errorf("cannot specify both BlockHash and FromBlock/ToBlock")
		}
	} else {
		if q.FromBlock == nil {
			arg["fromBlock"] = "0x0"
		} else {
			arg["fromBlock"] = toBlockNumArg(q.FromBlock)
		}
		arg["toBlock"] = toBlockNumArg(q.ToBlock)
	}
	return arg, nil
}

// Pending State

// PendingBalanceAt returns the wei balance of the given account in the pending state.
func (ec *Client) PendingBalanceAt(ctx context.Context, account common.Address) (*big.Int, error) {
	var result hexutil.Big
	err := ec.c.CallContext(ctx, &result, "inb_getBalance", account, "pending")
	return (*big.Int)(&result), err
}

//Resource by zc
//func (ec *Client) PendingCpuAt(ctx context.Context, account common.Address) (*big.Int, error) {
//	var result hexutil.Big
//	err := ec.c.CallContext(ctx, &result, "inb_getCpu", account, "pending")
//	return (*big.Int)(&result), err
//}
func (ec *Client) PendingNetAt(ctx context.Context, account common.Address) (*big.Int, error) {
	var result hexutil.Big
	err := ec.c.CallContext(ctx, &result, "inb_getRes", account, "pending")
	return (*big.Int)(&result), err
}

//Resource by zc
// PendingStorageAt returns the value of key in the contract storage of the given account in the pending state.
func (ec *Client) PendingStorageAt(ctx context.Context, account common.Address, key common.Hash) ([]byte, error) {
	var result hexutil.Bytes
	err := ec.c.CallContext(ctx, &result, "inb_getStorageAt", account, key, "pending")
	return result, err
}

// PendingCodeAt returns the contract code of the given account in the pending state.
func (ec *Client) PendingCodeAt(ctx context.Context, account common.Address) ([]byte, error) {
	var result hexutil.Bytes
	err := ec.c.CallContext(ctx, &result, "inb_getCode", account, "pending")
	return result, err
}

// PendingNonceAt returns the account nonce of the given account in the pending state.
// This is the nonce that should be used for the next transaction.
func (ec *Client) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	var result hexutil.Uint64
	err := ec.c.CallContext(ctx, &result, "inb_getTransactionCount", account, "pending")
	return uint64(result), err
}

// PendingTransactionCount returns the total number of transactions in the pending state.
func (ec *Client) PendingTransactionCount(ctx context.Context) (uint, error) {
	var num hexutil.Uint
	err := ec.c.CallContext(ctx, &num, "inb_getBlockTransactionCountByNumber", "pending")
	return uint(num), err
}

// TODO: SubscribePendingTransactions (needs server side)

// Contract Calling

// CallContract executes a message call transaction, which is directly executed in the VM
// of the node, but never mined into the blockchain.
//
// blockNumber selects the block height at which the call runs. It can be nil, in which
// case the code is taken from the latest known block. Note that state from very old
// blocks might not be available.
func (ec *Client) CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	var hex hexutil.Bytes
	err := ec.c.CallContext(ctx, &hex, "inb_call", toCallArg(msg), toBlockNumArg(blockNumber))
	if err != nil {
		return nil, err
	}
	return hex, nil
}

// PendingCallContract executes a message call transaction using the EVM.
// The state seen by the contract call is the pending state.
func (ec *Client) PendingCallContract(ctx context.Context, msg ethereum.CallMsg) ([]byte, error) {
	var hex hexutil.Bytes
	err := ec.c.CallContext(ctx, &hex, "inb_call", toCallArg(msg), "pending")
	if err != nil {
		return nil, err
	}
	return hex, nil
}

// SuggestGasPrice retrieves the currently suggested gas price to allow a timely
// execution of a transaction.
func (ec *Client) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	var hex hexutil.Big
	if err := ec.c.CallContext(ctx, &hex, "inb_gasPrice"); err != nil {
		return nil, err
	}
	return (*big.Int)(&hex), nil
}

// EstimateGas tries to estimate the gas needed to execute a specific transaction based on
// the current pending state of the backend blockchain. There is no guarantee that this is
// the true gas limit requirement as other transactions may be added or removed by miners,
// but it should provide a basis for setting a reasonable default.
func (ec *Client) EstimateGas(ctx context.Context, msg ethereum.CallMsg) (uint64, error) {
	var hex hexutil.Uint64
	err := ec.c.CallContext(ctx, &hex, "inb_estimateGas", toCallArg(msg))
	if err != nil {
		return 0, err
	}
	return uint64(hex), nil
}

// SendTransaction injects a signed transaction into the pending pool for execution.
//
// If the transaction was a contract creation use the TransactionReceipt method to get the
// contract address after the transaction has been mined.
func (ec *Client) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	data, err := rlp.EncodeToBytes(tx)
	if err != nil {
		return err
	}
	return ec.c.CallContext(ctx, nil, "inb_sendRawTransaction", common.ToHex(data))
}

func toCallArg(msg ethereum.CallMsg) interface{} {
	arg := map[string]interface{}{
		"from": msg.From,
		"to":   msg.To,
	}
	if len(msg.Data) > 0 {
		arg["data"] = hexutil.Bytes(msg.Data)
	}
	if msg.Value != nil {
		arg["value"] = (*hexutil.Big)(msg.Value)
	}
	if msg.Net != 0 {
		arg["net"] = hexutil.Uint64(msg.Net)
	}
	//if msg.GasPrice != nil {
	//	arg["gasPrice"] = (*hexutil.Big)(msg.GasPrice)
	//}
	return arg
}
