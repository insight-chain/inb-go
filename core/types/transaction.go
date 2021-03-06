// Copyright 2014 The go-ethereum Authors
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

package types

import (
	"container/heap"
	"errors"
	"github.com/insight-chain/inb-go/params"
	"io"
	"math/big"
	"sync/atomic"

	"github.com/insight-chain/inb-go/common"
	"github.com/insight-chain/inb-go/common/hexutil"
	"github.com/insight-chain/inb-go/crypto"
	"github.com/insight-chain/inb-go/ethdb"
	"github.com/insight-chain/inb-go/rlp"
)

//go:generate gencodec -type txdata -field-override txdataMarshaling -out gen_tx_json.go

var (
	ErrInvalidSig = errors.New("invalid transaction v, r, s values")
)

type TxType uint8

const (
	_                     TxType = iota
	Ordinary                     //1
	Mortgage                     //2
	Regular                      //3
	Redeem                       //4
	Vote                         //5
	Reset                        //6
	Receive                      //7
	ReceiveLockedAward           //8
	ReceiveVoteAward             //9
	UpdateNodeInformation        //10

	SpecialTx          //11
	Contract           //12
	IssueLightToken    //13
	TransferLightToken //14

	InsteadMortgage //15

	RegularLightToken        //16
	RedeemLightToken         //17
	InsteadRegularLightToken //18
)

// tx type that to not nil
func ValidateTo(txType TxType) bool {
	flag := false
	if txType == Ordinary || txType == SpecialTx || txType == TransferLightToken || txType == InsteadMortgage || txType == InsteadRegularLightToken {
		flag = true
	}
	return flag
}

func ValidateType(txType TxType) bool {
	flag := true
	if txType != Ordinary && txType != Mortgage && txType != Regular && txType != Redeem && txType != Vote && txType != Reset && txType != Receive &&
		txType != ReceiveLockedAward && txType != ReceiveVoteAward && txType != UpdateNodeInformation && txType != SpecialTx && txType != Contract &&
		txType != IssueLightToken && txType != TransferLightToken && txType != InsteadMortgage && txType != RegularLightToken &&
		txType != RedeemLightToken && txType != InsteadRegularLightToken {
		flag = false
	}
	return flag
}

type Transaction struct {
	data txdata
	// caches
	hash atomic.Value
	size atomic.Value
	from atomic.Value
}

type txdata struct {
	AccountNonce uint64 `json:"nonce"    gencodec:"required"`
	//Price        *big.Int        `json:"gasPrice" gencodec:"required"`
	//GasLimit  uint64          `json:"gas"      gencodec:"required"`
	//Net  uint64          `json:"net"      gencodec:"required"`
	Recipient *common.Address `json:"to"       rlp:"nil"` // nil means contract creation
	Amount    *big.Int        `json:"value"    gencodec:"required"`
	Payload   []byte          `json:"input"    gencodec:"required"`

	// Signature values
	V *big.Int `json:"v" gencodec:"required"`
	R *big.Int `json:"r" gencodec:"required"`
	S *big.Int `json:"s" gencodec:"required"`

	// This is only used when marshaling to JSON.
	Hash   *common.Hash `json:"hash" rlp:"-"`
	TxType TxType       `json:"txType" gencodec:"required"`

	ExtraSignature *ExtraSignature `json:"extraSignature" rlp:"nil"`
}

//payment the real account that pay resources for transactions
type ExtraSignature struct {
	//payment address
	ResourcePayer *common.Address `json:"resourcePayer" gencodec:"required"`
	// payment signature values
	Vp *big.Int `json:"vp" gencodec:"required"`
	Rp *big.Int `json:"rp" gencodec:"required"`
	Sp *big.Int `json:"sp" gencodec:"required"`
}

type txdataMarshaling struct {
	AccountNonce hexutil.Uint64
	//Price        *hexutil.Big
	//Net          hexutil.Uint64
	Amount    *hexutil.Big
	Payload   hexutil.Bytes
	V         *hexutil.Big
	R         *hexutil.Big
	S         *hexutil.Big
	TxType    hexutil.Uint64
	Repayment *ExtraSignature
}

func NewTransaction(nonce uint64, to common.Address, amount *big.Int, gasLimit uint64, data []byte, txType TxType) *Transaction {
	return newTransaction(nonce, &to, amount, gasLimit, data, txType, nil)
}

func NewTransaction4Payment(nonce uint64, to common.Address, amount *big.Int, gasLimit uint64, data []byte, txType TxType, payment *common.Address) *Transaction {
	return newTransaction(nonce, &to, amount, gasLimit, data, txType, payment)
}

func NewContractCreation(nonce uint64, amount *big.Int, gasLimit uint64, data []byte) *Transaction {
	return newTransaction(nonce, nil, amount, gasLimit, data, Contract, nil)
}

func NewNilToTransaction(nonce uint64, amount *big.Int, gasLimit uint64, data []byte, txType TxType) *Transaction {
	return newTransaction(nonce, nil, amount, gasLimit, data, txType, nil)
}

func newTransaction(nonce uint64, to *common.Address, amount *big.Int, res uint64, data []byte, txType TxType, resourcePayer *common.Address) *Transaction {
	if len(data) > 0 {
		data = common.CopyBytes(data)
	}
	var rePayment *ExtraSignature
	if nil != resourcePayer {
		rePayment = &ExtraSignature{
			ResourcePayer: resourcePayer,
			Vp:            nil,
			Rp:            nil,
			Sp:            nil,
		}
	}
	d := txdata{
		AccountNonce: nonce,
		Recipient:    to,
		Payload:      data,
		Amount:       new(big.Int),
		//Net:     gasLimit,
		//Price:        new(big.Int),
		V:              new(big.Int),
		R:              new(big.Int),
		S:              new(big.Int),
		TxType:         txType,
		ExtraSignature: rePayment,
	}
	if amount != nil {
		d.Amount.Set(amount)
	}
	//if gasPrice != nil {
	//	d.Price.Set(gasPrice)
	//}

	return &Transaction{data: d}
}

// ChainId returns which chain id this transaction was signed for (if at all)
func (tx *Transaction) ChainId() *big.Int {
	return deriveChainId(tx.data.V)
}

//achilles repayment
// ChainId returns which chain id this transaction was signed for (if at all)
func (tx *Transaction) ChainId4Payment() *big.Int {
	return deriveChainId(tx.data.ExtraSignature.Vp)
}

// Protected returns whether the transaction is protected from replay protection.
func (tx *Transaction) Protected() bool {
	return isProtectedV(tx.data.V)
}

func isProtectedV(V *big.Int) bool {
	if V.BitLen() <= 8 {
		v := V.Uint64()
		return v != 27 && v != 28
	}
	// anything not 27 or 28 is considered protected
	return true
}

// EncodeRLP implements rlp.Encoder
func (tx *Transaction) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, &tx.data)
}

// DecodeRLP implements rlp.Decoder
func (tx *Transaction) DecodeRLP(s *rlp.Stream) error {
	_, size, _ := s.Kind()
	err := s.Decode(&tx.data)
	if err == nil {
		tx.size.Store(common.StorageSize(rlp.ListSize(size)))
	}

	return err
}

// MarshalJSON encodes the web3 RPC transaction format.
func (tx *Transaction) MarshalJSON() ([]byte, error) {
	hash := tx.Hash()
	data := tx.data
	data.Hash = &hash
	return data.MarshalJSON()
}

// UnmarshalJSON decodes the web3 RPC transaction format.
func (tx *Transaction) UnmarshalJSON(input []byte) error {
	var dec txdata
	if err := dec.UnmarshalJSON(input); err != nil {
		return err
	}

	withSignature := dec.V.Sign() != 0 || dec.R.Sign() != 0 || dec.S.Sign() != 0
	if withSignature {
		var V byte
		if isProtectedV(dec.V) {
			chainID := deriveChainId(dec.V).Uint64()
			V = byte(dec.V.Uint64() - 35 - 2*chainID)
		} else {
			V = byte(dec.V.Uint64() - 27)
		}
		if !crypto.ValidateSignatureValues(V, dec.R, dec.S, false) {
			return ErrInvalidSig
		}
	}

	*tx = Transaction{data: dec}
	return nil
}

func (tx *Transaction) Data() []byte { return common.CopyBytes(tx.data.Payload) }
func (tx *Transaction) Gas() uint64  { return 0 }

//func (tx *Transaction) GasPrice() *big.Int { return new(big.Int).Set(tx.data.Price) }
func (tx *Transaction) Value() *big.Int  { return new(big.Int).Set(tx.data.Amount) }
func (tx *Transaction) Nonce() uint64    { return tx.data.AccountNonce }
func (tx *Transaction) CheckNonce() bool { return true }

func (tx *Transaction) ResourcePayer() common.Address {
	var addr common.Address
	if tx.IsRepayment() {
		return *tx.data.ExtraSignature.ResourcePayer
	}
	return addr
}
func (tx *Transaction) Types() TxType                { return tx.data.TxType }
func (tx *Transaction) WhichTypes(types TxType) bool { return tx.data.TxType == types }

func (tx *Transaction) isContract() bool {
	flag := false
	if tx.data.TxType == Contract && tx.data.Recipient == nil {
		flag = true
	}
	return flag
}

func (tx *Transaction) NoNeedUseNet() bool {
	flag := false
	if !(tx.WhichTypes(Mortgage) || tx.WhichTypes(Reset) || tx.WhichTypes(Regular) || tx.WhichTypes(Receive) || tx.WhichTypes(SpecialTx) || tx.WhichTypes(Redeem) || tx.WhichTypes(InsteadMortgage)) {
		flag = true
	}
	return flag
}

func (tx *Transaction) NoNeedUseBalance() bool {
	flag := false
	if !(tx.WhichTypes(Reset) || tx.WhichTypes(Receive) || tx.WhichTypes(TransferLightToken) || tx.WhichTypes(RegularLightToken) || tx.WhichTypes(RedeemLightToken) || tx.WhichTypes(InsteadRegularLightToken)) {
		flag = true
	}
	return flag
}

// To returns the recipient address of the transaction.
// It returns nil if the transaction is a contract creation.
func (tx *Transaction) To() *common.Address {
	if tx.data.Recipient == nil {
		return nil
	}
	to := *tx.data.Recipient
	return &to
}

// vdpos by ssh 190902 begin
// From return the account who send the transaction.
//func (tx *Transaction) From() common.Address {
//	signer := NewEIP155Signer(tx.ChainId())
//	from, _ := Sender(signer, tx)
//	return from
//}

// vdpos by ssh 190902 end

// Hash hashes the RLP encoding of tx.
// It uniquely identifies the transaction.
func (tx *Transaction) Hash() common.Hash {
	if hash := tx.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}
	v := rlpHash(tx)
	tx.hash.Store(v)
	return v
}

// Size returns the true RLP encoded storage size of the transaction, either by
// encoding and returning it, or returning a previsouly cached value.
func (tx *Transaction) Size() common.StorageSize {
	if size := tx.size.Load(); size != nil {
		return size.(common.StorageSize)
	}
	c := writeCounter(0)
	rlp.Encode(&c, &tx.data)
	tx.size.Store(common.StorageSize(c))
	return common.StorageSize(c)
}

// AsMessage returns the transaction as a core.Message.
//
// AsMessage requires a signer to derive the sender.
//
// XXX Rename message to something less arbitrary?
func (tx *Transaction) AsMessage(s Signer) (Message, error) {
	msg := Message{
		nonce: tx.data.AccountNonce,
		//net: tx.data.Net,
		//gasPrice:   new(big.Int).Set(tx.data.Price),
		to:            tx.data.Recipient,
		amount:        tx.data.Amount,
		data:          tx.data.Payload,
		checkNonce:    true,
		types:         tx.data.TxType,
		hash:          tx.Hash(),
		resourcePayer: tx.ResourcePayer(),
	}

	var err error
	msg.from, err = Sender(s, tx)
	return msg, err
}

// WithSignature returns a new transaction with the given signature.
// This signature needs to be formatted as described in the yellow paper (v+27).
func (tx *Transaction) WithSignature(signer Signer, sig []byte) (*Transaction, error) {
	r, s, v, err := signer.SignatureValues(tx, sig)
	if err != nil {
		return nil, err
	}
	cpy := &Transaction{data: tx.data}
	//achilles repayment
	flag := new(big.Int)
	if tx.IsRepayment() && tx.data.V.Cmp(flag) != 0 && tx.data.R.Cmp(flag) != 0 && tx.data.S.Cmp(flag) != 0 {
		cpy.data.ExtraSignature.Rp, cpy.data.ExtraSignature.Sp, cpy.data.ExtraSignature.Vp = r, s, v
		return cpy, nil
	}
	cpy.data.R, cpy.data.S, cpy.data.V = r, s, v
	return cpy, nil
}

// Cost returns amount + gasprice * gaslimit.
//func (tx *Transaction) Cost() *big.Int {
//	total := new(big.Int).Mul(tx.data.Price, new(big.Int).SetUint64(tx.data.GasLimit))
//	total.Add(total, tx.data.Amount)
//	return total
//}
//achilles0710 completed net's cost
func (tx *Transaction) Cost() *big.Int {
	//total := new(big.Int).Mul(tx.data.Price, new(big.Int).SetUint64(tx.data.GasLimit))
	//total.Add(total, tx.data.Amount)
	return tx.data.Amount
}

func (tx *Transaction) RawSignatureValues() (*big.Int, *big.Int, *big.Int) {
	return tx.data.V, tx.data.R, tx.data.S
}

func (tx *Transaction) RawPaymentSignatureValues() (*big.Int, *big.Int, *big.Int) {
	return tx.data.ExtraSignature.Vp, tx.data.ExtraSignature.Rp, tx.data.ExtraSignature.Sp
}

//
func (tx *Transaction) SetPayment() {
	tx.data.ExtraSignature = &ExtraSignature{
		ResourcePayer: nil,
		Vp:            nil,
		Rp:            nil,
		Sp:            nil,
	}
}

//
func (tx *Transaction) RemovePaymentSignatureValues() {
	tx.data.ExtraSignature.Vp = new(big.Int)
	tx.data.ExtraSignature.Rp = new(big.Int)
	tx.data.ExtraSignature.Sp = new(big.Int)
}

//achilles
//  type of transaction is repayment
func (tx *Transaction) IsRepayment() bool {
	if tx.data.ExtraSignature == nil {
		return false
	}
	var resourcePayer common.Address
	if nil == tx.data.ExtraSignature.ResourcePayer || resourcePayer == *tx.data.ExtraSignature.ResourcePayer {
		return false
	}
	return true
}

// Transactions is a Transaction slice type for basic sorting.
type Transactions []*Transaction

// Len returns the length of s.
func (s Transactions) Len() int { return len(s) }

// Swap swaps the i'th and the j'th element in s.
func (s Transactions) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// GetRlp implements Rlpable and returns the i'th element of s in rlp.
func (s Transactions) GetRlp(i int) []byte {
	enc, _ := rlp.EncodeToBytes(s[i])
	return enc
}

// TxDifference returns a new set which is the difference between a and b.
func TxDifference(a, b Transactions) Transactions {
	keep := make(Transactions, 0, len(a))

	remove := make(map[common.Hash]struct{})
	for _, tx := range b {
		remove[tx.Hash()] = struct{}{}
	}

	for _, tx := range a {
		if _, ok := remove[tx.Hash()]; !ok {
			keep = append(keep, tx)
		}
	}

	return keep
}

// TxByNonce implements the sort interface to allow sorting a list of transactions
// by their nonces. This is usually only useful for sorting transactions from a
// single account, otherwise a nonce comparison doesn't make much sense.
type TxByNonce Transactions

func (s TxByNonce) Len() int           { return len(s) }
func (s TxByNonce) Less(i, j int) bool { return s[i].data.AccountNonce < s[j].data.AccountNonce }
func (s TxByNonce) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// TxByPrice implements both the sort and the heap interface, making it useful
// for all at once sorting as well as individually adding and removing elements.
type TxByPrice Transactions

func (s TxByPrice) Len() int { return len(s) }

//achilles190806 remove unused column gasprice todo should return false
func (s TxByPrice) Less(i, j int) bool {
	iRes := intrinsicNet(s[i].Data(), s[j].To() == nil && s[i].Types() == Contract)
	jRes := intrinsicNet(s[j].Data(), s[j].To() == nil && s[j].Types() == Contract)
	return iRes < jRes
}
func (s TxByPrice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s *TxByPrice) Push(x interface{}) {
	*s = append(*s, x.(*Transaction))
}

func (s *TxByPrice) Pop() interface{} {
	old := *s
	n := len(old)
	x := old[n-1]
	*s = old[0 : n-1]
	return x
}

func intrinsicNet(data []byte, contractCreation bool) uint64 {
	if contractCreation {
		return params.TxConfig.NetRatio * (uint64(len(data)) + params.ContractRes)
	}
	return params.TxConfig.NetRatio * (uint64(len(data)) + params.TxRes)
}

// TransactionsByPriceAndNonce represents a set of transactions that can return
// transactions in a profit-maximizing sorted order, while supporting removing
// entire batches of transactions for non-executable accounts.
type TransactionsByPriceAndNonce struct {
	txs    map[common.Address]Transactions // Per account nonce-sorted list of transactions
	heads  TxByPrice                       // Next transaction for each unique account (price heap)
	signer Signer                          // Signer for the set of transactions
}

// NewTransactionsByPriceAndNonce creates a transaction set that can retrieve
// price sorted transactions in a nonce-honouring way.
//
// Note, the input map is reowned so the caller should not interact any more with
// if after providing it to the constructor.
func NewTransactionsByPriceAndNonce(signer Signer, txs map[common.Address]Transactions) *TransactionsByPriceAndNonce {
	// Initialize a price based heap with the head transactions
	heads := make(TxByPrice, 0, len(txs))
	for from, accTxs := range txs {
		heads = append(heads, accTxs[0])
		// Ensure the sender address is from the signer
		acc, _ := Sender(signer, accTxs[0])
		txs[acc] = accTxs[1:]
		if from != acc {
			delete(txs, from)
		}
	}
	heap.Init(&heads)

	// Assemble and return the transaction set
	return &TransactionsByPriceAndNonce{
		txs:    txs,
		heads:  heads,
		signer: signer,
	}
}

// Peek returns the next transaction by price.
func (t *TransactionsByPriceAndNonce) Peek() *Transaction {
	if len(t.heads) == 0 {
		return nil
	}
	return t.heads[0]
}

// Shift replaces the current best head with the next one from the same account.
func (t *TransactionsByPriceAndNonce) Shift() {
	acc, _ := Sender(t.signer, t.heads[0])
	if txs, ok := t.txs[acc]; ok && len(txs) > 0 {
		t.heads[0], t.txs[acc] = txs[0], txs[1:]
		heap.Fix(&t.heads, 0)
	} else {
		heap.Pop(&t.heads)
	}
}

// Pop removes the best transaction, *not* replacing it with the next one from
// the same account. This should be used when a transaction cannot be executed
// and hence all subsequent ones should be discarded from the same account.
func (t *TransactionsByPriceAndNonce) Pop() {
	heap.Pop(&t.heads)
}

// Message is a fully derived transaction and implements core.Message
//
// NOTE: In a future PR this will be removed.
type Message struct {
	to     *common.Address
	from   common.Address
	nonce  uint64
	amount *big.Int
	//gasLimit   uint64
	net uint64
	//gasPrice   *big.Int
	data       []byte
	checkNonce bool
	types      TxType
	receive    *big.Int
	//achilles repayment
	resourcePayer common.Address
	//20190919 added replacement mortgage
	hash common.Hash
}

func NewMessage(from common.Address, to *common.Address, nonce uint64, amount *big.Int, gasLimit uint64, data []byte, checkNonce bool, txType TxType) Message {
	return Message{
		from:   from,
		to:     to,
		nonce:  nonce,
		amount: amount,
		net:    gasLimit,
		//gasPrice:   gasPrice,
		data:       data,
		checkNonce: checkNonce,
		types:      txType,
	}
}

func (m Message) From() common.Address { return m.from }
func (m Message) To() *common.Address  { return m.to }

//func (m Message) GasPrice() *big.Int   { return m.gasPrice }
func (m Message) Value() *big.Int               { return m.amount }
func (m Message) Gas() uint64                   { return m.net }
func (m Message) Nonce() uint64                 { return m.nonce }
func (m Message) Data() []byte                  { return m.data }
func (m Message) CheckNonce() bool              { return m.checkNonce }
func (m Message) Types() TxType                 { return m.types }
func (m Message) Receive() *big.Int             { return m.receive }
func (m Message) WhichTypes(txType TxType) bool { return m.types == txType }

//achilles repayment add apis
func (m Message) ResourcePayer() common.Address { return m.resourcePayer }

//20190919 added replacement mortgage
func (m Message) Hash() common.Hash { return m.hash }
func (m Message) IsRePayment() bool {
	var resourcePayer common.Address
	if resourcePayer != m.resourcePayer {
		return true
	}
	return false
}

//inb by ssh begin
//type ITransaction struct {
//	Id             common.Hash
//	TimeLimit      uint64
//	RefBlockNum    uint64
//	RefBlockPrefix string
//	delayTimeSec   uint64
//	MaxCpuUsage    *big.Int
//	MaxNetUsage    *big.Int
//	Actions        []*action
//	Signatures     []*signature
//	PaySignatures  []*payment
//
//	// caches
//	Hash atomic.Value
//	Size atomic.Value
//	From atomic.Value
//}
//
//type action struct {
//	Name    string
//	Nonce   uint64
//	Account common.Address
//	Data    []byte
//	hexData []byte
//}
//
//type signature struct {
//	V *big.Int
//	R *big.Int
//	S *big.Int
//}
//
//type ITransactions []*ITransaction

// EncodeTransactionStruct change normal Transaction to ITransaction.
//func EncodeTransactionStruct(txs Transactions) ITransactions {
//	rlpTxs := make(ITransactions, 0)
//	for _, tx := range txs {
//		id := tx.Hash()
//
//		data, _ := tx.MarshalJSON()
//		actionx := &action{
//			Name:    "transfer",
//			Nonce:   tx.Nonce(),
//			Account: tx.From(),
//			Data:    data,
//			hexData: []byte{},
//		}
//		actions := []*action{actionx}
//
//		signaturex := &signature{
//			V: tx.data.V,
//			R: tx.data.R,
//			S: tx.data.S,
//		}
//		signatures := []*signature{signaturex}
//
//		var paySignatures []*payment
//		//if tx.data.Repayment != nil {
//		//	paySignature := &payment{
//		//		ResourcePayer: tx.data.Repayment.ResourcePayer,
//		//		Vp:            tx.data.Repayment.Vp,
//		//		Rp:            tx.data.Repayment.Rp,
//		//		Sp:            tx.data.Repayment.Sp,
//		//	}
//		//	paySignatures = append(paySignatures, paySignature)
//		//}
//
//		rlpTx := &ITransaction{
//			Id:             id,
//			TimeLimit:      0,
//			RefBlockNum:    0,
//			RefBlockPrefix: "",
//			delayTimeSec:   0,
//			MaxCpuUsage:    nil,
//			MaxNetUsage:    nil,
//			Actions:        actions,
//			Signatures:     signatures,
//			PaySignatures:  paySignatures,
//		}
//		if hash := tx.hash.Load(); hash != nil {
//			rlpTx.Hash.Store(hash)
//		}
//		if size := tx.size.Load(); size != nil {
//			rlpTx.Size.Store(size)
//		}
//		if from := tx.from.Load(); from != nil {
//			rlpTx.From.Store(from)
//		}
//		rlpTxs = append(rlpTxs, rlpTx)
//	}
//	return rlpTxs
//}

// DecodeTransactionStruct change ITransaction to normal Transaction.
//func DecodeTransactionStruct(encodeTxs ITransactions) Transactions {
//	var dec txdata
//	txs := make(Transactions, 0)
//	for _, encodeTx := range encodeTxs {
//		if len(encodeTx.Actions) == 1 {
//			if err := dec.UnmarshalJSON(encodeTx.Actions[0].Data); err != nil {
//				continue
//			} else {
//				tx := &Transaction{data: dec}
//				if hash := encodeTx.Hash.Load(); hash != nil {
//					tx.hash.Store(hash)
//				}
//				if size := encodeTx.Size.Load(); size != nil {
//					tx.size.Store(size)
//				}
//				if from := encodeTx.From.Load(); from != nil {
//					tx.from.Store(from)
//				}
//				txs = append(txs, tx)
//			}
//		} else {
//			continue
//		}
//	}
//	return txs
//}

//inb by ssh end

//type HeaderExtra struct {
//	LoopStartTime        uint64
//	SignersPool          []common.Address
//	SignerMissing        []common.Address
//	ConfirmedBlockNumber uint64
//	Enodes               []common.SuperNode
//}

//2019.8.29 inb by ghy begin
func ValidateTx(db ethdb.Database, txs Transactions, header, parentHeader *Header, Period uint64) error {
	if len(txs) == 0 {
		return nil
	}

	recipient := header.Coinbase
	if header.Number.Cmp(big.NewInt(1)) == 0 {
		parentHeader = header
	}
	parentRecipient := parentHeader.Coinbase
	specialConsensusAddress := header.GetSpecialConsensus().SpecialConsensusAddress
	//rewardInt, _ := strconv.Atoi(header.Reward)
	//minerReward := big.NewInt(int64(rewardInt))
	blockNumberOneYear := int64(365*86400) / int64(Period)
	minerReward := new(big.Int).Div(new(big.Int).Mul(big.NewInt(1e+8), big.NewInt(1e+5)), big.NewInt(blockNumberOneYear))
	//allianceReward := new(big.Int).Div(new(big.Int).Mul(big.NewInt(1e+8), big.NewInt(1e+5)), big.NewInt(blockNumberOneYear))
	//marketingReward := new(big.Int).Div(new(big.Int).Mul(big.NewInt(1e+8), big.NewInt(1e+5)), big.NewInt(blockNumberOneYear))
	//sealReward := new(big.Int).Div(new(big.Int).Mul(big.NewInt(1e+8), big.NewInt(1e+5)), big.NewInt(blockNumberOneYear))
	//teamReward := new(big.Int).Div(new(big.Int).Mul(big.NewInt(1e+8), big.NewInt(1e+5)), big.NewInt(blockNumberOneYear))


	SpecialConsensus := header.GetSpecialConsensus()
	if len(SpecialConsensus.SpecialConsensusAddress) > 1 {
		for _, v := range SpecialConsensus.SpecialNumber {
			if header.Number.Cmp(v.Number) == 1 {
				minerMul := new(big.Int).Mul(minerReward, SpecialConsensus.Molecule)
				minerReward = new(big.Int).Div(minerMul, SpecialConsensus.Denominator)

				//allianceMul := new(big.Int).Mul(allianceReward, SpecialConsensus.Molecule)
				//allianceReward = new(big.Int).Div(allianceMul, SpecialConsensus.Denominator)
				//
				//marketingMul := new(big.Int).Mul(marketingReward, SpecialConsensus.Molecule)
				//marketingReward = new(big.Int).Div(marketingMul, SpecialConsensus.Denominator)
				//
				//sealMul := new(big.Int).Mul(sealReward, SpecialConsensus.Molecule)
				//sealReward = new(big.Int).Div(sealMul, SpecialConsensus.Denominator)
				//
				//teamMul := new(big.Int).Mul(teamReward, SpecialConsensus.Molecule)
				//teamReward = new(big.Int).Div(teamMul, SpecialConsensus.Denominator)
			}
		}
	}
	type SpecialConsensusInfo struct {
		SpecialType uint
		Address     common.Address
		toAddress   common.Address
		num         int
	}
	specialConsensu := make(map[common.Address]*SpecialConsensusInfo)

	for _, v := range specialConsensusAddress {
		totalConsensus := new(SpecialConsensusInfo)
		totalConsensus.SpecialType = v.SpecialType
		totalConsensus.toAddress = v.ToAddress
		totalConsensus.Address = v.Address
		totalConsensus.num = 1
		specialConsensu[v.Address] = totalConsensus

		//if v.SpecialType == 135 || v.SpecialType == 171 {
		//	specialConsensu[v.ToAddress] = &SpecialConsensusInfo{SpecialType: 2}
		//}
	}
	specialConsensu[common.HexToAddress(common.MortgageAccount)] = &SpecialConsensusInfo{num: 1}

	for _, v := range txs {

		if (v.To() != nil || v.data.Recipient != nil) && (specialConsensu[*v.To()] != nil || specialConsensu[*v.data.Recipient] != nil) {
			if specialConsensu[*v.To()].SpecialType != 2 && specialConsensu[*v.data.Recipient].SpecialType != 2 {
				return errors.New("can not transfer recipient special consensus address")
			}

		}
		info := specialConsensu[common.BytesToAddress(v.Data())]
		if info != nil {
			switch info.SpecialType {
			case 110:

				address, err := getReceiveAddress(db, header)
				if err == nil {
					recipient = address
				}
				parentAddress, err := getReceiveAddress(db, parentHeader)
				if err == nil {
					parentRecipient = parentAddress
				}
				if (*v.data.Recipient != recipient && *v.data.Recipient != parentRecipient) || v.Value().Cmp(minerReward) != 0 {
					return errors.New("MiningReward special tx is not allowed")
				}

				info.num++
			//case 131:
			//	if *v.data.Recipient != info.toAddress || v.Value().Cmp(allianceReward) != 0 {
			//		return errors.New("Foundation special tx is not allowed")
			//	}
			//	info.num++
			//case 133:
			//	if *v.data.Recipient != info.toAddress || v.Value().Cmp(marketingReward) != 0  {
			//		return errors.New("VotingReward special tx is not allowed")
			//	}
			//	info.num++
			//case 135:
			//	if *v.data.Recipient != info.toAddress || v.Value().Cmp(sealReward) != 0 {
			//		return errors.New("team special tx is not allowed")
			//	}
			//	info.num++
			//case 150:
			//	if *v.data.Recipient != info.toAddress || v.Value().Cmp(teamReward) != 0 {
			//		return errors.New("OfflineMarketing special tx is not allowed")
			//	}
			//	info.num++
			default:
				return errors.New("other tx can not allowed")
			}
		}
	}
	for _, v := range specialConsensu {
		if v.num > 2 {
			return errors.New("a block can only have one special tx ")
		}
	}
	return nil
}

//2019.8.29 inb by ghy end
func getReceiveAddress(db ethdb.Database, header *Header) (common.Address, error) {
	//b := header.Extra[32 : len(header.Extra)-65]
	//headerExtra := HeaderExtra{}
	//val := &headerExtra
	//err := rlp.DecodeBytes(b, val)
	//vdposContext, err := NewVdposContextFromProto(db, header.VdposContext)
	vdposContext, err := NewVdposContextFromProtoJustSuperNodes(db, header.VdposContext)
	if err != nil {
		return common.Address{}, err
	}
	superNodes, err := vdposContext.GetSuperNodesFromTrie()
	if err == nil {
		for _, v := range superNodes {
			if v.Address == header.Coinbase && v.RewardAccount != "" {
				address := common.HexToAddress(v.RewardAccount)
				return address, nil
			}
		}
	}
	return common.Address{}, errors.New("err")
}
