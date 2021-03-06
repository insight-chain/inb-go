// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software MiningReward, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/insight-chain/inb-go/consensus/vdpos"
	"github.com/insight-chain/inb-go/core/vm"
	"github.com/insight-chain/inb-go/crypto"
	"math"
	"math/big"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/insight-chain/inb-go/common"
	"github.com/insight-chain/inb-go/common/prque"
	"github.com/insight-chain/inb-go/core/state"
	"github.com/insight-chain/inb-go/core/types"
	"github.com/insight-chain/inb-go/event"
	"github.com/insight-chain/inb-go/log"
	"github.com/insight-chain/inb-go/metrics"
	"github.com/insight-chain/inb-go/params"
)

const (
	// chainHeadChanSize is the size of channel listening to ChainHeadEvent.
	chainHeadChanSize = 10
	//inb by ghy begin
	ResponseRate = float64(0.01)
	CycleTimes   = uint64(12)
	//inb by ghy end
)

var (
	// ErrInvalidSender is returned if the transaction contains an invalid signature.
	ErrInvalidSender = errors.New("invalid sender")

	// ErrNonceTooLow is returned if the nonce of a transaction is lower than the
	// one present in the local chain.
	ErrNonceTooLow = errors.New("nonce too low")

	// ErrUnderpriced is returned if a transaction's gas price is below the minimum
	// configured for the transaction pool.
	ErrUnderpriced = errors.New("transaction underpriced")

	// ErrReplaceUnderpriced is returned if a transaction is attempted to be replaced
	// with a different one without the required price bump.
	ErrReplaceUnderpriced = errors.New("replacement transaction underpriced")

	// ErrInsufficientFunds is returned if the total cost of executing a transaction
	// is higher than the balance of the user's account.
	ErrInsufficientFunds = errors.New("insufficient funds for value")

	// ErrIntrinsicGas is returned if the transaction is specified to use less gas
	// than required to start the invocation.
	ErrIntrinsicGas = errors.New("intrinsic gas too low")

	// ErrGasLimit is returned if a transaction's requested gas limit exceeds the
	// maximum allowance of the current block.
	ErrGasLimit = errors.New("exceeds block gas limit")

	// ErrNegativeValue is a sanity error to ensure noone is able to specify a
	// transaction with a negative value.
	ErrNegativeValue = errors.New("negative value")

	// ErrOversizedData is returned if the input data of a transaction is greater
	// than some meaningful limit a user might use. This is not a consensus error
	// making the transaction invalid, rather a DOS protection.
	ErrOversizedData = errors.New("oversized data")
	//Resource by zc
	ErrOverResValue    = errors.New("not enough res")
	ErrBeforeResetTime = errors.New("before reset time")
	ErrParameterError  = errors.New("parameter error")

	//achilles0718 regular mortgagtion
	ErrCountLimit     = errors.New("exceeds time limited staking count limit")
	ErrInvalidAddress = errors.New("invalid address without right prefix")
	ErrTxType         = errors.New("invalid transaction type")
)

var (
	evictionInterval    = time.Minute     // Time interval to check for evictable transactions
	statsReportInterval = 8 * time.Second // Time interval to report transaction pool stats
)

var (
	// Metrics for the pending pool
	pendingDiscardCounter   = metrics.NewRegisteredCounter("txpool/pending/discard", nil)
	pendingReplaceCounter   = metrics.NewRegisteredCounter("txpool/pending/replace", nil)
	pendingRateLimitCounter = metrics.NewRegisteredCounter("txpool/pending/ratelimit", nil) // Dropped due to rate limiting
	pendingNofundsCounter   = metrics.NewRegisteredCounter("txpool/pending/nofunds", nil)   // Dropped due to out-of-funds

	// Metrics for the queued pool
	queuedDiscardCounter   = metrics.NewRegisteredCounter("txpool/queued/discard", nil)
	queuedReplaceCounter   = metrics.NewRegisteredCounter("txpool/queued/replace", nil)
	queuedRateLimitCounter = metrics.NewRegisteredCounter("txpool/queued/ratelimit", nil) // Dropped due to rate limiting
	queuedNofundsCounter   = metrics.NewRegisteredCounter("txpool/queued/nofunds", nil)   // Dropped due to out-of-funds

	// General tx metrics
	invalidTxCounter     = metrics.NewRegisteredCounter("txpool/invalid", nil)
	underpricedTxCounter = metrics.NewRegisteredCounter("txpool/underpriced", nil)
)

// TxStatus is the current status of a transaction as seen by the pool.
type TxStatus uint

const (
	TxStatusUnknown TxStatus = iota
	TxStatusQueued
	TxStatusPending
	TxStatusIncluded
)

// blockChain provides the state of blockchain and current gas limit to do
// some pre checks in tx pool and event subscribers.
type blockChain interface {
	CurrentBlock() *types.Block
	GetBlock(hash common.Hash, number uint64) *types.Block
	StateAt(root common.Hash) (*state.StateDB, error)

	SubscribeChainHeadEvent(ch chan<- ChainHeadEvent) event.Subscription
}

// TxPoolConfig are the configuration parameters of the transaction pool.
type TxPoolConfig struct {
	Locals    []common.Address // Addresses that should be treated by default as local
	NoLocals  bool             // Whether local transaction handling should be disabled
	Journal   string           // Journal of local transactions to survive node restarts
	Rejournal time.Duration    // Time interval to regenerate the local transaction journal

	PriceLimit uint64 // Minimum gas price to enforce for acceptance into the pool
	PriceBump  uint64 // Minimum price bump percentage to replace an already existing transaction (nonce)

	AccountSlots uint64 // Number of executable transaction slots guaranteed per account
	GlobalSlots  uint64 // Maximum number of executable transaction slots for all accounts
	AccountQueue uint64 // Maximum number of non-executable transaction slots permitted per account
	GlobalQueue  uint64 // Maximum number of non-executable transaction slots for all accounts

	Lifetime time.Duration // Maximum amount of time non-executable transaction are queued
}

// DefaultTxPoolConfig contains the default configurations for the transaction
// pool.
var DefaultTxPoolConfig = TxPoolConfig{
	Journal:   "transactions.rlp",
	Rejournal: time.Hour,

	PriceLimit: 1,
	PriceBump:  10,

	AccountSlots: 16,
	GlobalSlots:  4096,
	AccountQueue: 64,
	GlobalQueue:  1024,

	Lifetime: 3 * time.Hour,
}

// sanitize checks the provided user configurations and changes anything that's
// unreasonable or unworkable.
func (config *TxPoolConfig) sanitize() TxPoolConfig {
	conf := *config
	if conf.Rejournal < time.Second {
		log.Warn("Sanitizing invalid txpool journal time", "provided", conf.Rejournal, "updated", time.Second)
		conf.Rejournal = time.Second
	}
	if conf.PriceLimit < 1 {
		log.Warn("Sanitizing invalid txpool price limit", "provided", conf.PriceLimit, "updated", DefaultTxPoolConfig.PriceLimit)
		conf.PriceLimit = DefaultTxPoolConfig.PriceLimit
	}
	if conf.PriceBump < 1 {
		log.Warn("Sanitizing invalid txpool price bump", "provided", conf.PriceBump, "updated", DefaultTxPoolConfig.PriceBump)
		conf.PriceBump = DefaultTxPoolConfig.PriceBump
	}
	return conf
}

// TxPool contains all currently known transactions. Transactions
// enter the pool when they are received from the network or submitted
// locally. They exit the pool when they are included in the blockchain.
//
// The pool separates processable transactions (which can be applied to the
// current state) and future transactions. Transactions move between those
// two states over time as they are received and processed.
type TxPool struct {
	config       TxPoolConfig
	chainconfig  *params.ChainConfig
	chain        blockChain
	gasPrice     *big.Int
	txFeed       event.Feed
	scope        event.SubscriptionScope
	chainHeadCh  chan ChainHeadEvent
	chainHeadSub event.Subscription
	signer       types.Signer
	mu           sync.RWMutex

	currentState  *state.StateDB      // Current state in the blockchain head
	pendingState  *state.ManagedState // Pending state tracking virtual nonces
	currentMaxGas uint64              // Current gas limit for transaction caps

	locals  *accountSet // Set of local transaction to exempt from eviction rules
	journal *txJournal  // Journal of local transaction to back up to disk

	pending map[common.Address]*txList   // All currently processable transactions
	queue   map[common.Address]*txList   // Queued but non-processable transactions
	beats   map[common.Address]time.Time // Last heartbeat from each known account
	all     *txLookup                    // All transactions to allow lookups
	priced  *txPricedList                // All transactions sorted by price

	wg sync.WaitGroup // for shutdown sync

	homestead bool
}

// NewTxPool creates a new transaction pool to gather, sort and filter inbound
// transactions from the network.
func NewTxPool(config TxPoolConfig, chainconfig *params.ChainConfig, chain blockChain) *TxPool {
	// Sanitize the input to ensure no vulnerable gas prices are set
	config = (&config).sanitize()

	// Create the transaction pool with its initial settings
	pool := &TxPool{
		config:      config,
		chainconfig: chainconfig,
		chain:       chain,
		signer:      types.NewEIP155Signer(chainconfig.ChainID),
		pending:     make(map[common.Address]*txList),
		queue:       make(map[common.Address]*txList),
		beats:       make(map[common.Address]time.Time),
		all:         newTxLookup(),
		chainHeadCh: make(chan ChainHeadEvent, chainHeadChanSize),
		gasPrice:    new(big.Int).SetUint64(config.PriceLimit),
	}
	pool.locals = newAccountSet(pool.signer)
	for _, addr := range config.Locals {
		log.Info("Setting new local account", "address", addr)
		pool.locals.add(addr)
	}
	pool.priced = newTxPricedList(pool.all)
	pool.reset(nil, chain.CurrentBlock().Header())

	// If local transactions and journaling is enabled, load from disk
	if !config.NoLocals && config.Journal != "" {
		pool.journal = newTxJournal(config.Journal)

		if err := pool.journal.load(pool.AddLocals); err != nil {
			log.Warn("Failed to load transaction journal", "err", err)
		}
		if err := pool.journal.rotate(pool.local()); err != nil {
			log.Warn("Failed to rotate transaction journal", "err", err)
		}
	}
	// Subscribe events from blockchain
	pool.chainHeadSub = pool.chain.SubscribeChainHeadEvent(pool.chainHeadCh)

	// Start the event loop and return
	pool.wg.Add(1)
	go pool.loop()

	return pool
}

// loop is the transaction pool's main event loop, waiting for and reacting to
// outside blockchain events as well as for various reporting and transaction
// eviction events.
func (pool *TxPool) loop() {
	defer pool.wg.Done()

	// Start the stats reporting and transaction eviction tickers
	var prevPending, prevQueued, prevStales int

	report := time.NewTicker(statsReportInterval)
	defer report.Stop()

	evict := time.NewTicker(evictionInterval)
	defer evict.Stop()

	journal := time.NewTicker(pool.config.Rejournal)
	defer journal.Stop()

	// Track the previous head headers for transaction reorgs
	head := pool.chain.CurrentBlock()

	// Keep waiting for and reacting to the various events
	for {
		select {
		// Handle ChainHeadEvent
		case ev := <-pool.chainHeadCh:
			if ev.Block != nil {
				pool.mu.Lock()
				if pool.chainconfig.IsHomestead(ev.Block.Number()) {
					pool.homestead = true
				}
				pool.reset(head.Header(), ev.Block.Header())
				head = ev.Block

				pool.mu.Unlock()
			}
		// Be unsubscribed due to system stopped
		case <-pool.chainHeadSub.Err():
			return

		// Handle stats reporting ticks
		case <-report.C:
			pool.mu.RLock()
			pending, queued := pool.stats()
			stales := pool.priced.stales
			pool.mu.RUnlock()

			if pending != prevPending || queued != prevQueued || stales != prevStales {
				log.Debug("Transaction pool status report", "executable", pending, "queued", queued, "stales", stales)
				prevPending, prevQueued, prevStales = pending, queued, stales
			}

		// Handle inactive account transaction eviction
		case <-evict.C:
			pool.mu.Lock()
			for addr := range pool.queue {
				// Skip local transactions from the eviction mechanism
				if pool.locals.contains(addr) {
					continue
				}
				// Any non-locals old enough should be removed
				if time.Since(pool.beats[addr]) > pool.config.Lifetime {
					for _, tx := range pool.queue[addr].Flatten() {
						pool.removeTx(tx.Hash(), true)
					}
				}
			}
			pool.mu.Unlock()

		// Handle local transaction journal rotation
		case <-journal.C:
			if pool.journal != nil {
				pool.mu.Lock()
				if err := pool.journal.rotate(pool.local()); err != nil {
					log.Warn("Failed to rotate local tx journal", "err", err)
				}
				pool.mu.Unlock()
			}
		}
	}
}

// lockedReset is a wrapper around reset to allow calling it in a thread safe
// manner. This method is only ever used in the tester!
func (pool *TxPool) lockedReset(oldHead, newHead *types.Header) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pool.reset(oldHead, newHead)
}

// reset retrieves the current state of the blockchain and ensures the content
// of the transaction pool is valid with regard to the chain state.
func (pool *TxPool) reset(oldHead, newHead *types.Header) {
	// If we're reorging an old state, reinject all dropped transactions
	var reinject types.Transactions

	if oldHead != nil && oldHead.Hash() != newHead.ParentHash {
		// If the reorg is too deep, avoid doing it (will happen during fast sync)
		oldNum := oldHead.Number.Uint64()
		newNum := newHead.Number.Uint64()

		if depth := uint64(math.Abs(float64(oldNum) - float64(newNum))); depth > 64 {
			log.Debug("Skipping deep transaction reorg", "depth", depth)
		} else {
			// Reorg seems shallow enough to pull in all transactions into memory
			var discarded, included types.Transactions

			var (
				rem = pool.chain.GetBlock(oldHead.Hash(), oldHead.Number.Uint64())
				add = pool.chain.GetBlock(newHead.Hash(), newHead.Number.Uint64())
			)
			for rem.NumberU64() > add.NumberU64() {
				discarded = append(discarded, rem.Transactions()...)
				if rem = pool.chain.GetBlock(rem.ParentHash(), rem.NumberU64()-1); rem == nil {
					log.Error("Unrooted old chain seen by tx pool", "block", oldHead.Number, "hash", oldHead.Hash())
					return
				}
			}
			for add.NumberU64() > rem.NumberU64() {
				included = append(included, add.Transactions()...)
				if add = pool.chain.GetBlock(add.ParentHash(), add.NumberU64()-1); add == nil {
					log.Error("Unrooted new chain seen by tx pool", "block", newHead.Number, "hash", newHead.Hash())
					return
				}
			}
			for rem.Hash() != add.Hash() {
				discarded = append(discarded, rem.Transactions()...)
				if rem = pool.chain.GetBlock(rem.ParentHash(), rem.NumberU64()-1); rem == nil {
					log.Error("Unrooted old chain seen by tx pool", "block", oldHead.Number, "hash", oldHead.Hash())
					return
				}
				included = append(included, add.Transactions()...)
				if add = pool.chain.GetBlock(add.ParentHash(), add.NumberU64()-1); add == nil {
					log.Error("Unrooted new chain seen by tx pool", "block", newHead.Number, "hash", newHead.Hash())
					return
				}
			}
			reinject = types.TxDifference(discarded, included)
		}
	}
	// Initialize the internal state to the current head
	if newHead == nil {
		newHead = pool.chain.CurrentBlock().Header() // Special case during testing
	}
	statedb, err := pool.chain.StateAt(newHead.Root)
	if err != nil {
		log.Error("Failed to reset txpool state", "err", err)
		return
	}
	pool.currentState = statedb
	pool.pendingState = state.ManageState(statedb)
	pool.currentMaxGas = newHead.ResLimit

	// Inject any transactions discarded due to reorgs
	log.Debug("Reinjecting stale transactions", "count", len(reinject))
	senderCacher.recover(pool.signer, reinject)
	pool.addTxsLocked(reinject, false)

	// validate the pool of pending transactions, this will remove
	// any transactions that have been included in the block or
	// have been invalidated because of another transaction (e.g.
	// higher gas price)
	pool.demoteUnexecutables()

	// Update all accounts to the latest known pending nonce
	for addr, list := range pool.pending {
		txs := list.Flatten() // Heavy but will be cached and is needed by the miner anyway
		pool.pendingState.SetNonce(addr, txs[len(txs)-1].Nonce()+1)
	}
	// Check the queue and move transactions over to the pending if possible
	// or remove those that have become invalid
	pool.promoteExecutables(nil)
}

// Stop terminates the transaction pool.
func (pool *TxPool) Stop() {
	// Unsubscribe all subscriptions registered from txpool
	pool.scope.Close()

	// Unsubscribe subscriptions registered from blockchain
	pool.chainHeadSub.Unsubscribe()
	pool.wg.Wait()

	if pool.journal != nil {
		pool.journal.close()
	}
	log.Info("Transaction pool stopped")
}

// SubscribeNewTxsEvent registers a subscription of NewTxsEvent and
// starts sending event to the given channel.
func (pool *TxPool) SubscribeNewTxsEvent(ch chan<- NewTxsEvent) event.Subscription {
	return pool.scope.Track(pool.txFeed.Subscribe(ch))
}

// GasPrice returns the current gas price enforced by the transaction pool.
func (pool *TxPool) GasPrice() *big.Int {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	return new(big.Int).Set(pool.gasPrice)
}

// SetGasPrice updates the minimum price required by the transaction pool for a
// new transaction, and drops all transactions below this threshold.
func (pool *TxPool) SetGasPrice(price *big.Int) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pool.gasPrice = price
	for _, tx := range pool.priced.Cap(price, pool.locals) {
		pool.removeTx(tx.Hash(), false)
	}
	log.Info("Transaction pool price threshold updated", "price", price)
}

// State returns the virtual managed state of the transaction pool.
func (pool *TxPool) State() *state.ManagedState {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	return pool.pendingState
}

// Stats retrieves the current pool stats, namely the number of pending and the
// number of queued (non-executable) transactions.
func (pool *TxPool) Stats() (int, int) {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	return pool.stats()
}

// stats retrieves the current pool stats, namely the number of pending and the
// number of queued (non-executable) transactions.
func (pool *TxPool) stats() (int, int) {
	pending := 0
	for _, list := range pool.pending {
		pending += list.Len()
	}
	queued := 0
	for _, list := range pool.queue {
		queued += list.Len()
	}
	return pending, queued
}

// Content retrieves the data content of the transaction pool, returning all the
// pending as well as queued transactions, grouped by account and sorted by nonce.
func (pool *TxPool) Content() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pending := make(map[common.Address]types.Transactions)
	for addr, list := range pool.pending {
		pending[addr] = list.Flatten()
	}
	queued := make(map[common.Address]types.Transactions)
	for addr, list := range pool.queue {
		queued[addr] = list.Flatten()
	}
	return pending, queued
}

// Pending retrieves all currently processable transactions, grouped by origin
// account and sorted by nonce. The returned transaction set is a copy and can be
// freely modified by calling code.
func (pool *TxPool) Pending() (map[common.Address]types.Transactions, error) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pending := make(map[common.Address]types.Transactions)
	for addr, list := range pool.pending {
		pending[addr] = list.Flatten()
	}
	return pending, nil
}

// Locals retrieves the accounts currently considered local by the pool.
func (pool *TxPool) Locals() []common.Address {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	return pool.locals.flatten()
}

// local retrieves all currently known local transactions, grouped by origin
// account and sorted by nonce. The returned transaction set is a copy and can be
// freely modified by calling code.
func (pool *TxPool) local() map[common.Address]types.Transactions {
	txs := make(map[common.Address]types.Transactions)
	for addr := range pool.locals.accounts {
		if pending := pool.pending[addr]; pending != nil {
			txs[addr] = append(txs[addr], pending.Flatten()...)
		}
		if queued := pool.queue[addr]; queued != nil {
			txs[addr] = append(txs[addr], queued.Flatten()...)
		}
	}
	return txs
}

// validateTx checks whether a transaction is valid according to the consensus
// rules and adheres to some heuristic limits of the local node (price and size).
func (pool *TxPool) validateTx(tx *types.Transaction, local bool) error {
	// Heuristic limit, reject transactions over 32KB to prevent DOS attacks
	if !types.ValidateType(tx.Types()) {
		return ErrTxType
	}

	if tx.Size() > 32*1024 {
		return ErrOversizedData
	}
	// Transactions can't be negative. This may never happen using RLP decoded
	// transactions but may occur if you create a transaction using the RPC.
	//Resource by zc
	inputStr := string(tx.Data())
	//Resource by zc
	if tx.Value().Sign() < 0 {
		return ErrNegativeValue
	}
	if tx.WhichTypes(types.Mortgage) || tx.WhichTypes(types.Regular) || tx.WhichTypes(types.InsteadMortgage) || tx.WhichTypes(types.Redeem) {
		if params.TxConfig.MinStaking.Cmp(tx.Value()) > 0 {
			return errors.New(" minimum value more than 100,000 ")
		}
	}

	to := tx.To()
	if to == nil && types.ValidateTo(tx.Types()) {
		return errors.New(" 'to' is required for this type ")
	}

	var netPayment common.Address
	if tx.IsRepayment() {
		payment, err := types.Sender(pool.signer, tx)
		if err != nil {
			return ErrInvalidSender
		}
		netPayment = payment
		tx.RemovePaymentSignatureValues()
	}
	from, err := types.Sender(pool.signer, tx)
	if err != nil {
		return ErrInvalidSender
	}
	// Ensure the transaction doesn't exceed the current block limit gas.
	//achilles replace gas with net
	//if pool.currentMaxGas < tx.Gas() {
	//	return ErrGasLimit
	//}
	for _, v := range pool.chain.CurrentBlock().SpecialConsensus().SpecialConsensusAddress {
		if nil != to && (v.Address == *to || v.Address == from) {
			return errors.New("can not transfer to special consensus address")
		}

		//if v.SpecialType == state.SealReward || v.SpecialType == state.OnlineMarketing {
		//	if nil != to && (v.ToAddress == *to || v.ToAddress == from) {
		//		return errors.New("can not transfer online or voting address")
		//	}
		//}
	}

	//achilles config validate candidates size

	if tx.WhichTypes(types.UpdateNodeInformation) {
		if err = ValidateUpdateInformation(pool.currentState, from, tx.Data()); err != nil {
			return err
		}
	}

	//2019.7.18 inb mod by ghy begin
	if tx.WhichTypes(types.Vote) {
		if err = ValidateVote(pool.currentState, tx.Data()); err != nil {
			return err
		}
	}

	// Make sure the transaction is signed properly

	if from[0] != crypto.PrefixToAddress[0] {
		return ErrInvalidAddress
	}
	if !tx.IsRepayment() {
		netPayment = from
	}
	// Drop non-local transactions under our own minimal accepted gas price
	//achilles replace gas with net
	//local = local || pool.locals.contains(from) // account may be local even if the transaction arrived from the network
	//if !local && pool.gasPrice.Cmp(tx.GasPrice()) > 0 {
	//	return ErrUnderpriced
	//}
	// Ensure the transaction adheres to nonce ordering
	if pool.currentState.GetNonce(from) > tx.Nonce() {
		return ErrNonceTooLow
	}
	// Transactor should have enough funds to cover the costs
	// cost == V + GP * GL
	//achilles replace gas with net
	//if pool.currentState.GetBalance(from).Cmp(tx.Cost()) < 0 {
	//	return ErrInsufficientFunds
	//}

	// No need to consume balance
	if tx.NoNeedUseBalance() {
		if pool.currentState.GetBalance(from).Cmp(tx.Value()) < 0 {
			return ErrInsufficientFunds
		}
	}

	if tx.WhichTypes(types.Reset) {
		if big.NewInt(0).Add(pool.currentState.GetDate(from), params.TxConfig.ResetDuration).Cmp(pool.chain.CurrentBlock().Number()) > 0 {
			return ErrBeforeResetTime
		}
	}

	if tx.WhichTypes(types.ReceiveLockedAward) {
		if err := pool.validateReceiveLockedAward(tx.Data(), from); err != nil {
			return err
		}
	}

	if tx.WhichTypes(types.ReceiveVoteAward) {
		if err := pool.validateReceiveVoteAward(from); err != nil {
			return err
		}
	}

	if tx.WhichTypes(types.Receive) {
		timeLimit := new(big.Int).Add(pool.currentState.GetUnStakingHeight(from), params.TxConfig.RedeemDuration)
		if timeLimit.Cmp(pool.chain.CurrentBlock().Number()) > 0 {
			return errors.New(" before receive time ")
		}
		if big.NewInt(0).Cmp(pool.currentState.GetUnStaking(from)) == 0 {
			return errors.New(" insufficient available value for unstaking ")
		}
	}

	if tx.WhichTypes(types.Regular) {
		//durations := strings.Split(inputStr, ":")
		//if len(durations) <= 1 {
		//	return errors.New(" can't resolve field of input transaction ")
		//}
		//convert, err := strconv.Atoi(durations[1])
		convert, err := strconv.Atoi(inputStr)
		if err != nil {
			return errors.New(" can't resolve field of input transaction ")
		}
		if !params.Contains(big.NewInt(int64(convert))) {
			return errors.New(" invalid duration for staking ")
		}
		if count := pool.currentState.StoreLength(netPayment); count >= params.TxConfig.RegularLimit {
			return ErrCountLimit
		}
	}

	if tx.WhichTypes(types.InsteadMortgage) {
		//durations := strings.Split(inputStr, ":")
		//if len(durations) <= 1 {
		//	return errors.New(" can't resolve field of input transaction ")
		//}
		//convert, err := strconv.Atoi(durations[1])
		convert, err := strconv.Atoi(inputStr)
		if err != nil {
			return errors.New(" can't resolve field of input transaction ")
		}
		if !params.Contains(big.NewInt(int64(convert))) {
			return errors.New(" invalid duration for staking ")
		}
		if count := pool.currentState.StoreLength(*tx.To()); count >= params.TxConfig.RegularLimit {
			return ErrCountLimit
		}
	}

	// No need to consume resources
	if tx.NoNeedUseNet() {
		intrinsicRes := IntrinsicRes(tx.Data(), to == nil && tx.Types() == types.Contract)
		res := pool.currentState.GetNet(netPayment)
		if res.Cmp(big.NewInt(int64(intrinsicRes))) < 0 {
			return ErrOverResValue
		}
	}

	if tx.WhichTypes(types.Redeem) {
		//Make sure the unmarshaled Net is less than the mortgaged Net
		unit := pool.currentState.UnitConvertNet()
		usableNet := pool.currentState.GetNet(netPayment)

		if tx.Value().Cmp(params.TxConfig.WeiOfUseNet) < 0 {
			return errors.New(" value for unstaking is too low ")
		}

		if usableNet.Cmp(unit) < 0 {
			return errors.New(" insufficient available staking ")
		}
		mortgageInb := pool.currentState.GetStakingValue(netPayment)
		mortgageInb.Sub(mortgageInb, pool.currentState.GetTotalStaking(netPayment))
		mortgageInb.Sub(mortgageInb, pool.currentState.GetUnStaking(netPayment))
		if mortgageInb.Cmp(tx.Value()) < 0 {
			return errors.New(" insufficient available staking ")
		}
	}

	// add by ssh 190921 begin
	if tx.WhichTypes(types.IssueLightToken) {
		if err := ValidateIssueLightToken(pool.currentState, from, tx.Data(), tx.Value()); err != nil {
			return err
		}
		//lightTokenInfo := strings.Split(inputStr, "~")
		//if len(lightTokenInfo) < vdpos.PosEventIssueLightTokenSplitLen {
		//	return errors.New("issue lightToken need 4 parameter")
		//} else {
		//	decimalsStr := lightTokenInfo[vdpos.PosEventIssueLightTokenDecimals]
		//	decimalsNum, err := strconv.ParseUint(decimalsStr, 10, 64)
		//	if err != nil {
		//		return errors.New("decimals is not uint8")
		//	} else if decimalsNum > 5 {
		//		return errors.New("decimals must from 0~5")
		//	}
		//	totalSupplyStr := lightTokenInfo[vdpos.PosEventIssueLightTokenTotalSupply]
		//	_, ok := new(big.Int).SetString(totalSupplyStr, 10)
		//	if !ok {
		//		return errors.New("unable to convert totalSupply string to big integer")
		//	}
		//}

	}

	if tx.WhichTypes(types.TransferLightToken) {
		lightTokenAddress := common.HexToAddress(inputStr)
		vdposContext := pool.chain.CurrentBlock().VdposContext

		// check up if lightToken exist
		lightTokenExist, err := vdposContext.GetLightToken(lightTokenAddress)
		if lightTokenExist == nil {
			return errors.New("this lightToken do not exist")
		} else {
			if err != nil {
				return errors.New("err in vdposContext.GetLightToken()")
			}
		}

		// check up if lightToken balance is enough
		senderBalance, err := vdposContext.GetLightTokenBalanceByAddress(from, lightTokenAddress)
		if err != nil {
			return err
		} else {
			if senderBalance.Cmp(tx.Value()) == -1 {
				return errors.New("not enough lightToken balance to transfer")
			}
		}
	}
	// add by ssh 190921 end

	if tx.WhichTypes(types.RegularLightToken) {
		stakingJson := new(types.StakingJson)
		if err := json.Unmarshal(tx.Data(), stakingJson); err != nil {
			return err
		}
		if stakingJson.LockHeights == nil {
			return errors.New(" lock heights is necessary ")
		}
		if !params.Contains(stakingJson.LockHeights) {
			return errors.New(" invalid duration for staking ")
		}

		vdposContext := pool.chain.CurrentBlock().VdposContext

		// check up if lightToken exist
		lightTokenExist, err := vdposContext.GetLightToken(stakingJson.LightTokenAddress)
		if lightTokenExist == nil {
			return errors.New("this lightToken do not exist")
		} else {
			if err != nil {
				return errors.New("err in vdposContext.GetLightToken()")
			}
		}

		// check up if lightToken balance is enough
		senderBalance, err := vdposContext.GetLightTokenBalanceByAddress(from, stakingJson.LightTokenAddress)
		if err != nil {
			return err
		} else {
			if senderBalance.Cmp(tx.Value()) == -1 {
				return errors.New("not enough lightToken balance to stake")
			}
		}

		// check up lightToken stakings count limit
		stakings, err := vdposContext.GetLightTokenStakingsByAddress(from, stakingJson.LightTokenAddress)
		if err != nil {
			return err
		} else {
			if count := len(stakings); count >= params.TxConfig.RegularLimit {
				return ErrCountLimit
			}
		}
	}

	if tx.WhichTypes(types.RedeemLightToken) {
		unStakingJson := new(types.UnStakingJson)
		if err := json.Unmarshal(tx.Data(), unStakingJson); err != nil {
			return err
		}

		vdposContext := pool.chain.CurrentBlock().VdposContext

		// check up if lightToken exist
		lightTokenExist, err := vdposContext.GetLightToken(unStakingJson.LightTokenAddress)
		if lightTokenExist == nil {
			return errors.New("this lightToken do not exist")
		} else {
			if err != nil {
				return errors.New("err in vdposContext.GetLightToken()")
			}
		}

		// check up lightToken stakings
		stakings, err := vdposContext.GetLightTokenStakingsByAddress(from, unStakingJson.LightTokenAddress)
		if err != nil {
			return err
		} else {
			if count := len(stakings); count <= 0 {
				return errors.New("no this locked record")
			}
			flag := false
			for _, staking := range stakings {
				if staking.Hash == unStakingJson.StakingHash {
					heightNow := pool.chain.CurrentBlock().Header().Number
					startHeight := staking.StartHeight
					lockHeights := staking.LockHeights
					endTimeHeight := new(big.Int).Add(startHeight, lockHeights)
					if heightNow.Cmp(endTimeHeight) == -1 {
						return errors.New("not correct block height to redeemLightToken")
					} else {
						flag = true
						break
					}
				}
			}
			if !flag {
				return errors.New("no this locked record")
			}
		}
	}

	if tx.WhichTypes(types.InsteadRegularLightToken) {
		stakingJson := new(types.StakingJson)
		if err := json.Unmarshal(tx.Data(), stakingJson); err != nil {
			return err
		}
		if stakingJson.LockHeights == nil {
			return errors.New(" lock heights is necessary ")
		}
		if !params.Contains(stakingJson.LockHeights) {
			return errors.New(" invalid duration for staking ")
		}

		vdposContext := pool.chain.CurrentBlock().VdposContext

		// check up if lightToken exist
		lightTokenExist, err := vdposContext.GetLightToken(stakingJson.LightTokenAddress)
		if lightTokenExist == nil {
			return errors.New("this lightToken do not exist")
		} else {
			if err != nil {
				return errors.New("err in vdposContext.GetLightToken()")
			}
		}

		// check up if lightToken balance is enough
		senderBalance, err := vdposContext.GetLightTokenBalanceByAddress(from, stakingJson.LightTokenAddress)
		if err != nil {
			return err
		} else {
			if senderBalance.Cmp(tx.Value()) == -1 {
				return errors.New("not enough lightToken balance to insteadRegular")
			}
		}

		// check up lightToken stakings count limit
		stakings, err := vdposContext.GetLightTokenStakingsByAddress(*tx.To(), stakingJson.LightTokenAddress)
		if stakings != nil {
			if count := len(stakings); count >= params.TxConfig.RegularLimit {
				return ErrCountLimit
			}
		}
	}

	return nil
}

// add validates a transaction and inserts it into the non-executable queue for
// later pending promotion and execution. If the transaction is a replacement for
// an already pending or queued one, it overwrites the previous and returns this
// so outer code doesn't uselessly call promote.
//
// If a newly added transaction is marked as local, its sending account will be
// whitelisted, preventing any associated transaction from being dropped out of
// the pool due to pricing constraints.
func (pool *TxPool) add(tx *types.Transaction, local bool) (bool, error) {
	// If the transaction is already known, discard it
	hash := tx.Hash()
	if pool.all.Get(hash) != nil {
		log.Trace("Discarding already known transaction", "hash", hash)
		return false, fmt.Errorf("known transaction: %x", hash)
	}
	// If the transaction fails basic validation, discard it
	if err := pool.validateTx(tx, local); err != nil {
		log.Trace("Discarding invalid transaction", "hash", hash, "err", err)
		invalidTxCounter.Inc(1)
		return false, err
	}
	// If the transaction pool is full, discard underpriced transactions
	if uint64(pool.all.Count()) >= pool.config.GlobalSlots+pool.config.GlobalQueue {
		// If the new transaction is underpriced, don't accept it
		if !local && pool.priced.Underpriced(tx, pool.locals) {
			//log.Trace("Discarding underpriced transaction", "hash", hash, "price", tx.GasPrice())
			log.Trace("Discarding underpriced transaction", "hash", hash)
			underpricedTxCounter.Inc(1)
			return false, ErrUnderpriced
		}
		// New transaction is better than our worse ones, make room for it
		drop := pool.priced.Discard(pool.all.Count()-int(pool.config.GlobalSlots+pool.config.GlobalQueue-1), pool.locals)
		for _, tx := range drop {
			//log.Trace("Discarding freshly underpriced transaction", "hash", tx.Hash(), "price", tx.GasPrice())
			log.Trace("Discarding freshly underpriced transaction", "hash", tx.Hash())
			underpricedTxCounter.Inc(1)
			pool.removeTx(tx.Hash(), false)
		}
	}
	// If the transaction is replacing an already pending one, do directly
	from, _ := types.Sender(pool.signer, tx) // already validated
	if list := pool.pending[from]; list != nil && list.Overlaps(tx) {
		// Nonce already pending, check if required price bump is met
		inserted, old := list.Add(tx, pool.config.PriceBump)
		if !inserted {
			pendingDiscardCounter.Inc(1)
			return false, ErrReplaceUnderpriced
		}
		// New transaction is better, replace old one
		if old != nil {
			pool.all.Remove(old.Hash())
			pool.priced.Removed()
			pendingReplaceCounter.Inc(1)
		}
		pool.all.Add(tx)
		pool.priced.Put(tx)
		pool.journalTx(from, tx)

		log.Trace("Pooled new executable transaction", "hash", hash, "from", from, "to", tx.To())

		// We've directly injected a replacement transaction, notify subsystems
		go pool.txFeed.Send(NewTxsEvent{types.Transactions{tx}})

		return old != nil, nil
	}
	// New transaction isn't replacing a pending one, push into queue
	replace, err := pool.enqueueTx(hash, tx)
	if err != nil {
		return false, err
	}
	// Mark local addresses and journal local transactions
	if local {
		if !pool.locals.contains(from) {
			log.Info("Setting new local account", "address", from)
			pool.locals.add(from)
		}
	}
	pool.journalTx(from, tx)

	log.Trace("Pooled new future transaction", "hash", hash, "from", from, "to", tx.To())
	return replace, nil
}

// enqueueTx inserts a new transaction into the non-executable transaction queue.
//
// Note, this method assumes the pool lock is held!
func (pool *TxPool) enqueueTx(hash common.Hash, tx *types.Transaction) (bool, error) {
	// Try to insert the transaction into the future queue
	from, _ := types.Sender(pool.signer, tx) // already validated
	if pool.queue[from] == nil {
		pool.queue[from] = newTxList(false)
	}
	inserted, old := pool.queue[from].Add(tx, pool.config.PriceBump)
	if !inserted {
		// An older transaction was better, discard this
		queuedDiscardCounter.Inc(1)
		return false, ErrReplaceUnderpriced
	}
	// Discard any previous transaction and mark this
	if old != nil {
		pool.all.Remove(old.Hash())
		pool.priced.Removed()
		queuedReplaceCounter.Inc(1)
	}
	if pool.all.Get(hash) == nil {
		pool.all.Add(tx)
		pool.priced.Put(tx)
	}
	return old != nil, nil
}

// journalTx adds the specified transaction to the local disk journal if it is
// deemed to have been sent from a local account.
func (pool *TxPool) journalTx(from common.Address, tx *types.Transaction) {
	// Only journal if it's enabled and the transaction is local
	if pool.journal == nil || !pool.locals.contains(from) {
		return
	}
	if err := pool.journal.insert(tx); err != nil {
		log.Warn("Failed to journal local transaction", "err", err)
	}
}

// promoteTx adds a transaction to the pending (processable) list of transactions
// and returns whether it was inserted or an older was better.
//
// Note, this method assumes the pool lock is held!
func (pool *TxPool) promoteTx(addr common.Address, hash common.Hash, tx *types.Transaction) bool {
	// Try to insert the transaction into the pending queue
	if pool.pending[addr] == nil {
		pool.pending[addr] = newTxList(true)
	}
	list := pool.pending[addr]

	inserted, old := list.Add(tx, pool.config.PriceBump)
	if !inserted {
		// An older transaction was better, discard this
		pool.all.Remove(hash)
		pool.priced.Removed()

		pendingDiscardCounter.Inc(1)
		return false
	}
	// Otherwise discard any previous transaction and mark this
	if old != nil {
		pool.all.Remove(old.Hash())
		pool.priced.Removed()

		pendingReplaceCounter.Inc(1)
	}
	// Failsafe to work around direct pending inserts (tests)
	if pool.all.Get(hash) == nil {
		pool.all.Add(tx)
		pool.priced.Put(tx)
	}
	// Set the potentially new pending nonce and notify any subsystems of the new tx
	pool.beats[addr] = time.Now()
	pool.pendingState.SetNonce(addr, tx.Nonce()+1)

	return true
}

// AddLocal enqueues a single transaction into the pool if it is valid, marking
// the sender as a local one in the mean time, ensuring it goes around the local
// pricing constraints.
func (pool *TxPool) AddLocal(tx *types.Transaction) error {
	return pool.addTx(tx, !pool.config.NoLocals)
}

// AddRemote enqueues a single transaction into the pool if it is valid. If the
// sender is not among the locally tracked ones, full pricing constraints will
// apply.
func (pool *TxPool) AddRemote(tx *types.Transaction) error {
	return pool.addTx(tx, false)
}

// AddLocals enqueues a batch of transactions into the pool if they are valid,
// marking the senders as a local ones in the mean time, ensuring they go around
// the local pricing constraints.
func (pool *TxPool) AddLocals(txs []*types.Transaction) []error {
	return pool.addTxs(txs, !pool.config.NoLocals)
}

// AddRemotes enqueues a batch of transactions into the pool if they are valid.
// If the senders are not among the locally tracked ones, full pricing constraints
// will apply.
func (pool *TxPool) AddRemotes(txs []*types.Transaction) []error {
	return pool.addTxs(txs, false)
}

// addTx enqueues a single transaction into the pool if it is valid.
func (pool *TxPool) addTx(tx *types.Transaction, local bool) error {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	// Try to inject the transaction and update any state
	replace, err := pool.add(tx, local)
	if err != nil {
		return err
	}
	// If we added a new transaction, run promotion checks and return
	if !replace {
		from, _ := types.Sender(pool.signer, tx) // already validated
		pool.promoteExecutables([]common.Address{from})
	}
	return nil
}

// addTxs attempts to queue a batch of transactions if they are valid.
func (pool *TxPool) addTxs(txs []*types.Transaction, local bool) []error {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	return pool.addTxsLocked(txs, local)
}

// addTxsLocked attempts to queue a batch of transactions if they are valid,
// whilst assuming the transaction pool lock is already held.
func (pool *TxPool) addTxsLocked(txs []*types.Transaction, local bool) []error {
	// Add the batch of transactions, tracking the accepted ones
	dirty := make(map[common.Address]struct{})
	errs := make([]error, len(txs))

	for i, tx := range txs {
		var replace bool
		if replace, errs[i] = pool.add(tx, local); errs[i] == nil && !replace {
			from, _ := types.Sender(pool.signer, tx) // already validated
			dirty[from] = struct{}{}
		}
	}
	// Only reprocess the internal state if something was actually added
	if len(dirty) > 0 {
		addrs := make([]common.Address, 0, len(dirty))
		for addr := range dirty {
			addrs = append(addrs, addr)
		}
		pool.promoteExecutables(addrs)
	}
	return errs
}

// Status returns the status (unknown/pending/queued) of a batch of transactions
// identified by their hashes.
func (pool *TxPool) Status(hashes []common.Hash) []TxStatus {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	status := make([]TxStatus, len(hashes))
	for i, hash := range hashes {
		if tx := pool.all.Get(hash); tx != nil {
			from, _ := types.Sender(pool.signer, tx) // already validated
			if pool.pending[from] != nil && pool.pending[from].txs.items[tx.Nonce()] != nil {
				status[i] = TxStatusPending
			} else {
				status[i] = TxStatusQueued
			}
		}
	}
	return status
}

// Get returns a transaction if it is contained in the pool
// and nil otherwise.
func (pool *TxPool) Get(hash common.Hash) *types.Transaction {
	return pool.all.Get(hash)
}

// removeTx removes a single transaction from the queue, moving all subsequent
// transactions back to the future queue.
func (pool *TxPool) removeTx(hash common.Hash, outofbound bool) {
	// Fetch the transaction we wish to delete
	tx := pool.all.Get(hash)
	if tx == nil {
		return
	}
	addr, _ := types.Sender(pool.signer, tx) // already validated during insertion

	// Remove it from the list of known transactions
	pool.all.Remove(hash)
	if outofbound {
		pool.priced.Removed()
	}
	// Remove the transaction from the pending lists and reset the account nonce
	if pending := pool.pending[addr]; pending != nil {
		if removed, invalids := pending.Remove(tx); removed {
			// If no more pending transactions are left, remove the list
			if pending.Empty() {
				delete(pool.pending, addr)
				delete(pool.beats, addr)
			}
			// Postpone any invalidated transactions
			for _, tx := range invalids {
				pool.enqueueTx(tx.Hash(), tx)
			}
			// Update the account nonce if needed
			if nonce := tx.Nonce(); pool.pendingState.GetNonce(addr) > nonce {
				pool.pendingState.SetNonce(addr, nonce)
			}
			return
		}
	}
	// Transaction is in the future queue
	if future := pool.queue[addr]; future != nil {
		future.Remove(tx)
		if future.Empty() {
			delete(pool.queue, addr)
		}
	}
}

// promoteExecutables moves transactions that have become processable from the
// future queue to the set of pending transactions. During this process, all
// invalidated transactions (low nonce, low balance) are deleted.
func (pool *TxPool) promoteExecutables(accounts []common.Address) {
	// Track the promoted transactions to broadcast them at once
	var promoted []*types.Transaction

	// Gather all the accounts potentially needing updates
	if accounts == nil {
		accounts = make([]common.Address, 0, len(pool.queue))
		for addr := range pool.queue {
			accounts = append(accounts, addr)
		}
	}
	// Iterate over all accounts and promote any executable transactions
	for _, addr := range accounts {
		list := pool.queue[addr]
		if list == nil {
			continue // Just in case someone calls with a non existing account
		}
		// Drop all transactions that are deemed too old (low nonce)
		for _, tx := range list.Forward(pool.currentState.GetNonce(addr)) {
			hash := tx.Hash()
			log.Trace("Removed old queued transaction", "hash", hash)
			pool.all.Remove(hash)
			pool.priced.Removed()
		}
		// Drop all transactions that are too costly (low balance or out of gas)
		drops, _ := list.Filter(pool.currentState.GetBalance(addr), pool.currentMaxGas)
		for _, tx := range drops {
			hash := tx.Hash()
			log.Trace("Removed unpayable queued transaction", "hash", hash)
			pool.all.Remove(hash)
			pool.priced.Removed()
			queuedNofundsCounter.Inc(1)
		}
		// Gather all executable transactions and promote them
		for _, tx := range list.Ready(pool.pendingState.GetNonce(addr)) {
			hash := tx.Hash()
			if pool.promoteTx(addr, hash, tx) {
				log.Trace("Promoting queued transaction", "hash", hash)
				promoted = append(promoted, tx)
			}
		}
		// Drop all transactions over the allowed limit
		if !pool.locals.contains(addr) {
			for _, tx := range list.Cap(int(pool.config.AccountQueue)) {
				hash := tx.Hash()
				pool.all.Remove(hash)
				pool.priced.Removed()
				queuedRateLimitCounter.Inc(1)
				log.Trace("Removed cap-exceeding queued transaction", "hash", hash)
			}
		}
		// Delete the entire queue entry if it became empty.
		if list.Empty() {
			delete(pool.queue, addr)
		}
	}
	// Notify subsystem for new promoted transactions.
	if len(promoted) > 0 {
		go pool.txFeed.Send(NewTxsEvent{promoted})
	}
	// If the pending limit is overflown, start equalizing allowances
	pending := uint64(0)
	for _, list := range pool.pending {
		pending += uint64(list.Len())
	}
	if pending > pool.config.GlobalSlots {
		pendingBeforeCap := pending
		// Assemble a spam order to penalize large transactors first
		spammers := prque.New(nil)
		for addr, list := range pool.pending {
			// Only evict transactions from high rollers
			if !pool.locals.contains(addr) && uint64(list.Len()) > pool.config.AccountSlots {
				spammers.Push(addr, int64(list.Len()))
			}
		}
		// Gradually drop transactions from offenders
		offenders := []common.Address{}
		for pending > pool.config.GlobalSlots && !spammers.Empty() {
			// Retrieve the next offender if not local address
			offender, _ := spammers.Pop()
			offenders = append(offenders, offender.(common.Address))

			// Equalize balances until all the same or below threshold
			if len(offenders) > 1 {
				// Calculate the equalization threshold for all current offenders
				threshold := pool.pending[offender.(common.Address)].Len()

				// Iteratively reduce all offenders until below limit or threshold reached
				for pending > pool.config.GlobalSlots && pool.pending[offenders[len(offenders)-2]].Len() > threshold {
					for i := 0; i < len(offenders)-1; i++ {
						list := pool.pending[offenders[i]]
						for _, tx := range list.Cap(list.Len() - 1) {
							// Drop the transaction from the global pools too
							hash := tx.Hash()
							pool.all.Remove(hash)
							pool.priced.Removed()

							// Update the account nonce to the dropped transaction
							if nonce := tx.Nonce(); pool.pendingState.GetNonce(offenders[i]) > nonce {
								pool.pendingState.SetNonce(offenders[i], nonce)
							}
							log.Trace("Removed fairness-exceeding pending transaction", "hash", hash)
						}
						pending--
					}
				}
			}
		}
		// If still above threshold, reduce to limit or min allowance
		if pending > pool.config.GlobalSlots && len(offenders) > 0 {
			for pending > pool.config.GlobalSlots && uint64(pool.pending[offenders[len(offenders)-1]].Len()) > pool.config.AccountSlots {
				for _, addr := range offenders {
					list := pool.pending[addr]
					for _, tx := range list.Cap(list.Len() - 1) {
						// Drop the transaction from the global pools too
						hash := tx.Hash()
						pool.all.Remove(hash)
						pool.priced.Removed()

						// Update the account nonce to the dropped transaction
						if nonce := tx.Nonce(); pool.pendingState.GetNonce(addr) > nonce {
							pool.pendingState.SetNonce(addr, nonce)
						}
						log.Trace("Removed fairness-exceeding pending transaction", "hash", hash)
					}
					pending--
				}
			}
		}
		pendingRateLimitCounter.Inc(int64(pendingBeforeCap - pending))
	}
	// If we've queued more transactions than the hard limit, drop oldest ones
	queued := uint64(0)
	for _, list := range pool.queue {
		queued += uint64(list.Len())
	}
	if queued > pool.config.GlobalQueue {
		// Sort all accounts with queued transactions by heartbeat
		addresses := make(addressesByHeartbeat, 0, len(pool.queue))
		for addr := range pool.queue {
			if !pool.locals.contains(addr) { // don't drop locals
				addresses = append(addresses, addressByHeartbeat{addr, pool.beats[addr]})
			}
		}
		sort.Sort(addresses)

		// Drop transactions until the total is below the limit or only locals remain
		for drop := queued - pool.config.GlobalQueue; drop > 0 && len(addresses) > 0; {
			addr := addresses[len(addresses)-1]
			list := pool.queue[addr.address]

			addresses = addresses[:len(addresses)-1]

			// Drop all transactions if they are less than the overflow
			if size := uint64(list.Len()); size <= drop {
				for _, tx := range list.Flatten() {
					pool.removeTx(tx.Hash(), true)
				}
				drop -= size
				queuedRateLimitCounter.Inc(int64(size))
				continue
			}
			// Otherwise drop only last few transactions
			txs := list.Flatten()
			for i := len(txs) - 1; i >= 0 && drop > 0; i-- {
				pool.removeTx(txs[i].Hash(), true)
				drop--
				queuedRateLimitCounter.Inc(1)
			}
		}
	}
}

// demoteUnexecutables removes invalid and processed transactions from the pools
// executable/pending queue and any subsequent transactions that become unexecutable
// are moved back into the future queue.
func (pool *TxPool) demoteUnexecutables() {
	// Iterate over all accounts and demote any non-executable transactions
	for addr, list := range pool.pending {
		nonce := pool.currentState.GetNonce(addr)

		// Drop all transactions that are deemed too old (low nonce)
		for _, tx := range list.Forward(nonce) {
			hash := tx.Hash()
			log.Trace("Removed old pending transaction", "hash", hash)
			pool.all.Remove(hash)
			pool.priced.Removed()
		}
		// Drop all transactions that are too costly (low balance or out of gas), and queue any invalids back for later
		drops, invalids := list.Filter(pool.currentState.GetBalance(addr), pool.currentMaxGas)
		for _, tx := range drops {
			hash := tx.Hash()
			log.Trace("Removed unpayable pending transaction", "hash", hash)
			pool.all.Remove(hash)
			pool.priced.Removed()
			pendingNofundsCounter.Inc(1)
		}
		for _, tx := range invalids {
			hash := tx.Hash()
			log.Trace("Demoting pending transaction", "hash", hash)
			pool.enqueueTx(hash, tx)
		}
		// If there's a gap in front, alert (should never happen) and postpone all transactions
		if list.Len() > 0 && list.txs.Get(nonce) == nil {
			for _, tx := range list.Cap(0) {
				hash := tx.Hash()
				log.Error("Demoting invalidated transaction", "hash", hash)
				pool.enqueueTx(hash, tx)
			}
		}
		// Delete the entire queue entry if it became empty.
		if list.Empty() {
			delete(pool.pending, addr)
			delete(pool.beats, addr)
		}
	}
}

// addressByHeartbeat is an account address tagged with its last activity timestamp.
type addressByHeartbeat struct {
	address   common.Address
	heartbeat time.Time
}

type addressesByHeartbeat []addressByHeartbeat

func (a addressesByHeartbeat) Len() int           { return len(a) }
func (a addressesByHeartbeat) Less(i, j int) bool { return a[i].heartbeat.Before(a[j].heartbeat) }
func (a addressesByHeartbeat) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

// accountSet is simply a set of addresses to check for existence, and a signer
// capable of deriving addresses from transactions.
type accountSet struct {
	accounts map[common.Address]struct{}
	signer   types.Signer
	cache    *[]common.Address
}

// newAccountSet creates a new address set with an associated signer for sender
// derivations.
func newAccountSet(signer types.Signer) *accountSet {
	return &accountSet{
		accounts: make(map[common.Address]struct{}),
		signer:   signer,
	}
}

// contains checks if a given address is contained within the set.
func (as *accountSet) contains(addr common.Address) bool {
	_, exist := as.accounts[addr]
	return exist
}

// containsTx checks if the sender of a given tx is within the set. If the sender
// cannot be derived, this method returns false.
func (as *accountSet) containsTx(tx *types.Transaction) bool {
	if addr, err := types.Sender(as.signer, tx); err == nil {
		return as.contains(addr)
	}
	return false
}

// add inserts a new address into the set to track.
func (as *accountSet) add(addr common.Address) {
	as.accounts[addr] = struct{}{}
	as.cache = nil
}

// flatten returns the list of addresses within this set, also caching it for later
// reuse. The returned slice should not be changed!
func (as *accountSet) flatten() []common.Address {
	if as.cache == nil {
		accounts := make([]common.Address, 0, len(as.accounts))
		for account := range as.accounts {
			accounts = append(accounts, account)
		}
		as.cache = &accounts
	}
	return *as.cache
}

// txLookup is used internally by TxPool to track transactions while allowing lookup without
// mutex contention.
//
// Note, although this type is properly protected against concurrent access, it
// is **not** a type that should ever be mutated or even exposed outside of the
// transaction pool, since its internal state is tightly coupled with the pools
// internal mechanisms. The sole purpose of the type is to permit out-of-bound
// peeking into the pool in TxPool.Get without having to acquire the widely scoped
// TxPool.mu mutex.
type txLookup struct {
	all  map[common.Hash]*types.Transaction
	lock sync.RWMutex
}

// newTxLookup returns a new txLookup structure.
func newTxLookup() *txLookup {
	return &txLookup{
		all: make(map[common.Hash]*types.Transaction),
	}
}

// Range calls f on each key and value present in the map.
func (t *txLookup) Range(f func(hash common.Hash, tx *types.Transaction) bool) {
	t.lock.RLock()
	defer t.lock.RUnlock()

	for key, value := range t.all {
		if !f(key, value) {
			break
		}
	}
}

// Get returns a transaction if it exists in the lookup, or nil if not found.
func (t *txLookup) Get(hash common.Hash) *types.Transaction {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.all[hash]
}

// Count returns the current number of items in the lookup.
func (t *txLookup) Count() int {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return len(t.all)
}

// Add adds a transaction to the lookup.
func (t *txLookup) Add(tx *types.Transaction) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.all[tx.Hash()] = tx
}

// Remove removes a transaction from the lookup.
func (t *txLookup) Remove(hash common.Hash) {
	t.lock.Lock()
	defer t.lock.Unlock()

	delete(t.all, hash)
}

func (pool *TxPool) validateVote(inputStr string, txType types.TxType) error {
	if strings.Contains(inputStr, "candidates") {
		var candidatesSlice []common.Address
		var UnqualifiedCandidatesSlice []string
		candidates := strings.Split(inputStr, ":")
		if candidates[0] == "candidates" {
			candidatesStr := strings.Split(candidates[1], ",")
			for _, value := range candidatesStr {
				address := common.HexToAddress(value)
				//2019.7.15 inb mod by ghy begin
				if pool.currentState.GetAccountInfo(address).Res.StakingValue.Cmp(vdpos.BeVotedNeedINB) == 1 {
					candidatesSlice = append(candidatesSlice, address)
				} else {
					UnqualifiedCandidatesSlice = append(UnqualifiedCandidatesSlice, address.String())
				}
			}
			if len(UnqualifiedCandidatesSlice) > 0 {
				return errors.New(fmt.Sprintf("Voting Node Account : %v Mortgage Less than %v", UnqualifiedCandidatesSlice, vdpos.BeVotedNeedINB))
			}
			//2019.7.15 inb mod by ghy end
			if params.TxConfig.CandidateSize < uint64(len(candidatesSlice)) {
				return errors.New("candidates over size")
			}
		}
	}
	return nil
}

//2019.7.22 inb by ghy begin
func (pool *TxPool) validateReceiveLockedAward(receivebonus []byte, from common.Address) error {
	account := pool.currentState.GetAccountInfo(from)
	if account == nil {
		return errors.New("errors of address")
	}
	if account.Voted.Cmp(big.NewInt(0)) != 1 {
		return errors.New("can only receive locked rewards after voting")
	}
	if len(account.Stakings) <= 0 {
		return errors.New("no locked record")
	}

	LockedRewardCycleHeight := new(big.Int)
	LockedRewardCycleTimes := new(big.Int)
	LockedDenominator := new(big.Int)
	LockedHundred := new(big.Int)
	LockedNumberOfDaysOneYear := new(big.Int)
	for _, v := range account.Stakings {
		if v.Hash == common.BytesToHash(receivebonus) {
			switch v.LockHeights.Uint64() {
			case params.HeightOf30Days.Uint64():
				LockedRewardCycleHeight = common.LockedRewardCycleSecondsFor30days
				LockedRewardCycleTimes = common.LockedRewardCycleTimesFor30days
				LockedDenominator = common.LockedDenominatorFor30days
				LockedHundred = common.LockedHundredFor30days
				LockedNumberOfDaysOneYear = common.LockedNumberOfDaysOneYearFor30days
			case params.HeightOf90Days.Uint64():
				LockedRewardCycleHeight = common.LockedRewardCycleSecondsFor90days
				LockedRewardCycleTimes = common.LockedRewardCycleTimesFor90days
				LockedDenominator = common.LockedDenominatorFor90days
				LockedHundred = common.LockedHundredFor90days
				LockedNumberOfDaysOneYear = common.LockedNumberOfDaysOneYearFor90days
			case params.HeightOf180Days.Uint64():
				LockedRewardCycleHeight = common.LockedRewardCycleSecondsFor180days
				LockedRewardCycleTimes = common.LockedRewardCycleTimesFor180days
				LockedDenominator = common.LockedDenominatorFor180days
				LockedHundred = common.LockedHundredFor180days
				LockedNumberOfDaysOneYear = common.LockedNumberOfDaysOneYearFor180days
			case params.HeightOf360Days.Uint64(), params.HeightOf720Days.Uint64(), params.HeightOf1080Days.Uint64(), params.HeightOf1800Days.Uint64(), params.HeightOf3600Days.Uint64():
				LockedRewardCycleHeight = common.LockedRewardCycleSecondsForMoreThan360days
				LockedRewardCycleTimes = common.LockedRewardCycleTimesForMoreThan360days
				LockedDenominator = common.LockedDenominatorForMoreThan360days
				LockedHundred = common.LockedHundredForMoreThan360days
				LockedNumberOfDaysOneYear = common.LockedNumberOfDaysOneYearForMoreThan360days
			default:
				return errors.New("unknow times")
			}

			heightNow := pool.chain.CurrentBlock().Header().Number

			startHeight := v.StartHeight
			lastReceivedHeight := v.LastReceivedHeight

			lockHeights := v.LockHeights
			endTimeHeight := new(big.Int).Add(startHeight, lockHeights)

			totalValue := v.Value
			receivedValue := v.Received

			if startHeight.Cmp(lastReceivedHeight) == 1 {
				return errors.New("last receipt time and start time error")
			}
			if lastReceivedHeight.Cmp(heightNow) == 1 {
				return errors.New("last receipt time error")
			}
			if lastReceivedHeight.Cmp(endTimeHeight) == 1 {
				return errors.New("all the rewards are received")
			}

			FromLastReceivedPassTimeHeight := new(big.Int).Sub(heightNow, lastReceivedHeight)
			FromStartPassTimeHeight := new(big.Int).Sub(heightNow, startHeight)

			if heightNow.Cmp(endTimeHeight) >= 0 {
				//HeightNow = endTimeHeight
				FromLastReceivedPassTimeHeight = new(big.Int).Sub(endTimeHeight, lastReceivedHeight)
				FromStartPassTimeHeight = new(big.Int).Sub(endTimeHeight, startHeight)
			}

			FromLastReceivedPassDays := new(big.Int).Div(FromLastReceivedPassTimeHeight, LockedRewardCycleHeight)

			FromStartPassDays := new(big.Int).Div(FromStartPassTimeHeight, LockedRewardCycleHeight)

			totalValue1 := new(big.Int).Mul(totalValue, LockedDenominator)
			totalValue2 := new(big.Int).Mul(totalValue1, FromStartPassDays)
			totalValue3 := new(big.Int).Div(totalValue2, LockedHundred)
			MaxReceivedValueNow := new(big.Int).Div(totalValue3, LockedNumberOfDaysOneYear)
			subValue := new(big.Int).Sub(MaxReceivedValueNow, receivedValue)

			if subValue.Cmp(big.NewInt(0)) != 1 {
				return errors.New("have no rewards to received")
			}

			if heightNow.Cmp(endTimeHeight) == -1 && FromLastReceivedPassDays.Cmp(LockedRewardCycleTimes) == -1 {
				return errors.New("not block height to receive rewards")
			}
			//for _, v := range pool.chain.CurrentBlock().Header().GetSpecialConsensus().SpecialConsensusAddress {
			//	if v.SpecialType == state.OnlineMarketing {
			//		if pool.currentState.GetBalance(v.ToAddress).Cmp(subValue) != 1 {
			//			return errors.New("there are not enough inb in the online account")
			//		}
			//		return nil
			//	}
			//}
			return errors.New("can not find online account")
		}
	}
	return errors.New("no such lock record")

}

func (pool *TxPool) validateReceiveVoteAward(from common.Address) error {
	account := pool.currentState.GetAccountInfo(from)
	if account == nil {
		return errors.New("errors of address")
	}
	if account.Voted.Cmp(big.NewInt(0)) != 1 {
		return errors.New("please receive vote award after voting")
	}

	HeightNow := pool.chain.CurrentBlock().Header().Number
	lastReceiveVoteAwardHeight := account.LastReceivedVoteRewardHeight
	if HeightNow.Cmp(lastReceiveVoteAwardHeight) != 1 {
		return errors.New("last receive vote award time error")
	}

	fromLastReceiveVoteAwardTimeToNowHeight := new(big.Int).Sub(HeightNow, lastReceiveVoteAwardHeight)
	cycles := new(big.Int).Div(fromLastReceiveVoteAwardTimeToNowHeight, common.VoteRewardCycleSeconds)
	if cycles.Cmp(common.VoteRewardCycleTimes) >= 0 {
		consensus := pool.chain.CurrentBlock().Header().GetSpecialConsensus()
		for _, v := range consensus.SpecialConsensusAddress {
			if v.SpecialType == state.SealReward {
				votes := account.Voted
				votes1 := new(big.Int).Mul(votes, common.VoteDenominator)
				votes2 := new(big.Int).Mul(votes1, cycles)
				votes3 := new(big.Int).Div(votes2, common.VoteHundred)
				value := new(big.Int).Div(votes3, common.VoteNumberOfDaysOneYear)

				if pool.currentState.GetBalance(v.ToAddress).Cmp(value) != 1 {
					return errors.New("there are not enough inb in the voting account")
				}
			}
		}
		return nil
	}

	return errors.New("not receive vote award time")
}

//2019.7.22 inb by ghy end
func ValidateUpdateInformation(db vm.StateDB, from common.Address, input []byte) error {
	nodeInfo := new(common.SuperNodeExtra)

	if len(input) > common.LenOfNodeInfoByte {
		return errors.New("date over size")
	}

	if err := json.Unmarshal(input, nodeInfo); err != nil {
		return err
	}

	if ip := net.ParseIP(nodeInfo.Ip); ip == nil {
		return errors.New("err of ip")
	}

	if err := ValidatePort(nodeInfo.Port); err != nil {
		return err
	}

	if len(nodeInfo.Id) != common.LenOfNodeInfoId || len(nodeInfo.Id) == 0 {
		return errors.New("len of node id err")
	}

	if nodeInfo.RewardAccount != "" && !common.IsRewardAddress(nodeInfo.RewardAccount) {
		return errors.New("err of reward account")
	}

	if len(nodeInfo.Image) > common.LenOfNodeInfoImage {
		return errors.New("out of image length")
	}

	if len(nodeInfo.Email) > common.LenOfNodeInfoEmail {
		return errors.New("out of email length")
	}

	if len(nodeInfo.Website) > common.LenOfNodeInfoWebsite {
		return errors.New("out of website length")
	}

	if len(nodeInfo.Nation) > common.LenOfNodeInfoNation {
		return errors.New("out of nation length")
	}

	if len(nodeInfo.Name) > common.LenOfNodeInfoName {
		return errors.New("out of name length")
	}

	if len(nodeInfo.ExtraData) > common.LenOfNodeInfoExtraData {
		return errors.New("out of extra data length")
	}

	if db.GetStakingValue(from).Cmp(vdpos.BeVotedNeedINB) == -1 {
		return errors.New(fmt.Sprintf("update node mortgage Less than %v", vdpos.BeVotedNeedINB))
	}

	return nil
}

func ValidatePort(port string) error {
	if len(port) > common.LenOfNodeInfoPort || len(port) == 0 {
		return errors.New("len of port err")
	}
	intPort, err := strconv.Atoi(port)
	if err != nil {
		return err
	}
	if intPort <= 0 || intPort > 65535 {
		return errors.New("out of port range")
	}
	return nil
}

func ValidateVote(db vm.StateDB, input []byte) error {
	var candidatesSlice []common.Address
	var UnqualifiedCandidatesSlice []string
	var UnAddressSlice []string
	candidatesStr := strings.Split(string(input), ",")
	for _, value := range candidatesStr {
		if !common.IsRewardAddress(value) {
			UnAddressSlice = append(UnAddressSlice, value)
		}
		address := common.HexToAddress(value)
		//2019.7.15 inb mod by ghy begin
		if db.GetStakingValue(address).Cmp(vdpos.BeVotedNeedINB) >= 0 {
			candidatesSlice = append(candidatesSlice, address)
		} else {
			UnqualifiedCandidatesSlice = append(UnqualifiedCandidatesSlice, address.String())
		}
	}
	if len(UnAddressSlice) > 0 {
		return errors.New(fmt.Sprintf("Voting node : %v is not address", UnAddressSlice))
	}
	if len(UnqualifiedCandidatesSlice) > 0 {
		return errors.New(fmt.Sprintf("Voting Node Account : %v Mortgage Less than %v", UnqualifiedCandidatesSlice, vdpos.BeVotedNeedINB))
	}
	//2019.7.15 inb mod by ghy end
	if params.TxConfig.CandidateSize < uint64(len(candidatesSlice)) {
		return errors.New("candidates over size")
	}
	return nil
}

func ValidateIssueLightToken(db vm.StateDB, from common.Address, input []byte, value *big.Int) error {
	lightTokenJson := new(types.LightTokenJson)

	if len(input) > common.LenOfLightTokenByte {
		return errors.New("data too big")
	}

	if err := json.Unmarshal(input, lightTokenJson); err != nil {
		return err
	}

	if len(lightTokenJson.Name) > common.LenOfLightTokenName {
		return errors.New("light token name too long")
	}

	if lightTokenJson.Decimals > common.LightTokenDecimals {
		return errors.New("light token decimals must from 0~5")
	}

	if len(lightTokenJson.Symbol) > common.LenOfLightTokenSymbol {
		return errors.New("light token symbol name  too long")
	}
	if lightTokenJson.TotalSupply == nil {
		return errors.New(" totalSupply is necessary")
	}
	if lightTokenJson.TotalSupply.Cmp(big.NewInt(0)) != 1 {
		return errors.New("light token totalSupply can not negative")
	}

	if lightTokenJson.TotalSupply.Cmp(common.LenOfLightTokenTotalSupply) > 0 {
		return errors.New("light token totalSupply too big")
	}
	if value.Cmp(common.LightTokenMinValue) < 0 || value.Cmp(common.LightTokenMaxValue) > 0 {
		return errors.New("issue token must sub 1000~10000 inb")
	}

	if db.GetBalance(from).Cmp(value) < 0 {
		return errors.New("issue token : balance not enough")
	}

	return nil
}
