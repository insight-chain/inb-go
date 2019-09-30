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

package state

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/insight-chain/inb-go/common"
	"github.com/insight-chain/inb-go/core/types"
	"github.com/insight-chain/inb-go/params"

	"github.com/insight-chain/inb-go/crypto"
	"github.com/insight-chain/inb-go/rlp"
	"io"
	"math/big"
)

var emptyCodeHash = crypto.Keccak256(nil)

type Code []byte

func (self Code) String() string {
	return string(self) //strings.Join(Disassemble(self), " ")
}

type Storage map[common.Hash]common.Hash

func (self Storage) String() (str string) {
	for key, value := range self {
		str += fmt.Sprintf("%X : %X\n", key, value)
	}

	return
}

func (self Storage) Copy() Storage {
	cpy := make(Storage)
	for key, value := range self {
		cpy[key] = value
	}

	return cpy
}

// stateObject represents an Ethereum account which is being modified.
//
// The usage pattern is as follows:
// First you need to obtain a state object.
// Account values can be accessed and modified through the object.
// Finally, call CommitTrie to write the modified storage trie into a database.
type stateObject struct {
	address  common.Address
	addrHash common.Hash // hash of ethereum address of the account
	data     Account
	db       *StateDB

	// DB error.
	// State objects are used by the consensus core and VM which are
	// unable to deal with database-level errors. Any error that occurs
	// during a database read is memoized here and will eventually be returned
	// by StateDB.Commit.
	dbErr error

	// Write caches.
	trie Trie // storage trie, which becomes non-nil on first access
	code Code // contract bytecode, which gets set when code is loaded

	originStorage Storage // Storage cache of original entries to dedup rewrites
	dirtyStorage  Storage // Storage entries that need to be flushed to disk

	// Cache flags.
	// When an object is marked suicided it will be delete from the trie
	// during the "update" phase of the state transition.
	dirtyCode bool // true if the code was updated
	suicided  bool
	deleted   bool
}

// empty returns whether the account is considered empty.
func (s *stateObject) empty() bool {
	return s.data.Nonce == 0 && s.data.Balance.Sign() == 0 && bytes.Equal(s.data.CodeHash, emptyCodeHash)
}

// Account is the Ethereum consensus representation of accounts.
// These objects are stored in the main account trie.
type Account struct {
	Nonce    uint64
	Balance  *big.Int
	Root     common.Hash // merkle root of the storage trie
	CodeHash []byte
	Res      Resource // resource for account
	Stores   []Store  // slice of regular mortgaging
	//Recommender common.Address
	Redeems                      []Redeem // redeeming nets
	Regular                      *big.Int //  total of regular mortgaging
	Voted                        *big.Int //current vote to someone else number
	LastReceivedVoteRewardHeight *big.Int
}

type Resource struct {
	Used     *big.Int // used
	Usable   *big.Int // unuse
	Mortgage *big.Int // total number of mortgage
	Height   *big.Int
}

//Resource by zc
//type Resources struct {
//	CPU  Resource
//	NET  Resource
//	Date *big.Int
//}
//type Resource struct {
//	Used         *big.Int // used
//	Usableness   *big.Int // unuse
//	MortgagteINB *big.Int //
//}

type Store struct {
	Hash               common.Hash // transaction of regular mortgaging
	StartHeight        *big.Int    // start time
	LockHeights        *big.Int    // duration of mortgaging
	Value              *big.Int    // amount of mortgaging
	Received           *big.Int    // amount of already received value
	LastReceivedHeight *big.Int    // Last receive time
}

type Redeem struct {
	StartHeight *big.Int // start time
	Value       *big.Int // amount of redeeming
}

//Resource by zc
// newObject creates a state object.
func newObject(db *StateDB, address common.Address, data Account) *stateObject {
	if data.Balance == nil {
		data.Balance = new(big.Int)
	}
	if data.CodeHash == nil {
		data.CodeHash = emptyCodeHash
	}
	//Resource by zc
	if data.Res.Used == nil {
		data.Res.Used = new(big.Int)
	}
	if data.Res.Usable == nil {
		data.Res.Usable = new(big.Int)
	}
	if data.Res.Mortgage == nil {
		data.Res.Mortgage = new(big.Int)
	}
	if data.Res.Height == nil {
		data.Res.Height = new(big.Int)
	}
	if data.Stores == nil {
		data.Stores = make([]Store, 0)
	}
	if data.Redeems == nil {
		data.Redeems = make([]Redeem, 1)
	}
	if data.Regular == nil {
		data.Regular = new(big.Int)
	}
	if data.LastReceivedVoteRewardHeight == nil {
		data.LastReceivedVoteRewardHeight = new(big.Int)
	}
	if data.Voted == nil {
		data.Voted = new(big.Int)
	}
	//Resource by zc
	return &stateObject{
		db:            db,
		address:       address,
		addrHash:      crypto.Keccak256Hash(address[:]),
		data:          data,
		originStorage: make(Storage),
		dirtyStorage:  make(Storage),
	}
}

// EncodeRLP implements rlp.Encoder.
func (c *stateObject) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, c.data)
}

// setError remembers the first non-nil error it is called with.
func (self *stateObject) setError(err error) {
	if self.dbErr == nil {
		self.dbErr = err
	}
}

func (self *stateObject) markSuicided() {
	self.suicided = true
}

func (c *stateObject) touch() {
	c.db.journal.append(touchChange{
		account: &c.address,
	})
	if c.address == ripemd {
		// Explicitly put it in the dirty-cache, which is otherwise generated from
		// flattened journals.
		c.db.journal.dirty(c.address)
	}
}

func (c *stateObject) getTrie(db Database) Trie {
	if c.trie == nil {
		var err error
		c.trie, err = db.OpenStorageTrie(c.addrHash, c.data.Root)
		if err != nil {
			c.trie, _ = db.OpenStorageTrie(c.addrHash, common.Hash{})
			c.setError(fmt.Errorf("can't create storage trie: %v", err))
		}
	}
	return c.trie
}

// GetState retrieves a value from the account storage trie.
func (self *stateObject) GetState(db Database, key common.Hash) common.Hash {
	// If we have a dirty value for this state entry, return it
	value, dirty := self.dirtyStorage[key]
	if dirty {
		return value
	}
	// Otherwise return the entry's original value
	return self.GetCommittedState(db, key)
}

// GetCommittedState retrieves a value from the committed account storage trie.
func (self *stateObject) GetCommittedState(db Database, key common.Hash) common.Hash {
	// If we have the original value cached, return that
	value, cached := self.originStorage[key]
	if cached {
		return value
	}
	// Otherwise load the value from the database
	enc, err := self.getTrie(db).TryGet(key[:])
	if err != nil {
		self.setError(err)
		return common.Hash{}
	}
	if len(enc) > 0 {
		_, content, _, err := rlp.Split(enc)
		if err != nil {
			self.setError(err)
		}
		value.SetBytes(content)
	}
	self.originStorage[key] = value
	return value
}

// SetState updates a value in account storage.
func (self *stateObject) SetState(db Database, key, value common.Hash) {
	// If the new value is the same as old, don't set
	prev := self.GetState(db, key)
	if prev == value {
		return
	}
	// New value is different, update and journal the change
	self.db.journal.append(storageChange{
		account:  &self.address,
		key:      key,
		prevalue: prev,
	})
	self.setState(key, value)
}

func (self *stateObject) setState(key, value common.Hash) {
	self.dirtyStorage[key] = value
}

// updateTrie writes cached storage modifications into the object's storage trie.
func (self *stateObject) updateTrie(db Database) Trie {
	tr := self.getTrie(db)
	for key, value := range self.dirtyStorage {
		delete(self.dirtyStorage, key)

		// Skip noop changes, persist actual changes
		if value == self.originStorage[key] {
			continue
		}
		self.originStorage[key] = value

		if (value == common.Hash{}) {
			self.setError(tr.TryDelete(key[:]))
			continue
		}
		// Encoding []byte cannot fail, ok to ignore the error.
		v, _ := rlp.EncodeToBytes(bytes.TrimLeft(value[:], "\x00"))
		self.setError(tr.TryUpdate(key[:], v))
	}
	return tr
}

// UpdateRoot sets the trie root to the current root hash of
func (self *stateObject) updateRoot(db Database) {
	self.updateTrie(db)
	self.data.Root = self.trie.Hash()
}

// CommitTrie the storage trie of the object to db.
// This updates the trie root.
func (self *stateObject) CommitTrie(db Database) error {
	self.updateTrie(db)
	if self.dbErr != nil {
		return self.dbErr
	}
	root, err := self.trie.Commit(nil)
	if err == nil {
		self.data.Root = root
	}
	return err
}

// AddBalance removes amount from c's balance.
// It is used to add funds to the destination account of a transfer.
func (c *stateObject) AddBalance(amount *big.Int) {
	// EIP158: We must check emptiness for the objects such that the account
	// clearing (0,0,0 objects) can take effect.
	if amount.Sign() == 0 {
		if c.empty() {
			c.touch()
		}

		return
	}
	c.SetBalance(new(big.Int).Add(c.Balance(), amount))
}

func (c *stateObject) AddVoteRecord(amount *big.Int) {
	// EIP158: We must check emptiness for the objects such that the account
	// clearing (0,0,0 objects) can take effect.
	//if amount.Sign() == 0 {
	//	if c.empty() {
	//		c.touch()
	//	}
	//
	//	return
	//}
	c.SetVoteRecord(amount)
}

// SubBalance removes amount from c's balance.
// It is used to remove funds from the origin account of a transfer.
func (c *stateObject) SubBalance(amount *big.Int) {
	if amount.Sign() == 0 {
		return
	}
	c.SetBalance(new(big.Int).Sub(c.Balance(), amount))
}

func (self *stateObject) SetBalance(amount *big.Int) {
	self.db.journal.append(balanceChange{
		account: &self.address,
		prev:    new(big.Int).Set(self.data.Balance),
	})
	self.setBalance(amount)
}

func (self *stateObject) SetVoteRecord(amount *big.Int) {

	self.setVoteRecord(amount)
}

func (self *stateObject) setBalance(amount *big.Int) {
	self.data.Balance = amount
}

func (self *stateObject) setVoteRecord(amount *big.Int) {
	self.data.Voted = amount
}

//achilles MortgageNet add nets from c's resource
func (self *stateObject) MortgageNet(amount *big.Int, duration *big.Int, sTime big.Int, hash common.Hash) *big.Int {
	if amount.Sign() == 0 {
		return nil
	}
	netUse := self.db.ConvertToNets(amount)
	self.SetNet(self.UsedNet(), new(big.Int).Add(self.Net(), netUse), new(big.Int).Add(self.MortgageOfRes(), amount))

	mortgageStateObject := self.db.GetMortgageStateObject()
	//mortgage := new(big.Int).Add(mortgageStateObject.MortgageOfRes(), amount)
	//mortgageStateObject.SetNet(mortgageStateObject.UsedNet(), mortgageStateObject.Net(), mortgage)
	mortgageStateObject.AddBalance(amount)

	if duration.Cmp(big.NewInt(0)) > 0 {
		store := Store{
			Hash:               hash,
			StartHeight:        &sTime,
			LockHeights:        duration,
			Value:              amount,
			LastReceivedHeight: &sTime,
		}
		stores := append(self.data.Stores, store)
		regular := new(big.Int).Add(self.data.Regular, amount)
		self.SetStores(stores, regular)
	}

	if !(big.NewInt(0).Cmp(self.Date()) < 0) {
		self.SetDate(&sTime)
	}

	//2019.8.29 inb by ghy begin
	votes := self.data.Voted

	if votes.Cmp(big.NewInt(0)) == 1 && self.data.LastReceivedVoteRewardHeight.Cmp(big.NewInt(0)) == 1 {
		self.Vote(&sTime)
		HeightNow := sTime
		lastReceiveVoteAwardHeight := self.data.LastReceivedVoteRewardHeight
		if HeightNow.Cmp(lastReceiveVoteAwardHeight) != 1 {
			return netUse
		}
		fromLastReceiveVoteAwardTimeToNowHeight := new(big.Int).Sub(&HeightNow, lastReceiveVoteAwardHeight)
		cycles := new(big.Int).Div(fromLastReceiveVoteAwardTimeToNowHeight, common.VoteRewardCycleSecondsForChange)
		if cycles.Cmp(common.VoteRewardCycleTimesForChange) != -1 {
			votes1 := new(big.Int).Mul(votes, common.VoteDenominatorForChange)
			votes2 := new(big.Int).Div(votes1, common.VoteHundredForChange)
			votes3 := new(big.Int).Div(votes2, common.VoteNumberOfDaysOneYearForChange)
			value := new(big.Int).Mul(votes3, cycles)
			self.ReceiveVoteAward(value, &HeightNow)
		}
	}
	//2019.8.29 inb by ghy end
	return netUse
}

func (self *stateObject) ResetNet(update *big.Int) *big.Int {
	//available := new(big.Int).Sub(self.MortgageOfRes(), self.GetRedeem())
	netUse := self.db.ConvertToNets(self.MortgageOfRes())
	netUsed := big.NewInt(0)

	self.SetNet(netUsed, netUse, self.MortgageOfRes())
	self.SetDate(update)
	return netUse
}

//2019.7.22 inb by ghy begin
func (self *stateObject) CanReceiveLockedAward(nonce common.Hash, height *big.Int, consensus types.SpecialConsensus) (err error, value *big.Int, isAll bool) {
	if self.data.Voted.Cmp(big.NewInt(0)) != 1 {
		return errors.New("can only receive locked rewards after voting"), big.NewInt(0), false
	}
	if len(self.data.Stores) == 0 {
		return errors.New("no lock record"), big.NewInt(0), false
	}
	LockedRewardCycleHeight := new(big.Int)
	LockedRewardCycleTimes := new(big.Int)
	LockedDenominator := new(big.Int)
	LockedHundred := new(big.Int)
	LockedNumberOfDaysOneYear := new(big.Int)

	for _, v := range self.data.Stores {
		if nonce == v.Hash {
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
				return errors.New("unknow times"), big.NewInt(0), false
			}

			HeightNow := height

			startHeight := v.StartHeight

			lastReceivedHeight := v.LastReceivedHeight

			lockHeights := v.LockHeights

			endTimeHeight := new(big.Int).Add(startHeight, lockHeights)

			totalValue := v.Value
			receivedValue := v.Received

			if startHeight.Cmp(lastReceivedHeight) == 1 {
				return errors.New("last receipt time and start time error"), big.NewInt(0), false
			}
			if lastReceivedHeight.Cmp(HeightNow) == 1 {
				return errors.New("last receipt time error"), big.NewInt(0), false
			}
			if lastReceivedHeight.Cmp(endTimeHeight) == 1 {
				return errors.New("all the rewards are received"), big.NewInt(0), false
			}

			FromLastReceivedPassTimeHeight := new(big.Int).Sub(HeightNow, lastReceivedHeight)
			FromStartPassTimeHeight := new(big.Int).Sub(HeightNow, startHeight)

			if HeightNow.Cmp(endTimeHeight) >= 0 {
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
				return errors.New("have no rewards to received"), big.NewInt(0), false
			}

			if HeightNow.Cmp(endTimeHeight) == -1 && FromLastReceivedPassDays.Cmp(LockedRewardCycleTimes) == -1 {
				return errors.New("not block height to receive rewards"), big.NewInt(0), false
			}
			return nil, subValue, HeightNow.Cmp(endTimeHeight) >= 0
		}
	}
	return errors.New("no such lock record"), big.NewInt(0), false

}

func (self *stateObject) ReceiveLockedAward(nonce common.Hash, value *big.Int, isAll bool, height *big.Int) {

	if len(self.data.Stores) > 0 {
		for k, v := range self.data.Stores {
			if nonce == v.Hash {
				self.AddBalance(value)
				self.data.Stores[k].LastReceivedHeight = height
				if isAll {
					self.AddBalance(v.Value)

					afterRegular := new(big.Int).Sub(self.data.Regular, v.Value)
					self.data.Regular = afterRegular
					afterMortgagteINB := new(big.Int).Sub(self.data.Res.Mortgage, v.Value)
					self.data.Res.Mortgage = afterMortgagteINB

					self.data.Stores = append(self.data.Stores[:k], self.data.Stores[k+1:]...)

					mortgageStateObject := self.db.GetMortgageStateObject()
					if mortgageStateObject.Balance().Cmp(value) < 0 {
						return
					}
					//balance := new(big.Int).Sub(mortgageStateObject.MortgageOfRes(), value)
					mortgageStateObject.SubBalance(value)

				} else {

					//receiveAdd := v.Received.Int64() + int64(value)
					receiveAdd := new(big.Int).Add(v.Received, value)
					self.data.Stores[k].Received = receiveAdd
				}
			}
		}
	}
}

func (self *stateObject) CanReceiveVoteAward(height *big.Int) (err error, value *big.Int) {
	//account := pool.currentState.GetAccountInfo(from)
	votes := self.data.Voted
	if votes.Cmp(big.NewInt(0)) != 1 {
		return errors.New("please receive vote award after voting"), big.NewInt(0)

	}
	heightNow := height
	lastReceiveVoteAwardHeight := self.data.LastReceivedVoteRewardHeight
	if heightNow.Cmp(lastReceiveVoteAwardHeight) != 1 {
		return errors.New("please receive vote award after voting"), big.NewInt(0)
	}
	fromLastReceiveVoteAwardTimeToNowHeights := new(big.Int).Sub(heightNow, lastReceiveVoteAwardHeight)
	cycles := new(big.Int).Div(fromLastReceiveVoteAwardTimeToNowHeights, common.VoteRewardCycleSeconds)
	if cycles.Cmp(common.VoteRewardCycleTimes) != -1 {
		votes1 := new(big.Int).Mul(votes, common.VoteDenominator)
		votes2 := new(big.Int).Mul(votes1, cycles)
		votes3 := new(big.Int).Div(votes2, common.VoteHundred)
		value := new(big.Int).Div(votes3, common.VoteNumberOfDaysOneYear)
		return nil, value
	}
	return errors.New("not receive vote award time"), big.NewInt(0)
}

func (self *stateObject) ReceiveVoteAward(value *big.Int, height *big.Int) {
	self.data.LastReceivedVoteRewardHeight = height
	self.AddBalance(value)

}

func (self *stateObject) Vote(height *big.Int) {
	self.data.Voted = self.data.Res.Mortgage
	self.data.LastReceivedVoteRewardHeight = height
}

//2019.7.22 inb by ghy end

//achilles Redeem freeze inb of mortgaging from c's balance
func (self *stateObject) Redeem(amount *big.Int, sTime *big.Int) {
	if amount.Sign() == 0 {
		return
	}
	available := new(big.Int).Sub(self.MortgageOfRes(), self.Regular())
	available.Sub(available, self.GetRedeem())
	if available.Cmp(amount) < 0 {
		return
	}
	// freeze inb of redeeming
	mortgaging := new(big.Int).Sub(self.MortgageOfRes(), amount)
	self.SetNet(self.UsedNet(), self.Net(), mortgaging)

	redeem := Redeem{
		StartHeight: sTime,
		Value:       new(big.Int).Add(self.GetRedeem(), amount),
	}
	self.data.Redeems[0] = redeem
	self.SetRedeems(self.data.Redeems)
}

func (self *stateObject) Receive(sTime *big.Int) *big.Int {

	value := self.GetRedeem()
	redeem := Redeem{
		StartHeight: sTime,
		Value:       big.NewInt(0),
	}
	self.data.Redeems[0] = redeem
	self.SetRedeems(self.data.Redeems)

	self.AddBalance(value)
	mortgageStateObject := self.db.GetMortgageStateObject()
	if mortgageStateObject.Balance().Cmp(value) < 0 {
		return nil
	}
	//balance := new(big.Int).Sub(mortgageStateObject.MortgageOfRes(), value)
	mortgageStateObject.SubBalance(value)

	//2019.8.29 inb by ghy begin
	votes := self.data.Voted

	if votes.Cmp(big.NewInt(0)) == 1 && self.data.LastReceivedVoteRewardHeight.Cmp(big.NewInt(0)) == 1 {
		self.Vote(sTime)
		HeightNow := sTime
		lastReceiveVoteAwardHeight := self.data.LastReceivedVoteRewardHeight
		if HeightNow.Cmp(lastReceiveVoteAwardHeight) != 1 {
			return value
		}
		fromLastReceiveVoteAwardTimeToNowHeight := new(big.Int).Sub(HeightNow, lastReceiveVoteAwardHeight)
		cycles := new(big.Int).Div(fromLastReceiveVoteAwardTimeToNowHeight, common.VoteRewardCycleSecondsForChange)
		if cycles.Cmp(common.VoteRewardCycleTimesForChange) != -1 {
			votes1 := new(big.Int).Mul(votes, common.VoteDenominatorForChange)
			votes2 := new(big.Int).Div(votes1, common.VoteHundredForChange)
			votes3 := new(big.Int).Div(votes2, common.VoteNumberOfDaysOneYearForChange)
			value := new(big.Int).Mul(votes3, cycles)
			self.ReceiveVoteAward(value, HeightNow)
		}
	}
	//2019.8.29 inb by ghy end
	return value
}

func (self *stateObject) SetNet(usedAmount *big.Int, usableAmount *big.Int, mortgageInb *big.Int) {

	self.db.journal.append(netChange{
		account:      &self.address,
		Used:         new(big.Int).Set(self.data.Res.Used),
		Usableness:   new(big.Int).Set(self.data.Res.Usable),
		MortgagteINB: new(big.Int).Set(self.data.Res.Mortgage),
	})
	self.setNet(usedAmount, usableAmount, mortgageInb)
}

func (self *stateObject) setNet(usedAmount *big.Int, usableAmount *big.Int, mortgageInb *big.Int) {
	self.data.Res.Used = usedAmount
	self.data.Res.Usable = usableAmount
	self.data.Res.Mortgage = mortgageInb
}

func (self *stateObject) SetRedeems(redeems []Redeem) {
	self.db.journal.append(redeemChange{
		account: &self.address,
		redeems: self.data.Redeems,
	})
	self.setRedeems(redeems)
}

func (self *stateObject) setRedeems(redeems []Redeem) {
	self.data.Redeems = redeems
}

func (self *stateObject) SetDate(update *big.Int) {

	self.db.journal.append(dateChange{
		account: &self.address,
		prev:    new(big.Int).Set(self.data.Res.Height),
	})
	self.setDate(update)
}

func (self *stateObject) setDate(update *big.Int) {
	self.data.Res.Height = update
}

//achilles0718 regular mortgagtion
func (self *stateObject) SetStores(stores []Store, amount *big.Int) {
	self.db.journal.append(regularChange{
		account: &self.address,
		stores:  self.data.Stores,
		regular: new(big.Int).Set(self.data.Regular),
	})
	self.setStores(stores, amount)
}

func (self *stateObject) setStores(stores []Store, amount *big.Int) {
	self.data.Stores = stores
	self.data.Regular = amount
}

// Return the gas back to the origin. Used by the Virtual machine or Closures
func (c *stateObject) ReturnGas(gas *big.Int) {}

func (self *stateObject) deepCopy(db *StateDB) *stateObject {
	stateObject := newObject(db, self.address, self.data)
	if self.trie != nil {
		stateObject.trie = db.db.CopyTrie(self.trie)
	}
	stateObject.code = self.code
	stateObject.dirtyStorage = self.dirtyStorage.Copy()
	stateObject.originStorage = self.originStorage.Copy()
	stateObject.suicided = self.suicided
	stateObject.dirtyCode = self.dirtyCode
	stateObject.deleted = self.deleted
	return stateObject
}

//
// Attribute accessors
//

// Returns the address of the contract/account
func (c *stateObject) Address() common.Address {
	return c.address
}

// Code returns the contract code associated with this object, if any.
func (self *stateObject) Code(db Database) []byte {
	if self.code != nil {
		return self.code
	}
	if bytes.Equal(self.CodeHash(), emptyCodeHash) {
		return nil
	}
	code, err := db.ContractCode(self.addrHash, common.BytesToHash(self.CodeHash()))
	if err != nil {
		self.setError(fmt.Errorf("can't load code hash %x: %v", self.CodeHash(), err))
	}
	self.code = code
	return code
}

func (self *stateObject) SetCode(codeHash common.Hash, code []byte) {
	prevcode := self.Code(self.db.db)
	self.db.journal.append(codeChange{
		account:  &self.address,
		prevhash: self.CodeHash(),
		prevcode: prevcode,
	})
	self.setCode(codeHash, code)
}

func (self *stateObject) setCode(codeHash common.Hash, code []byte) {
	self.code = code
	self.data.CodeHash = codeHash[:]
	self.dirtyCode = true
}

func (self *stateObject) SetNonce(nonce uint64) {
	self.db.journal.append(nonceChange{
		account: &self.address,
		prev:    self.data.Nonce,
	})
	self.setNonce(nonce)
}

func (self *stateObject) setNonce(nonce uint64) {
	self.data.Nonce = nonce
}

func (self *stateObject) CodeHash() []byte {
	return self.data.CodeHash
}

func (self *stateObject) Balance() *big.Int {
	return self.data.Balance
}

//achilles0718 regular mortgagtion
func (self *stateObject) StoreLength() int {
	regulars := self.data.Stores
	return len(regulars)
}

//Resource by zc
func (self *stateObject) Net() *big.Int {
	return self.data.Res.Usable
}
func (self *stateObject) UsedNet() *big.Int {
	return self.data.Res.Used
}
func (self *stateObject) MortgageOfRes() *big.Int {
	return self.data.Res.Mortgage
}

func (self *stateObject) GetRedeem() *big.Int {
	return self.data.Redeems[0].Value
}

func (self *stateObject) GetRedeemTime() *big.Int {
	return self.data.Redeems[0].StartHeight
}

func (self *stateObject) Regular() *big.Int {
	return self.data.Regular
}

func (self *stateObject) Date() *big.Int {
	return self.data.Res.Height
}

//Resource by zc
func (self *stateObject) Nonce() uint64 {
	return self.data.Nonce
}

//2019.6.28 inb by ghy begin
func (self *stateObject) Resource() Resource {
	return self.data.Res
}

//
//func (self *stateObject) MortgageOfINB() *big.Int {
//	return self.data.Res.Mortgage
//}

//2019.6.28 inb by ghy end
// Never called, but must be present to allow stateObject to be used
// as a vm.Account interface that also satisfies the vm.ContractRef
// interface. Interfaces are awesome.
func (self *stateObject) Value() *big.Int {
	panic("Value on stateObject should never be called")
}
