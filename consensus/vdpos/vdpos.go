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
	"bytes"
	"errors"
	"math/big"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/insight-chain/inb-go/accounts"
	"github.com/insight-chain/inb-go/common"
	"github.com/insight-chain/inb-go/consensus"
	"github.com/insight-chain/inb-go/consensus/misc"
	"github.com/insight-chain/inb-go/core/state"
	"github.com/insight-chain/inb-go/core/types"
	"github.com/insight-chain/inb-go/crypto"
	"github.com/insight-chain/inb-go/crypto/sha3"
	"github.com/insight-chain/inb-go/ethdb"
	"github.com/insight-chain/inb-go/log"
	"github.com/insight-chain/inb-go/params"
	"github.com/insight-chain/inb-go/rlp"
	"github.com/insight-chain/inb-go/rpc"
)



// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	// errUnknownBlock is returned when the list of signers is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")

	// errMissingVanity is returned if a block's extra-data section is shorter than
	// 32 bytes, which is required to store the signer vanity.
	errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")

	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte suffix signature missing")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// ErrInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	ErrInvalidTimestamp = errors.New("invalid timestamp")

	// errInvalidVotingChain is returned if an authorization list is attempted to
	// be modified via out-of-range or non-contiguous headers.
	errInvalidVotingChain = errors.New("invalid voting chain")

	// errUnauthorizedSigner is returned if a header is signed by a non-authorized entity.
	errUnauthorizedSigner = errors.New("unauthorized signer")

	// errPunishedMissing is returned if a header calculate punished signer is wrong.
	errPunishedMissing = errors.New("punished signer missing")

	// errUnclesNotAllowed is returned if uncles exists
	errUnclesNotAllowed = errors.New("uncles not allowed")

	// errCreateSignersPoolNotAllowed is returned if called in (block number + 1) % maxSignerCount != 0
	errCreateSignersPoolNotAllowed = errors.New("create signers pool not allowed")

	// errInvalidSignersPool is returned if verify Signers fail
	errInvalidSignersPool = errors.New("invalid signers pool")

	// errSignersPoolEmpty is returned if no signer when calculate
	errSignersPoolEmpty = errors.New("signers pool is empty")

	// errMissingGenesisLightConfig is returned only in light syncmode if light config missing
	errMissingGenesisLightConfig = errors.New("light config in genesis is missing")

	// errIncorrectTallyCount is used in snapshot.go
	errIncorrectTallyCount = errors.New("incorrect tally count")
)

// SignerFn is a signer callback function to request a hash to be signed by a
// backing account.
type SignerFn func(accounts.Account, []byte) ([]byte, error)

// SignTxFn is a signTx
type SignTxFn func(accounts.Account, *types.Transaction, *big.Int) (*types.Transaction, error)

type Vdpos struct {
	config     *params.VdposConfig // Consensus engine configuration parameters
	db         ethdb.Database      // Database to store and retrieve snapshot checkpoints
	recents    *lru.ARCCache       // Snapshots for recent block to speed up reorgs
	signatures *lru.ARCCache       // Signatures of recent blocks to speed up mining
	signer     common.Address      // Ethereum address of the signing key
	signFn     SignerFn            // Signer function to authorize hashes with
	signTxFn   SignTxFn            // Sign transaction function to sign tx
	lock       sync.RWMutex        // Protects the signer fields
}

// New creates a Vdpos delegated-proof-of-stake consensus engine with the initial
// signers set to the ones provided by the user.
func New(config *params.VdposConfig, db ethdb.Database) *Vdpos {
	// Set any missing consensus parameters to their defaults
	conf := *config
	if conf.Epoch == 0 {
		conf.Epoch = defaultEpochLength
	}
	if conf.Period == 0 {
		conf.Period = defaultBlockPeriod
	}
	if conf.SignerPeriod == 0 {
		conf.SignerPeriod = defaultSignerPeriod
	}
	if conf.SignerBlocks == 0 {
		conf.SignerBlocks = defaultSignerBlocks
	}
	if conf.MaxSignerCount == 0 {
		conf.MaxSignerCount = defaultMaxSignerCount
	}
	if conf.MinVoterBalance.Uint64() > 0 {
		minVoterBalance = conf.MinVoterBalance
	}

	// Allocate the snapshot caches and create the engine
	recents, _ := lru.NewARC(inMemorySnapshots)
	signatures, _ := lru.NewARC(inMemorySignatures)

	return &Vdpos{
		config:     &conf,
		db:         db,
		recents:    recents,
		signatures: signatures,
	}
}

// Author implements consensus.Engine, returning the Ethereum address recovered
// from the signature in the header's extra-data section.
func (v *Vdpos) Author(header *types.Header) (common.Address, error) {
	return ecrecover(header, v.signatures)
}

// VerifyHeader checks whether a header conforms to the consensus rules.
func (v *Vdpos) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	return v.verifyHeader(chain, header, nil)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).
func (v *Vdpos) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := v.verifyHeader(chain, header, headers[:i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()

	return abort, results
}

// verifyHeader checks whether a header conforms to the consensus rules.The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
func (v *Vdpos) verifyHeader(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	if header.Number == nil {
		return errUnknownBlock
	}

	// Don't waste time checking blocks from the future
	if header.Time.Cmp(big.NewInt(time.Now().Unix())) > 0 {
		return consensus.ErrFutureBlock
	}

	// Check that the extra-data contains both the vanity and signature
	if len(header.Extra) < extraVanity {
		return errMissingVanity
	}
	if len(header.Extra) < extraVanity+extraSeal {
		return errMissingSignature
	}

	// Ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}

	// Ensure that the block doesn't contain any uncles which are meaningless in Vdpos
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}

	// If all checks passed, validate any special fields for hard forks
	if err := misc.VerifyForkHashes(chain.Config(), header, false); err != nil {
		return err
	}

	// All basic checks passed, verify cascading fields
	return v.verifyCascadingFields(chain, header, parents)
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (v *Vdpos) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errUnclesNotAllowed
	}
	return nil
}

// VerifySeal implements consensus.Engine, checking whether the signature contained
// in the header satisfies the consensus protocol requirements.
func (v *Vdpos) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	return v.verifySeal(chain, header, nil)
}

// verifySeal checks whether the signature contained in the header satisfies the
// consensus protocol requirements. The method accepts an optional list of parent
// headers that aren't yet part of the local blockchain to generate the snapshots
// from.
func (v *Vdpos) verifySeal(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	// Verifying the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}

	// Retrieve the snapshot needed to verify this header and cache it
	snap, err := v.snapshot(chain, number-1, header.ParentHash, parents, nil, defaultLoopCntRecalculateSigners)
	if err != nil {
		return err
	}

	// Resolve the authorization key and check against signers
	signer, err := ecrecover(header, v.signatures)
	if err != nil {
		return err
	}

	if number > v.config.MaxSignerCount*v.config.SignerBlocks {
		var parent *types.Header
		if len(parents) > 0 {
			parent = parents[len(parents)-1]
		} else {
			parent = chain.GetHeader(header.ParentHash, number-1)
		}
		parentHeaderExtra := HeaderExtra{}
		err = decodeHeaderExtra(parent.Extra[extraVanity:len(parent.Extra)-extraSeal], &parentHeaderExtra)
		if err != nil {
			log.Info("Fail to decode parent header", "err", err)
			return err
		}
		currentHeaderExtra := HeaderExtra{}
		err = decodeHeaderExtra(header.Extra[extraVanity:len(header.Extra)-extraSeal], &currentHeaderExtra)
		if err != nil {
			log.Info("Fail to decode header", "err", err)
			return err
		}
		// verify SignersPool
		if number%(v.config.MaxSignerCount*v.config.SignerBlocks) == 0 {
			err := snap.verifySignersPool(currentHeaderExtra.SignersPool)
			if err != nil {
				return err
			}
		} else {
			for i := 0; i < int(v.config.MaxSignerCount); i++ {
				if parentHeaderExtra.SignersPool[i] != currentHeaderExtra.SignersPool[i] {
					return errInvalidSignersPool
				}
			}
			//if signer == parent.Coinbase && header.Time.Uint64()-parent.Time.Uint64() < chain.Config().Vdpos.Period {
			//	return errInvalidNeighborSigner
			//}
		}

		// verify missing signer for punish
		newLoop := false
		if number%(v.config.MaxSignerCount*v.config.SignerBlocks) == 0 {
			newLoop = true
		}
		parentSignerMissing := v.getSignerMissing(parent.Coinbase, header.Coinbase, parentHeaderExtra, newLoop)
		if len(parentSignerMissing) != len(currentHeaderExtra.SignerMissing) {
			return errPunishedMissing
		}
		for i, signerMissing := range currentHeaderExtra.SignerMissing {
			if parentSignerMissing[i] != signerMissing {
				return errPunishedMissing
			}
		}
	}

	if !snap.inturn(signer, header.Time.Uint64()) {
		return errUnauthorizedSigner
	}
	return nil
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (v *Vdpos) Prepare(chain consensus.ChainReader, header *types.Header) error {

	// Set the correct difficulty
	header.Difficulty = new(big.Int).Set(defaultDifficulty)

	if v.config.GenesisTimestamp < uint64(time.Now().Unix()) {
		return nil
	}

	// waiting for start
	if header.Number.Uint64() == 1 {
		for {
			delay := time.Unix(int64(v.config.GenesisTimestamp), 0).Sub(time.Now())
			if delay <= time.Duration(0) {
				log.Info("Ready for seal block", "time", time.Now())
				break
			} else if delay > time.Duration(v.config.Period*v.config.SignerBlocks)*time.Second {
				delay = time.Duration(v.config.Period*v.config.SignerBlocks) * time.Second
			}
			log.Info("Waiting for seal block", "delay", common.PrettyDuration(time.Unix(int64(v.config.GenesisTimestamp), 0).Sub(time.Now())))
			select {
			case <-time.After(delay):
				continue
			}
		}
	}

	return nil
}

// Finalize implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given, and returns the final block.
func (v *Vdpos) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {

	number := header.Number.Uint64()

	// Mix digest is reserved for now, set to empty
	header.MixDigest = common.Hash{}

	// Ensure the timestamp has the correct delay
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return nil, consensus.ErrUnknownAncestor
	}

	//TODO if config.Period != config.SignerPeriod how to do
	header.Time = new(big.Int).Add(parent.Time, new(big.Int).SetUint64(v.config.Period))
	if header.Time.Int64() < time.Now().Unix() {
		header.Time = big.NewInt(time.Now().Unix())
	}

	// Ensure the extra data has all it's components
	if len(header.Extra) < extraVanity {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, extraVanity-len(header.Extra))...)
	}
	header.Extra = header.Extra[:extraVanity]

	// genesisVotes write direct into snapshot, which number is 1
	var genesisVotes []*Vote
	parentHeaderExtra := HeaderExtra{}
	currentHeaderExtra := HeaderExtra{}

	if number == 1 {
		alreadyVote := make(map[common.Address]struct{})
		for _, unPrefixVoter := range v.config.SelfVoteSigners {
			voter := common.Address(unPrefixVoter)
			if _, ok := alreadyVote[voter]; !ok {
				genesisVotes = append(genesisVotes, &Vote{
					Voter:     voter,
					Candidate: voter,
					Stake:     state.GetBalance(voter),
				})
				alreadyVote[voter] = struct{}{}
			}
		}
	} else {
		// decode extra from last header.extra
		err := decodeHeaderExtra(parent.Extra[extraVanity:len(parent.Extra)-extraSeal], &parentHeaderExtra)
		if err != nil {
			log.Info("Fail to decode parent header", "err", err)
			return nil, err
		}
		currentHeaderExtra.ConfirmedBlockNumber = parentHeaderExtra.ConfirmedBlockNumber
		currentHeaderExtra.SignersPool = parentHeaderExtra.SignersPool
		currentHeaderExtra.LoopStartTime = parentHeaderExtra.LoopStartTime
		newLoop := false
		if number%(v.config.MaxSignerCount*v.config.SignerBlocks) == 0 {
			newLoop = true
		}
		currentHeaderExtra.SignerMissing = v.getSignerMissing(parent.Coinbase, header.Coinbase, parentHeaderExtra, newLoop)
	}

	// Assemble the voting snapshot to check which votes make sense
	snap, err := v.snapshot(chain, number-1, header.ParentHash, nil, genesisVotes, defaultLoopCntRecalculateSigners)
	if err != nil {
		return nil, err
	}

	// calculate votes write into header.extra
	midCurrentHeaderExtra, _, err := v.processCustomTx(currentHeaderExtra, chain, header, state, txs, receipts)
	if err != nil {
		return nil, err
	}
	currentHeaderExtra = midCurrentHeaderExtra
	currentHeaderExtra.ConfirmedBlockNumber = snap.getLastConfirmedBlockNumber(currentHeaderExtra.CurrentBlockConfirmations).Uint64()
	// write signersPool in first header, from self vote signers in genesis block
	// we must decide the signers order here first
	if number == 1 {
		currentHeaderExtra.LoopStartTime = v.config.GenesisTimestamp
		if len(v.config.SelfVoteSigners) > 0 {
			for i := 0; i < int(v.config.MaxSignerCount); i++ {
				currentHeaderExtra.SignersPool = append(currentHeaderExtra.SignersPool, common.Address(v.config.SelfVoteSigners[i%len(v.config.SelfVoteSigners)]))
			}
		}
	} else if number%(v.config.MaxSignerCount*v.config.SignerBlocks) == 0 {
		//currentHeaderExtra.LoopStartTime = header.Time.Uint64()
		currentHeaderExtra.LoopStartTime += v.config.Period * v.config.MaxSignerCount * v.config.SignerBlocks
		// create random signersPool in currentHeaderExtra by snapshot.Tally
		currentHeaderExtra.SignersPool = []common.Address{}
		newSignersPool, err := snap.createSignersPool()
		if err != nil {
			return nil, err
		}
		currentHeaderExtra.SignersPool = newSignersPool
	}

	// Accumulate any block rewards and commit the final state root
	v.accumulateRewards(chain.Config(), state, header)

	// encode header.extra
	currentHeaderExtraEnc, err := encodeHeaderExtra(currentHeaderExtra)
	if err != nil {
		return nil, err
	}

	header.Extra = append(header.Extra, currentHeaderExtraEnc...)
	header.Extra = append(header.Extra, make([]byte, extraSeal)...)

	// Set the correct difficulty
	header.Difficulty = new(big.Int).Set(defaultDifficulty)

	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))

	// No uncle block
	header.UncleHash = types.CalcUncleHash(nil)

	// Assemble and return the final block for sealing
	return types.NewBlock(header, txs, nil, receipts), nil
}

// Authorize injects a private key into the consensus engine to mint new blocks
// with.
func (v *Vdpos) Authorize(signer common.Address, signFn SignerFn, signTxFn SignTxFn) {
	v.lock.Lock()
	defer v.lock.Unlock()

	v.signer = signer
	v.signFn = signFn
	v.signTxFn = signTxFn
}

// Seal implements consensus.Engine, attempting to create a sealed block using
// the local signing credentials.
func (v *Vdpos) Seal(chain consensus.ChainReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	header := block.Header()

	// Sealing the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}

	// For 0-period chains, refuse to seal empty blocks (no reward but would spin sealing)
	if v.config.Period == 0 && len(block.Transactions()) == 0 {
		log.Info("Sealing paused, waiting for transactions")
		return nil
	}
	// Don't hold the signer fields for the entire sealing procedure
	v.lock.RLock()
	signer, signFn := v.signer, v.signFn
	v.lock.RUnlock()

	// Bail out if we're unauthorized to sign a block
	snap, err := v.snapshot(chain, number-1, header.ParentHash, nil, nil, defaultLoopCntRecalculateSigners)
	if err != nil {
		return err
	}

	if !snap.inturn(signer, header.Time.Uint64()) {
		//<-stop
		return errUnauthorizedSigner
	}

	// correct the time
	delay := time.Unix(header.Time.Int64(), 0).Sub(time.Now())

	//select {
	//case <-stop:
	//	return nil
	//case <-time.After(delay):
	//}

	// Sign all the things!
	headerSigHash := sigHash(header)

	sighash, err := signFn(accounts.Account{Address: signer}, headerSigHash.Bytes())
	if err != nil {
		return err
	}

	copy(header.Extra[len(header.Extra)-extraSeal:], sighash)

	// Wait until sealing is terminated or delay timeout.
	log.Trace("Waiting for slot to sign and propagate", "delay", common.PrettyDuration(delay))
	go func() {
		select {
		case <-stop:
			return
		case <-time.After(delay):
		}

		select {
		case results <- block.WithSeal(header):
		default:
			log.Warn("Sealing result is not read by miner", "sealhash", headerSigHash)
		}
	}()

	return nil
}

// SealHash returns the hash of a block prior to it being sealed.
func (v *Vdpos) SealHash(header *types.Header) common.Hash {
	return sigHash(header)
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have.
// In Vdpos just return 1.
func (v *Vdpos) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	return new(big.Int).Set(defaultDifficulty)
}

// APIs implements consensus.Engine, returning the user facing RPC API to allow
// controlling the signer voting.
func (v *Vdpos) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{
		{
			Namespace: "eth",
			Version:   "1.0",
			Service:   &API{chain: chain, vdpos: v},
			Public:    true,
		},
		{
			Namespace: "vdpos",
			Version:   "1.0",
			Service:   &API{chain: chain, vdpos: v},
			Public:    true,
		},
	}
}

// Close implements consensus.Engine. It's a noop for vdpos as there are no background threads.
func (v *Vdpos) Close() error {
	return nil
}

// sigHash returns the hash which is used as input for the proof-of-authority
// signing. It is the hash of the entire header apart from the 65 byte signature
// contained at the end of the extra data.
//
// Note, the method requires the extra data to be at least 65 bytes, otherwise it
// panics. This is done to avoid accidentally using both forms (signature present
// or not), which could be abused to produce different hashes for the same header.
func sigHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewKeccak256()

	err := rlp.Encode(hasher, []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:len(header.Extra)-65], // Yes, this will panic if extra is too short
		header.MixDigest,
		header.Nonce,
	})
	if err != nil {
		return common.Hash{}
	}
	hasher.Sum(hash[:0])
	return hash
}

// ecrecover extracts the Ethereum account address from a signed header.
func ecrecover(header *types.Header, sigcache *lru.ARCCache) (common.Address, error) {
	// If the signature's already cached, return that
	hash := header.Hash()
	if address, known := sigcache.Get(hash); known {
		return address.(common.Address), nil
	}
	// Retrieve the signature from the header extra-data
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]

	// Recover the public key and the Ethereum address
	headerSigHash := sigHash(header)
	pubkey, err := crypto.Ecrecover(headerSigHash.Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	sigcache.Add(hash, signer)
	return signer, nil
}

// snapshot retrieves the authorization snapshot at a given point in time.
func (v *Vdpos) snapshot(chain consensus.ChainReader, number uint64, hash common.Hash, parents []*types.Header, genesisVotes []*Vote, lcrs uint64) (*Snapshot, error) {
	// Search for a snapshot in memory or on disk for checkpoints
	var (
		headers []*types.Header
		snap    *Snapshot
	)

	for snap == nil {
		// If an in-memory snapshot was found, use that
		if s, ok := v.recents.Get(hash); ok {
			snap = s.(*Snapshot)
			break
		}
		// If an on-disk checkpoint snapshot can be found, use that
		if number%checkpointInterval == 0 {
			if s, err := loadSnapshot(v.config, v.signatures, v.db, hash); err == nil {
				log.Trace("Loaded voting snapshot from disk", "number", number, "hash", hash)
				snap = s
				break
			}
		}

		// If we're at an checkpoint block, make a snapshot if it's known
		if number == 0 || (number%v.config.Epoch == 0 && chain.GetHeaderByNumber(number-1) == nil) {
			checkpoint := chain.GetHeaderByNumber(number)
			if checkpoint != nil {
				if err := v.VerifyHeader(chain, checkpoint, false); err != nil {
					return nil, err
				}
				hash := checkpoint.Hash()
				v.config.Period = chain.Config().Vdpos.Period
				snap = newSnapshot(v.config, v.signatures, hash, genesisVotes, lcrs)
				if err := snap.store(v.db); err != nil {
					return nil, err
				}
				log.Trace("Stored checkpoint snapshot to disk", "number", number, "hash", hash)
				break
			}
		}

		// No snapshot for this header, gather the header and move backward
		var header *types.Header
		if len(parents) > 0 {
			// If we have explicit parents, pick from there (enforced)
			header = parents[len(parents)-1]
			if header.Hash() != hash || header.Number.Uint64() != number {
				return nil, consensus.ErrUnknownAncestor
			}
			parents = parents[:len(parents)-1]
		} else {
			// No explicit parents (or no more left), reach out to the database
			header = chain.GetHeader(hash, number)
			if header == nil {
				return nil, consensus.ErrUnknownAncestor
			}
		}
		headers = append(headers, header)
		number, hash = number-1, header.ParentHash
	}
	// Previous snapshot found, apply any pending headers on top of it
	for i := 0; i < len(headers)/2; i++ {
		headers[i], headers[len(headers)-1-i] = headers[len(headers)-1-i], headers[i]
	}

	snap, err := snap.apply(headers)
	if err != nil {
		return nil, err
	}

	v.recents.Add(snap.Hash, snap)

	// If we've generated a new checkpoint snapshot, save to disk
	if snap.Number%checkpointInterval == 0 && len(headers) > 0 {
		if err = snap.store(v.db); err != nil {
			return nil, err
		}
		log.Trace("Stored voting snapshot to disk", "number", snap.Number, "hash", snap.Hash)
	}
	return snap, err
}

// verifyCascadingFields verifies all the header fields that are not standalone,
// rather depend on a batch of previous headers. The caller may optionally pass
// in a batch of parents (ascending order) to avoid looking those up from the
// database. This is useful for concurrently verifying a batch of new headers.
func (v *Vdpos) verifyCascadingFields(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	// The genesis block is the always valid dead-end
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}
	// Ensure that the block's timestamp isn't too close to it's parent
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}

	//TODO if config.Period != config.SignerPeriod,how to check the block is the last one of the conf.SignerBlocks
	if parent.Time.Uint64()+v.config.Period > header.Time.Uint64() {
		return ErrInvalidTimestamp
	}
	// Retrieve the snapshot needed to verify this header and cache it
	_, err := v.snapshot(chain, number-1, header.ParentHash, parents, nil, defaultLoopCntRecalculateSigners)
	if err != nil {
		return err
	}

	// All basic checks passed, verify the seal and return
	return v.verifySeal(chain, header, parents)
}

func (v *Vdpos) ApplyGenesis(chain consensus.ChainReader, genesisHash common.Hash) error {
	if v.config.LightConfig != nil {
		var genesisVotes []*Vote
		alreadyVote := make(map[common.Address]struct{})
		for _, unPrefixVoter := range v.config.SelfVoteSigners {
			voter := common.Address(unPrefixVoter)
			if genesisAccount, ok := v.config.LightConfig.Alloc[unPrefixVoter]; ok {
				if _, ok := alreadyVote[voter]; !ok {
					stake := new(big.Int)
					stake.UnmarshalText([]byte(genesisAccount.Balance))
					genesisVotes = append(genesisVotes, &Vote{
						Voter:     voter,
						Candidate: voter,
						Stake:     stake,
					})
					alreadyVote[voter] = struct{}{}
				}
			}
		}
		// Assemble the voting snapshot to check which votes make sense
		if _, err := v.snapshot(chain, 0, genesisHash, nil, genesisVotes, defaultLoopCntRecalculateSigners); err != nil {
			return err
		}
		return nil
	}
	return errMissingGenesisLightConfig
}

// accumulateRewards credits the coinbase of the given block with the mining reward.
func (v *Vdpos) accumulateRewards(config *params.ChainConfig, state *state.StateDB, header *types.Header) {
	reward := new(big.Int).Set(defaultMinerReward)
	if reward.Cmp(big.NewInt(0)) > 0 {
		state.AddBalance(header.Coinbase, reward)
	}
}

// Get the signer missing from last signer till header.Coinbase
func (v *Vdpos) getSignerMissing(lastSigner common.Address, currentSigner common.Address, extra HeaderExtra, newLoop bool) []common.Address {

	var signerMissing []common.Address

	if newLoop {
		for i, qlen := 0, len(extra.SignersPool); i < len(extra.SignersPool); i++ {
			if lastSigner == extra.SignersPool[qlen-1-i] {
				break
			} else {
				signerMissing = append(signerMissing, extra.SignersPool[qlen-1-i])
			}
		}
	} else {
		recordMissing := false
		for _, signer := range extra.SignersPool {
			if signer == lastSigner {
				recordMissing = true
				continue
			}
			if signer == currentSigner {
				break
			}
			if recordMissing {
				signerMissing = append(signerMissing, signer)
			}
		}

	}

	return signerMissing
}
