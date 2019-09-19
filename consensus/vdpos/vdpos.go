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

	"github.com/hashicorp/golang-lru"
	"github.com/insight-chain/inb-go/accounts"
	"github.com/insight-chain/inb-go/common"
	"github.com/insight-chain/inb-go/consensus"
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

const (
	inMemorySnapshots  = 128  // Number of recent vote snapshots to keep in memory
	inMemorySignatures = 4096 // Number of recent block signatures to keep in memory
)

var (
	DefaultInbIncreaseOneYear1       = new(big.Int).Mul(big.NewInt(2e+8), big.NewInt(1e+18))
	DefaultInbIncreaseOneYear        = new(big.Int).Mul(big.NewInt(2e+8), big.NewInt(params.Inber))
	OneYearBySec                     = int64(365 * 86400)
	defaultBlockPeriod               = uint64(2)                                                      // default minimum difference between two consecutive block's timestamps
	defaultSignerPeriod              = uint64(2)                                                      // default minimum difference between two signer's timestamps
	defaultSignerBlocks              = uint64(6)                                                      // default number of blocks every signer created
	defaultMaxSignerCount            = uint64(21)                                                     // default max signers
	extraVanity                      = 32                                                             // fixed number of extra-data prefix bytes reserved for signer vanity
	extraSeal                        = 65                                                             // fixed number of extra-data suffix bytes reserved for signer seal
	uncleHash                        = types.CalcUncleHash(nil)                                       // always Keccak256(RLP([])) as uncles are meaningless outside of PoW.
	defaultDifficulty                = big.NewInt(1)                                                  // default difficulty
	defaultLoopCntRecalculateSigners = uint64(350)                                                    // default loop count to recreate signers from top tally
	selfVoteSignersStake1            = new(big.Int).Mul(big.NewInt(500000), big.NewInt(1e+18))        // default stake of selfVoteSigners in first LOOP
	selfVoteSignersStake             = new(big.Int).Mul(big.NewInt(500000), big.NewInt(params.Inber)) // default stake of selfVoteSigners in first LOOP
	DefaultMinerReward1              = big.NewInt(6341958396752917300)                                // default reward for miner in wei
	DefaultMinerReward               = big.NewInt(634195)                                             // default reward for miner in wei
	BeVotedNeedINB1                  = new(big.Int).Mul(big.NewInt(100000), big.NewInt(1e+18))        // default min mortgage INB of candidates
	BeVotedNeedINB                   = new(big.Int).Mul(big.NewInt(100000), big.NewInt(params.Inber)) // default min mortgage INB of candidates

)

// various error messages to mark blocks invalid. These should be private to
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

	// errUnauthorizedSigner is returned if a header is signed by a non-authorized entity.
	errUnauthorizedSigner = errors.New("unauthorized signer")

	// errUnclesNotAllowed is returned if uncles exists
	errUnclesNotAllowed = errors.New("uncles not allowed")

	// errCreateSignersPoolNotAllowed is returned if called in (block number + 1) % maxSignerCount != 0
	errCreateSignersPoolNotAllowed = errors.New("create signers pool not allowed")

	// errInvalidSignersPool is returned if verify Signers fail
	errInvalidSignersPool = errors.New("invalid signers pool")

	// errSignersPoolEmpty is returned if no signer when calculate
	//errSignersPoolEmpty = errors.New("signers pool is empty")
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
	// set any missing consensus parameters to their defaults
	conf := *config
	if conf.Period == 0 {
		conf.Period = defaultBlockPeriod
	}
	if conf.SignerPeriod == 0 {
		conf.SignerPeriod = defaultSignerPeriod
	}
	if conf.SignerBlocks == 0 {
		conf.SignerBlocks = defaultSignerBlocks
	}
	if conf.LoopCntRecalculate == 0 {
		conf.LoopCntRecalculate = defaultLoopCntRecalculateSigners
	}
	if conf.MaxSignerCount == 0 {
		conf.MaxSignerCount = defaultMaxSignerCount
	}

	// allocate the snapshot caches and create the engine
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

	// don't waste time checking blocks from the future
	if header.Time.Cmp(big.NewInt(time.Now().Unix())) > 0 {
		return consensus.ErrFutureBlock
	}

	// check that the extra-data contains both the vanity and signature
	if len(header.Extra) < extraVanity {
		return errMissingVanity
	}
	if len(header.Extra) < extraVanity+extraSeal {
		return errMissingSignature
	}

	// ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}

	// ensure that the block doesn't contain any uncles which are meaningless in Vdpos
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}

	// If all checks passed, validate any special fields for hard forks
	//if err := misc.VerifyForkHashes(chain.Config(), header, false); err != nil {
	//	return err
	//}

	// all basic checks passed, verify cascading fields
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

	// resolve the authorization key and check against signers
	signer, err := ecrecover(header, v.signatures)
	if err != nil {
		return err
	}

	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	vdposContext, err := types.NewVdposContextFromProto(v.db, parent.VdposContext)
	if err != nil {
		return err
	}
	db, err := chain.StateAt(parent.Root)
	if err != nil {
		return err
	}
	snapContext := v.snapContext(v.config, db, parent, vdposContext, nil)

	if number > v.config.MaxSignerCount*v.config.SignerBlocks {
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
			snapContext.SignersPool = parentHeaderExtra.SignersPool
			err := snapContext.verifySignersPool(currentHeaderExtra.SignersPool)
			if err != nil {
				return err
			}
		} else {
			for i := 0; i < int(v.config.MaxSignerCount); i++ {
				if parentHeaderExtra.SignersPool[i] != currentHeaderExtra.SignersPool[i] {
					return errInvalidSignersPool
				}
			}
		}
	}

	if !snapContext.inturn(signer, header, parent) {
		return errUnauthorizedSigner
	}
	return nil
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (v *Vdpos) Prepare(chain consensus.ChainReader, header *types.Header) error {
	// set the correct difficulty
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
func (v *Vdpos) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt, vdposContext *types.VdposContext) (*types.Block, error) {

	number := header.Number.Uint64()

	// mix digest is reserved for now, set to empty
	header.MixDigest = common.Hash{}

	// ensure the timestamp has the correct delay
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return nil, consensus.ErrUnknownAncestor
	}
	header.SpecialConsensus = parent.SpecialConsensus //2019.7.23 inb by ghy
	// handle config.Period != config.SignerPeriod
	if (number-1)%v.config.SignerBlocks == 0 {
		header.Time = new(big.Int).Add(parent.Time, new(big.Int).SetUint64(v.config.SignerPeriod))
	} else {
		header.Time = new(big.Int).Add(parent.Time, new(big.Int).SetUint64(v.config.Period))
	}

	if header.Time.Int64() < time.Now().Unix() {
		header.Time = big.NewInt(time.Now().Unix())
	}

	// ensure the extra data has all it's components
	if len(header.Extra) < extraVanity {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, extraVanity-len(header.Extra))...)
	}
	header.Extra = header.Extra[:extraVanity]

	parentHeaderExtra := HeaderExtra{}
	currentHeaderExtra := HeaderExtra{}
	// when number is 1, we must update the voteTrie by config.SelfVoteSigners
	if number == 1 {
		alreadyVote := make(map[common.Address]struct{})
		for _, unPrefixVoter := range v.config.SelfVoteSigners {
			voter := common.Address(unPrefixVoter)
			//achilles vote
			candidates := []common.Address{voter}
			if _, ok := alreadyVote[voter]; !ok {
				vote := &types.Votes{
					Voter:     voter,
					Candidate: candidates,
					Stake:     selfVoteSignersStake,
					//Stake: big.NewInt(1),
				}
				vdposContext.UpdateTallysByVotes(vote)
				vdposContext.UpdateVotes(vote)
				alreadyVote[voter] = struct{}{}
			}
		}
		for _, v := range v.config.Enodes {
			enode := new(common.EnodeInfo)
			enode.Address = v.Address
			enode.Port = v.Port
			enode.Ip = v.Ip
			enode.Id = v.Id
			currentHeaderExtra.Enodes = append(currentHeaderExtra.Enodes, *enode)
		}
		//currentHeaderExtra.Enodes = v.config.Enodes
	} else {
		// decode extra from last header.extra
		err := decodeHeaderExtra(parent.Extra[extraVanity:len(parent.Extra)-extraSeal], &parentHeaderExtra)
		if err != nil {
			log.Error("Fail to decode parent header", "err", err)
			return nil, err
		}
		currentHeaderExtra.ConfirmedBlockNumber = parentHeaderExtra.ConfirmedBlockNumber
		currentHeaderExtra.SignersPool = parentHeaderExtra.SignersPool
		currentHeaderExtra.LoopStartTime = parentHeaderExtra.LoopStartTime
		currentHeaderExtra.Enodes = parentHeaderExtra.Enodes
	}

	snapContext := v.snapContext(v.config, state, parent, vdposContext, parentHeaderExtra.SignersPool)

	// calculate votes write into header.extra
	midCurrentHeaderExtra, err := v.processCustomTx(currentHeaderExtra, chain, header, state, txs, vdposContext)
	if err != nil {
		return nil, err
	}
	currentHeaderExtra = midCurrentHeaderExtra
	currentHeaderExtra.ConfirmedBlockNumber = snapContext.getLastConfirmedBlockNumber().Uint64()
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
		//currentHeaderExtra.LoopStartTime += v.config.Period * v.config.MaxSignerCount * v.config.SignerBlocks
		// handle config.Period != config.SignerPeriod
		currentHeaderExtra.LoopStartTime += (v.config.Period*(v.config.SignerBlocks-1) + v.config.SignerPeriod) * v.config.MaxSignerCount
		// create random signersPool in currentHeaderExtra
		currentHeaderExtra.SignersPool = []common.Address{}
		newSignersPool, err := snapContext.createSignersPool()
		if err != nil {
			log.Error("err", err)
			return nil, err
		}
		currentHeaderExtra.SignersPool = newSignersPool
	}

	// accumulate any block rewards and commit the final state root
	//v.accumulateRewards(chain.Config(), state, header)

	// encode header.extra
	currentHeaderExtraEnc, err := encodeHeaderExtra(currentHeaderExtra)
	if err != nil {

		return nil, err
	}

	header.Extra = append(header.Extra, currentHeaderExtraEnc...)
	header.Extra = append(header.Extra, make([]byte, extraSeal)...)

	// set the correct difficulty
	header.Difficulty = new(big.Int).Set(defaultDifficulty)

	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))

	// no uncle block
	header.UncleHash = types.CalcUncleHash(nil)

	header.VdposContext = vdposContext.ToProto()

	//inb by ghy begin
	header.Reward = DefaultMinerReward.String()
	//inb by ghy end
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

	// sealing the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}

	// for 0-period chains, refuse to seal empty blocks (no reward but would spin sealing)
	//if v.config.Period == 0 && len(block.Transactions()) == 0 {
	//	log.Info("Sealing paused, waiting for transactions")
	//	return nil
	//}

	//2019.9.6 inb by ghy begin
	if len(block.Transactions()) == 0 {
		log.Debug("Sealing paused, waiting for transactions")
		return nil
	}
	//2019.9.6 inb by ghy end

	// don't hold the signer fields for the entire sealing procedure
	v.lock.RLock()
	signer, signFn := v.signer, v.signFn
	v.lock.RUnlock()

	// bail out if we're unauthorized to sign a block
	parent := chain.GetHeader(header.ParentHash, number-1)

	vdposContext, err := types.NewVdposContextFromProto(v.db, parent.VdposContext)
	if err != nil {
		return err
	}
	snapContext := v.snapContext(v.config, nil, parent, vdposContext, nil)

	if !snapContext.inturn(signer, header, parent) {
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

	// sign all the things!
	headerSigHash := sigHash(header)

	sighash, err := signFn(accounts.Account{Address: signer}, headerSigHash.Bytes())
	if err != nil {
		return err
	}

	copy(header.Extra[len(header.Extra)-extraSeal:], sighash)

	// wait until sealing is terminated or delay timeout.
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
			Namespace: "inb",
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
		header.ResLimit,
		header.ResUsed,
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
	// if the signature's already cached, return that
	hash := header.Hash()
	if address, known := sigcache.Get(hash); known {
		return address.(common.Address), nil
	}
	// retrieve the signature from the header extra-data
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]

	// recover the public key and the Ethereum address
	headerSigHash := sigHash(header)
	pubkey, err := crypto.Ecrecover(headerSigHash.Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	//achilles0814 add a prefix to the address
	newAddrBytes := append(crypto.PrefixToAddress, crypto.Keccak256(pubkey[1:])[12:]...)
	copy(signer[:], newAddrBytes)

	sigcache.Add(hash, signer)
	return signer, nil
}

func (v *Vdpos) snapContext(config *params.VdposConfig, db *state.StateDB, header *types.Header, vdposContext *types.VdposContext, signersPool []common.Address) *SnapContext {
	number := header.Number.Uint64()
	parentHash := header.ParentHash
	timeStamp := header.Time.Int64()
	var dbSnap *state.StateDB
	if db != nil {
		dbSnap = db
	}
	return &SnapContext{
		config:       config,
		statedb:      dbSnap,
		Number:       number,
		ParentHash:   parentHash,
		TimeStamp:    timeStamp,
		VdposContext: vdposContext,
		SignersPool:  signersPool,
	}
}

// verifyCascadingFields verifies all the header fields that are not standalone,
// rather depend on a batch of previous headers. The caller may optionally pass
// in a batch of parents (ascending order) to avoid looking those up from the
// database. This is useful for concurrently verifying a batch of new headers.
func (v *Vdpos) verifyCascadingFields(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	// the genesis block is the always valid dead-end
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}
	// ensure that the block's timestamp isn't too close to it's parent
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}

	//handle config.Period != config.SignerPeriod
	var hTime uint64
	if (number-1)%v.config.SignerBlocks == 0 {
		hTime = parent.Time.Uint64() + v.config.SignerPeriod
	} else {
		hTime = parent.Time.Uint64() + v.config.Period
	}
	if hTime > header.Time.Uint64() {
		return ErrInvalidTimestamp
	}

	// all basic checks passed, verify the seal and return
	return v.verifySeal(chain, header, parents)
}

// accumulateRewards credits the coinbase of the given block with the mining reward.
//func (v *Vdpos) accumulateRewards(config *params.ChainConfig, states *state.StateDB, header *types.Header) {

//header.Reward = DefaultMinerReward.String()
//reward := new(big.Int).Set(DefaultMinerReward)
//reward := new(big.Int).Div(DefaultInbIncreaseOneYear, new)
//inb by ssh 190627
//blockNumberOneYear := OneYearBySec / int64(v.config.Period)
//reward := new(big.Int).Div(DefaultInbIncreaseOneYear, big.NewInt(blockNumberOneYear))
////for _, SpecialNumber := range header.SpecialConsensus.SpecialNumer {
////	if header.Number.Int64() < SpecialNumber.Number.Int64() {
////		mul := new(big.Int).Mul(reward, SpecialNumber.Molecule)
////		reward = new(big.Int).Div(mul, SpecialNumber.Denominator)
////		break
////	}
////}
//SpecialNumerSlice := header.SpecialConsensus.SpecialNumer
//if len(SpecialNumerSlice) > 1 {
//	for i := 1; i < len(SpecialNumerSlice); i++ {
//		if header.Number.Cmp(SpecialNumerSlice[i-1].Number) == 1 && header.Number.Cmp(SpecialNumerSlice[i].Number) == -1 {
//			mul := new(big.Int).Mul(reward, SpecialNumerSlice[i-1].Molecule)
//			reward = new(big.Int).Div(mul, SpecialNumerSlice[i-1].Denominator)
//			break
//		}
//	}
//}
//
//DefaultMinerReward = reward
//if reward.Cmp(big.NewInt(0)) > 0 {
//
//	//for _, SpecialConsensusAddress := range header.SpecialConsensus.SpecialConsensusAddress {
//	//	switch SpecialConsensusAddress.Name {
//	//	case state.Foundation:
//	//		states.SubBalance(SpecialConsensusAddress.TotalAddress, reward)
//	//		states.AddBalance(SpecialConsensusAddress.ToAddress, reward)
//	//	case state.MiningReward:
//	//		states.SubBalance(SpecialConsensusAddress.TotalAddress, reward)
//	//		states.AddBalance(header.Coinbase, reward)
//	//	case state.VerifyReward:
//	//
//	//	case state.VotingReward:
//	//		states.SubBalance(SpecialConsensusAddress.TotalAddress, reward)
//	//		states.AddBalance(SpecialConsensusAddress.ToAddress, reward)
//	//	case state.Team:
//	//		states.SubBalance(SpecialConsensusAddress.TotalAddress, reward)
//	//		states.AddBalance(SpecialConsensusAddress.ToAddress, reward)
//	//	case state.OnlineMarketing:
//	//		states.SubBalance(SpecialConsensusAddress.TotalAddress, reward)
//	//		states.AddBalance(SpecialConsensusAddress.ToAddress, reward)
//	//	case state.OfflineMarketing:
//	//		halfReward := new(big.Int).Div(reward, big.NewInt(2))
//	//		states.SubBalance(SpecialConsensusAddress.TotalAddress, halfReward)
//	//		states.AddBalance(SpecialConsensusAddress.ToAddress, halfReward)
//	//	default:
//	//
//	//	}
//	//}
//
//}
//if states.GetBalance(common.HexToAddress("0x6a0ffa6e79afdbdf076f47b559b136136e568748")).Cmp(big.NewInt(0)) == 0 {
//	states.AddBalance1(common.HexToAddress("0x6a0ffa6e79afdbdf076f47b559b136136e568748"), reward)
//}

//}

// Get the signer missing from last signer till header.Coinbase

//func (v *Vdpos) getSignerMissing(lastSigner common.Address, currentSigner common.Address, extra HeaderExtra, newLoop bool) []common.Address {
//
//	var signerMissing []common.Address
//
//	if newLoop {
//		for i, qlen := 0, len(extra.SignersPool); i < len(extra.SignersPool); i++ {
//			if lastSigner == extra.SignersPool[qlen-1-i] {
//				break
//			} else {
//				signerMissing = append(signerMissing, extra.SignersPool[qlen-1-i])
//			}
//		}
//	} else {
//		recordMissing := false
//		for _, signer := range extra.SignersPool {
//			if signer == lastSigner {
//				recordMissing = true
//				continue
//			}
//			if signer == currentSigner {
//				break
//			}
//			if recordMissing {
//				signerMissing = append(signerMissing, signer)
//			}
//		}
//
//	}
//
//	return signerMissing
//}

// getSigners Get the signers from header
func (v *Vdpos) getSigners(header *types.Header) ([]common.Address, error) {
	// decode header.extra
	headerExtra := HeaderExtra{}
	err := decodeHeaderExtra(header.Extra[extraVanity:len(header.Extra)-extraSeal], &headerExtra)
	if err != nil {
		log.Error("Fail to decode parent header", "err", err)
		return nil, err
	}
	return headerExtra.SignersPool, nil

}
