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

package core

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/insight-chain/inb-go/common"
	"github.com/insight-chain/inb-go/common/hexutil"
	"github.com/insight-chain/inb-go/common/math"
	"github.com/insight-chain/inb-go/consensus/vdpos"
	"github.com/insight-chain/inb-go/core/rawdb"
	"github.com/insight-chain/inb-go/core/state"
	"github.com/insight-chain/inb-go/core/types"
	"github.com/insight-chain/inb-go/ethdb"
	"github.com/insight-chain/inb-go/log"
	"github.com/insight-chain/inb-go/params"
	"github.com/insight-chain/inb-go/rlp"
	"math/big"
	"strings"
)

//go:generate gencodec -type Genesis -field-override genesisSpecMarshaling -out gen_genesis.go
//go:generate gencodec -type GenesisAccount -field-override genesisAccountMarshaling -out gen_genesis_account.go

var errGenesisNoConfig = errors.New("genesis has no chain configuration")

// Genesis specifies the header fields, state of a genesis block. It also defines hard
// fork switch-over blocks through the chain configuration.
type Genesis struct {
	Config           *params.ChainConfig    `json:"config"`
	Nonce            uint64                 `json:"nonce"`
	Timestamp        uint64                 `json:"timestamp"`
	ExtraData        []byte                 `json:"extraData"`
	ResLimit         uint64                 `json:"resLimit"   gencodec:"required"`
	Difficulty       *big.Int               `json:"difficulty" gencodec:"required"`
	Mixhash          common.Hash            `json:"mixHash"`
	Coinbase         common.Address         `json:"coinbase"`
	Alloc            GenesisAlloc           `json:"alloc"      gencodec:"required"`
	SpecialConsensus types.SpecialConsensus `json:"specialConsensus"  gencodec:"required"` //2019.7.23 inb by ghy
	// These fields are used for consensus tests. Please don't use them
	// in actual genesis blocks.
	Number     uint64      `json:"number"`
	ResUsed    uint64      `json:"resUsed"`
	ParentHash common.Hash `json:"parentHash"`
}

// GenesisAlloc specifies the initial state that is part of the genesis block.
type GenesisAlloc map[common.Address]GenesisAccount

// UnmarshalJSON implements json.Unmarshal.
func Unmarshal(data []byte, g *Genesiss) error {
	if err := json.Unmarshal(data, g); err != nil {
		return err
	}
	SetDefaultGenesisTests(g)
	return nil
}

func (ga *GenesisAlloc) UnmarshalJSON(data []byte) error {
	m := make(map[common.UnprefixedAddress]GenesisAccount)
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	*ga = make(GenesisAlloc)
	for addr, a := range m {
		(*ga)[common.Address(addr)] = a
	}
	return nil
}

// GenesisAccount is an account in the state of the genesis block.
type GenesisAccount struct {
	Code       []byte                      `json:"code,omitempty"`
	Storage    map[common.Hash]common.Hash `json:"storage,omitempty"`
	Balance    *big.Int                    `json:"balance" gencodec:"required"`
	Nonce      uint64                      `json:"nonce,omitempty"`
	PrivateKey []byte                      `json:"secretKey,omitempty"` // for tests
}

// field type overrides for gencodec
type genesisSpecMarshaling struct {
	Nonce      math.HexOrDecimal64
	Timestamp  math.HexOrDecimal64
	ExtraData  hexutil.Bytes
	ResLimit   math.HexOrDecimal64
	ResUsed    math.HexOrDecimal64
	Number     math.HexOrDecimal64
	Difficulty *math.HexOrDecimal256
	Alloc      map[common.UnprefixedAddress]GenesisAccount
}

type genesisAccountMarshaling struct {
	Code       hexutil.Bytes
	Balance    *math.HexOrDecimal256
	Nonce      math.HexOrDecimal64
	Storage    map[storageJSON]storageJSON
	PrivateKey hexutil.Bytes
}

// storageJSON represents a 256 bit byte array, but allows less than 256 bits when
// unmarshaling from hex.
type storageJSON common.Hash

func (h *storageJSON) UnmarshalText(text []byte) error {
	text = bytes.TrimPrefix(text, []byte("0x"))
	if len(text) > 64 {
		return fmt.Errorf("too many hex characters in storage key/value %q", text)
	}
	offset := len(h) - len(text)/2 // pad on the left
	if _, err := hex.Decode(h[offset:], text); err != nil {
		fmt.Println(err)
		return fmt.Errorf("invalid hex storage key/value %q", text)
	}
	return nil
}

func (h storageJSON) MarshalText() ([]byte, error) {
	return hexutil.Bytes(h[:]).MarshalText()
}

// GenesisMismatchError is raised when trying to overwrite an existing
// genesis block with an incompatible one.
type GenesisMismatchError struct {
	Stored, New common.Hash
}

func (e *GenesisMismatchError) Error() string {
	return fmt.Sprintf("database already contains an incompatible genesis block (have %x, new %x)", e.Stored[:8], e.New[:8])
}

// SetupGenesisBlock writes or updates the genesis block in db.
// The block that will be used is:
//
//                          genesis == nil       genesis != nil
//                       +------------------------------------------
//     db has no genesis |  main-net default  |  genesis
//     db has genesis    |  from DB           |  genesis (if compatible)
//
// The stored chain configuration will be updated if it is compatible (i.e. does not
// specify a fork block below the local head block). In case of a conflict, the
// error is a *params.ConfigCompatError and the new, unwritten config is returned.
//
// The returned chain configuration is never nil.
func SetupGenesisBlock(db ethdb.Database, genesis *Genesis) (*params.ChainConfig, common.Hash, error) {
	return SetupGenesisBlockWithOverride(db, genesis, nil)
}
func SetupGenesisBlockWithOverride(db ethdb.Database, genesis *Genesis, constantinopleOverride *big.Int) (*params.ChainConfig, common.Hash, error) {
	if genesis != nil && genesis.Config == nil {
		return params.AllEthashProtocolChanges, common.Hash{}, errGenesisNoConfig
	}

	// Just commit the new block if there is no stored genesis block.
	stored := rawdb.ReadCanonicalHash(db, 0)
	if (stored == common.Hash{}) {
		if genesis == nil {
			log.Info("Writing default main-net genesis block")
			genesis = DefaultGenesisBlock()
		} else {
			log.Info("Writing custom genesis block")
		}
		block, err := genesis.Commit(db)
		return genesis.Config, block.Hash(), err
	}

	// Check whether the genesis block is already written.
	if genesis != nil {
		hash := genesis.ToBlock(nil).Hash()
		if hash != stored {
			return genesis.Config, hash, &GenesisMismatchError{stored, hash}
		}
	}

	// Get the existing chain configuration.
	newcfg := genesis.configOrDefault(stored)
	if constantinopleOverride != nil {
		newcfg.ConstantinopleBlock = constantinopleOverride
	}
	storedcfg := rawdb.ReadChainConfig(db, stored)
	if storedcfg == nil {
		log.Warn("Found genesis block without chain config")
		rawdb.WriteChainConfig(db, stored, newcfg)
		return newcfg, stored, nil
	}
	// Special case: don't change the existing config of a non-mainnet chain if no new
	// config is supplied. These chains would get AllProtocolChanges (and a compat error)
	// if we just continued here.
	if genesis == nil && stored != params.MainnetGenesisHash {
		return storedcfg, stored, nil
	}

	// Check config compatibility and write the config. Compatibility errors
	// are returned to the caller unless we're already at block zero.
	height := rawdb.ReadHeaderNumber(db, rawdb.ReadHeadHeaderHash(db))
	if height == nil {
		return newcfg, stored, fmt.Errorf("missing block number for head header hash")
	}
	compatErr := storedcfg.CheckCompatible(newcfg, *height)
	if compatErr != nil && *height != 0 && compatErr.RewindTo != 0 {
		return newcfg, stored, compatErr
	}
	rawdb.WriteChainConfig(db, stored, newcfg)
	return newcfg, stored, nil
}

func (g *Genesis) configOrDefault(ghash common.Hash) *params.ChainConfig {
	switch {
	case g != nil:
		return g.Config
	case ghash == params.MainnetGenesisHash:
		return params.MainnetChainConfig
	case ghash == params.TestnetGenesisHash:
		return params.TestnetChainConfig
	default:
		return params.AllEthashProtocolChanges
	}
}

// ToBlock creates the genesis block and writes state of a genesis specification
// to the given database (or discards it if nil).
func (g *Genesis) ToBlock(db ethdb.Database) *types.Block {
	if db == nil {
		db = ethdb.NewMemDatabase()
	}
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(db))
	for addr, account := range g.Alloc {
		statedb.AddBalance(addr, account.Balance)
		statedb.SetCode(addr, account.Code)
		statedb.SetNonce(addr, account.Nonce)
		for key, value := range account.Storage {
			statedb.SetState(addr, key, value)
		}
	}
	root := statedb.IntermediateRoot(false)

	// add by ssh 190815 begin
	//vdposContext, headerExtra := initGenesisVdposContext(g, db)
	vdposContext := initGenesisVdposContext(g, db)
	vdposContextProto := vdposContext.ToProto()
	head := &types.Header{
		Number:           new(big.Int).SetUint64(g.Number),
		Nonce:            types.EncodeNonce(g.Nonce),
		Time:             new(big.Int).SetUint64(g.Timestamp),
		ParentHash:       g.ParentHash,
		Extra:            g.ExtraData,
		ResLimit:         g.ResLimit,
		ResUsed:          g.ResUsed,
		Difficulty:       g.Difficulty,
		MixDigest:        g.Mixhash,
		Coinbase:         g.Coinbase,
		Root:             root,
		DataRoot:         [32]byte{},                        //inb by ssh 190627
		Reward:           vdpos.DefaultMinerReward.String(), //inb by ghy 19.6.28
		SpecialConsensus: []byte{},                          //2019.7.23 inb by ghy
		VdposContext:     vdposContextProto,                 //add by ssh 190805
		//LoopStartTime:        0,
		//ConfirmedBlockNumber: 0,
	}

	// inb by ssh 190724
	if g.Config.Vdpos != nil {
		//inb by ghy begin
		headerExtra := new(vdpos.HeaderExtra)
		//headerExtra.Enode=g.Config.Vdpos.Enode

		//for i,v:=range g.Config.Vdpos.Enodes{
		//	marshal, _:= json.Marshal(v.Data)
		//	g.Config.Vdpos.Enodes[i].DataJson=string(marshal)

		//headerExtra.Enodes = g.Config.Vdpos.Enodes
		//head.LoopStartTime = g.Config.Vdpos.GenesisTimestamp

		headerExtra.LoopStartTime = g.Config.Vdpos.GenesisTimestamp
		if len(head.Extra) < 32 {
			head.Extra = append(head.Extra, bytes.Repeat([]byte{0x00}, 32-len(head.Extra))...)
		}
		head.Extra = head.Extra[:32]
		extraByte, _ := rlp.EncodeToBytes(headerExtra)
		head.Extra = append(head.Extra, extraByte...)
		head.Extra = append(head.Extra, bytes.Repeat([]byte{0x00}, 65)...)

		//inb by ghy end
		encodeSpecialConsensusToBytes, err := rlp.EncodeToBytes(g.SpecialConsensus)
		if err != nil {
			log.Trace("EncodeToBytes", err)
		}
		head.SpecialConsensus = encodeSpecialConsensusToBytes
		//encodeSpecialConsensusToBytes, err := rlp.EncodeToBytes(g.SpecialConsensus)
		//if err != nil {
		//
		//}
		//key := common.BytesToHash(encodeSpecialConsensusToBytes)
		//head.SpecialConsensus = key
	}

	if g.ResLimit == 0 {
		head.ResLimit = params.GenesisGasLimit
	}
	if g.Difficulty == nil {
		head.Difficulty = params.GenesisDifficulty
	}
	statedb.Commit(false)
	statedb.Database().TrieDB().Commit(root, true)

	//return types.NewBlock(head, nil, nil, nil)
	block := types.NewBlock(head, nil, nil, nil)
	block.VdposContext = vdposContext
	return block

	// add by ssh 190815 end
}

// Commit writes the block and state of a genesis specification to the database.
// The block is committed as the canonical head block.
func (g *Genesis) Commit(db ethdb.Database) (*types.Block, error) {
	block := g.ToBlock(db)
	if block.Number().Sign() != 0 {
		return nil, fmt.Errorf("can't commit genesis block with number > 0")
	}

	// add by ssh 190815 begin
	// add dposcontext
	if _, err := block.VdposContext.Commit(); err != nil {
		return nil, err
	}
	// add by ssh 190815 end

	rawdb.WriteTd(db, block.Hash(), block.NumberU64(), g.Difficulty)
	rawdb.WriteBlock(db, block)
	rawdb.WriteReceipts(db, block.Hash(), block.NumberU64(), nil)
	rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	rawdb.WriteHeadBlockHash(db, block.Hash())
	rawdb.WriteHeadHeaderHash(db, block.Hash())

	config := g.Config
	if config == nil {
		config = params.AllEthashProtocolChanges
	}
	rawdb.WriteChainConfig(db, block.Hash(), config)
	return block, nil
}

// MustCommit writes the genesis block and state to db, panicking on error.
// The block is committed as the canonical head block.
func (g *Genesis) MustCommit(db ethdb.Database) *types.Block {
	block, err := g.Commit(db)
	if err != nil {
		panic(err)
	}
	return block
}

// GenesisBlockForTesting creates and writes a block in which addr has the given wei balance.
func GenesisBlockForTesting(db ethdb.Database, addr common.Address, balance *big.Int) *types.Block {
	g := Genesis{Alloc: GenesisAlloc{addr: {Balance: balance}}}
	return g.MustCommit(db)
}

// DefaultGenesisBlock returns the Ethereum main net genesis block.
func DefaultGenesisBlock() *Genesis {

	//vdpos by ssh begin
	mainnetAlloc := make(GenesisAlloc, 50)
	for _, addr := range params.MainnetChainConfig.Vdpos.SelfVoteSigners {
		balance, _ := new(big.Int).SetString("400000000000000000", 16)
		mainnetAlloc[common.Address(addr)] = GenesisAccount{Balance: balance}
	}

	balance, _ := new(big.Int).SetString("26c566f0a2b77a000000000", 16)
	mainnetAlloc[common.HexToAddress("t0bce13d77339971d1f5f00c38f523ba7ee44c95ed")] = GenesisAccount{Balance: balance}
	//vdpos by ssh end

	return &Genesis{
		Config:     params.MainnetChainConfig,
		Nonce:      66,
		ExtraData:  hexutil.MustDecode("0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa"),
		ResLimit:   5000,
		Difficulty: big.NewInt(17179869184),
		Alloc:      decodePrealloc(mainnetAllocData),
	}
}

// DefaultTestnetGenesisBlock returns the Ropsten network genesis block.
func DefaultTestnetGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.TestnetChainConfig,
		Nonce:      66,
		ExtraData:  hexutil.MustDecode("0x3535353535353535353535353535353535353535353535353535353535353535"),
		ResLimit:   16777216,
		Difficulty: big.NewInt(1048576),
		Alloc:      decodePrealloc(testnetAllocData),
	}
}

// DefaultRinkebyGenesisBlock returns the Rinkeby network genesis block.
func DefaultRinkebyGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.RinkebyChainConfig,
		Timestamp:  1492009146,
		ExtraData:  hexutil.MustDecode("0x52657370656374206d7920617574686f7269746168207e452e436172746d616e42eb768f2244c8811c63729a21a3569731535f067ffc57839b00206d1ad20c69a1981b489f772031b279182d99e65703f0076e4812653aab85fca0f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		ResLimit:   4700000,
		Difficulty: big.NewInt(1),
		Alloc:      decodePrealloc(rinkebyAllocData),
	}
}

// DeveloperGenesisBlock returns the 'ginb --dev' genesis block. Note, this must
// be seeded with the
func DeveloperGenesisBlock(period uint64, faucet common.Address) *Genesis {
	// Override the default period to the user requested one
	config := *params.AllCliqueProtocolChanges
	config.Clique.Period = period

	// Assemble and return the genesis with the precompiles and faucet pre-funded
	return &Genesis{
		Config:     &config,
		ExtraData:  append(append(make([]byte, 32), faucet[:]...), make([]byte, 65)...),
		ResLimit:   6283185,
		Difficulty: big.NewInt(1),
		Alloc: map[common.Address]GenesisAccount{
			common.BytesToAddress([]byte{1}): {Balance: big.NewInt(1)}, // ECRecover
			common.BytesToAddress([]byte{2}): {Balance: big.NewInt(1)}, // SHA256
			common.BytesToAddress([]byte{3}): {Balance: big.NewInt(1)}, // RIPEMD
			common.BytesToAddress([]byte{4}): {Balance: big.NewInt(1)}, // Identity
			common.BytesToAddress([]byte{5}): {Balance: big.NewInt(1)}, // ModExp
			common.BytesToAddress([]byte{6}): {Balance: big.NewInt(1)}, // ECAdd
			common.BytesToAddress([]byte{7}): {Balance: big.NewInt(1)}, // ECScalarMul
			common.BytesToAddress([]byte{8}): {Balance: big.NewInt(1)}, // ECPairing
			faucet: {Balance: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(9))},
		},
	}
}

func decodePrealloc(data string) GenesisAlloc {
	var p []struct{ Addr, Balance *big.Int }
	if err := rlp.NewStream(strings.NewReader(data), 0).Decode(&p); err != nil {
		panic(err)
	}
	ga := make(GenesisAlloc, len(p))
	for _, account := range p {
		ga[common.BigToAddress(account.Addr)] = GenesisAccount{Balance: account.Balance}
	}
	return ga
}

//func initGenesisVdposContext(g *Genesis, db ethdb.Database) (*types.VdposContext, *vdpos.HeaderExtra) {
func initGenesisVdposContext(g *Genesis, db ethdb.Database) *types.VdposContext {
	dc, err := types.NewVdposContext(db)
	if err != nil {
		//return nil, nil
		return nil
	}
	//headerExtra := new(vdpos.HeaderExtra)
	if g.Config != nil && g.Config.Vdpos != nil && g.Config.Vdpos.SelfVoteSigners != nil {
		alreadyVote := make(map[common.Address]struct{})
		//currentSigners := make([]common.Address, 0)
		for _, unPrefixVoter := range g.Config.Vdpos.SelfVoteSigners {
			voter := common.Address(unPrefixVoter)
			//currentSigners = append(currentSigners, voter)
			candidates := []common.Address{voter}
			if _, ok := alreadyVote[voter]; !ok {
				vote := &types.Votes{
					Voter:        voter,
					Candidate:    candidates,
					StakingValue: big.NewInt(1),
				}
				err = dc.UpdateTallysByVotes(vote, nil)
				if err != nil {
					//eturn nil, nil
					return nil
				}
				err = dc.UpdateVotes(vote)
				if err != nil {
					//return nil, nil
					return nil
				}
				alreadyVote[voter] = struct{}{}
			}
		}
		//err := dc.SetSignersToTrie(currentSigners)
		//if err != nil {
		//	log.Error("Fail in vdposContext.SetSignersToTrie()", "err", err)
		//	return nil
		//}
		//2019.9.4 inb by ghy begin
		currentEnodeInfos := make([]common.SuperNode, 0)
		for _, v := range g.Config.Vdpos.Enodes {
			enode := new(common.SuperNode)
			enode.Address = v.Address
			enode.Id = v.Id
			enode.Ip = v.Ip
			enode.Port = v.Port
			enode.RewardAccount = v.RewardAccount

			currentEnodeInfos = append(currentEnodeInfos, *enode)
			dc.UpdateTallysByNodeInfo(v)
		}
		err = dc.SetSuperNodesToTrie(currentEnodeInfos)
		if err != nil {
			log.Error("Fail in vdposContext.SetSuperNodesToTrie()", "err", err)
			return nil
		}
		//2019.9.4 inb by ghy end

	}

	//return dc, headerExtra
	return dc
}
