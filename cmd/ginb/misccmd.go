// Copyright 2016 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/insight-chain/inb-go/cmd/utils"
	"github.com/insight-chain/inb-go/consensus/ethash"
	"github.com/insight-chain/inb-go/eth"
	"github.com/insight-chain/inb-go/crypto"
	"github.com/insight-chain/inb-go/params"
	"gopkg.in/urfave/cli.v1"
	"os"
	"runtime"
	"strconv"
	"strings"
)

var (
	makecacheCommand = cli.Command{
		Action:    utils.MigrateFlags(makecache),
		Name:      "makecache",
		Usage:     "Generate ethash verification cache (for testing)",
		ArgsUsage: "<blockNum> <outputDir>",
		Category:  "MISCELLANEOUS COMMANDS",
		Description: `
The makecache command generates an ethash cache in <outputDir>.

This command exists to support the system testing project.
Regular users do not need to execute it.
`,
	}
	makedagCommand = cli.Command{
		Action:    utils.MigrateFlags(makedag),
		Name:      "makedag",
		Usage:     "Generate ethash mining DAG (for testing)",
		ArgsUsage: "<blockNum> <outputDir>",
		Category:  "MISCELLANEOUS COMMANDS",
		Description: `
The makedag command generates an ethash DAG in <outputDir>.

This command exists to support the system testing project.
Regular users do not need to execute it.
`,
	}
	versionCommand = cli.Command{
		Action:    utils.MigrateFlags(version),
		Name:      "version",
		Usage:     "Print version numbers",
		ArgsUsage: " ",
		Category:  "MISCELLANEOUS COMMANDS",
		Description: `
The output of this command is supposed to be machine-readable.
`,
	}
	licenseCommand = cli.Command{
		Action:    utils.MigrateFlags(license),
		Name:      "license",
		Usage:     "Display license information",
		ArgsUsage: " ",
		Category:  "MISCELLANEOUS COMMANDS",
	}
	//inb by ghy begin
	nodekeyCommand = cli.Command{
		Action:    utils.MigrateFlags(nodekey),
		Name:      "nodekey",
		Usage:     "create nodekey before init",
		ArgsUsage: " data-source path",
		Category:  "create nodekey before init",
	}
	//inb by ghy end
)

// makecache generates an ethash verification cache into the provided folder.
func makecache(ctx *cli.Context) error {
	args := ctx.Args()
	if len(args) != 2 {
		utils.Fatalf(`Usage: ginb makecache <block number> <outputdir>`)
	}
	block, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		utils.Fatalf("Invalid block number: %v", err)
	}
	ethash.MakeCache(block, args[1])

	return nil
}

// makedag generates an ethash mining DAG into the provided folder.
func makedag(ctx *cli.Context) error {
	args := ctx.Args()
	if len(args) != 2 {
		utils.Fatalf(`Usage: ginb makedag <block number> <outputdir>`)
	}
	block, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		utils.Fatalf("Invalid block number: %v", err)
	}
	ethash.MakeDataset(block, args[1])

	return nil
}

func version(ctx *cli.Context) error {
	fmt.Println(strings.Title(clientIdentifier))
	fmt.Println("Version:", params.VersionWithMeta)
	if gitCommit != "" {
		fmt.Println("Git Commit:", gitCommit)
	}
	fmt.Println("Architecture:", runtime.GOARCH)
	fmt.Println("Protocol Versions:", eth.ProtocolVersions)
	fmt.Println("Network Id:", eth.DefaultConfig.NetworkId)
	fmt.Println("Go Version:", runtime.Version())
	fmt.Println("Operating System:", runtime.GOOS)
	fmt.Printf("GOPATH=%s\n", os.Getenv("GOPATH"))
	fmt.Printf("GOROOT=%s\n", runtime.GOROOT())
	return nil
}

func license(_ *cli.Context) error {
	fmt.Println(`Ginb is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Geth is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ginb. If not, see <http://www.gnu.org/licenses/>.`)
	return nil
}

//inb by ghy begin
//Create file nodekey for generate nodeid
func nodekey(ctx *cli.Context) error {
	args := ctx.Args()
	if len(args) != 1 {
		utils.Fatalf(`Usage: ginb nodekey <block number> <outputdir>`)
	}
	var nodeKey *ecdsa.PrivateKey
	_, err := os.Stat(args[0]+"/ginb/nodekey")
	if os.IsExist(err)||err==nil {
		fmt.Println("nodekey is already exist")
		nodeKey, _ = crypto.LoadECDSA(args[0]+"/ginb/nodekey")

	}else{
		nodeKey, _ = crypto.GenerateKey()

		err = os.MkdirAll(args[0]+"/ginb/", os.ModePerm)
		if err = crypto.SaveECDSA(args[0]+"/ginb/nodekey", nodeKey); err != nil {
			utils.Fatalf(error.Error(err))
		}
	}
	nodeid:=fmt.Sprintf("%x", crypto.FromECDSAPub(&nodeKey.PublicKey)[1:])
	fmt.Println(nodeid)
	return nil
}
//inb by ghy end