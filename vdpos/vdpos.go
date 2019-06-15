// Copyright 2018 The Insight Chain
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

package vdpos

import (
	"bytes"
	"github.com/insight-chain/inb-go/common"
	"github.com/insight-chain/inb-go/vdpos/vcommon"
	"math/rand"
	"time"
)

var VConfig = Config{
	MaxSuperNodeNumber: 21,
	MaxValidatorNumber: 1000,

	SmallBlockProduceNumber: 6,

	SmallBlockProduceInterval: 500,
	BlockProduceInterval: 500,
}

type SuperNode struct {
	// Account Name
	Name string
	// Account address
	Account string
	// node uid
	Id string
	// node Ip
	Ip string
	// node Port
	Port uint
	// if the super node is Valid
	Valid bool
	// connected time with the currrent super node
	ConnectedTime *time.Time
}

// Super Nodes
type SuperNodes struct {
	Nodes []*SuperNode
	CreatedTime time.Time

	StartedTime time.Time

	CurrentRound uint
	CurrentRoundStartedTime time.Time
}

// TODO Test, how to make super nodes order believable?
var superNodes = SuperNodes{
	Nodes: make([]*SuperNode, 0, VConfig.MaxSuperNodeNumber),
	CreatedTime: time.Now(),
}

// the order of the super node generating block
var superNodeOrder = make([]*SuperNode, 0, cap(superNodes.Nodes))

func init() {
	//TODO Test 添加几个默认的超级节点



	//signers:=makeWizard("network").run()
	//
	//for i,v:=range signers{
	//	fmt.Println(i,v)
	//}
	//预定义解码结果
//	var adds address
//var path string
//   for i,v:=range os.Args{
//   	if v=="init"{
//   		path=os.Args[i+1]
//	}
//   }
//   if path !=""{
//   	fmt.Println("ddddddddddddddddddddddddddddddddddddd",path)
//   }
//	filePtr, _ := os.Open(path)
//	defer filePtr.Close()
//
//	decoder := json.NewDecoder(filePtr)
//
//	err := decoder.Decode(&adds)
//	if err!=nil{
//		fmt.Println("解码失败，err=",err)
//	}else {
//		fmt.Printf("解码成功:%#v\n",adds)
//	}
//
//	if len(adds.Config.Vdpos.Signers)==len(adds.Config.Vdpos.Ip)&&len(adds.Config.Vdpos.Ip)==len(adds.Config.Vdpos.Port){
//
//	}else{
//
//	}
//	for k,v:=range adds.Config.Vdpos.Signers{
//		AddSuperNode(v, v[2:], "728de7ca649c73eba10088eabd2dc4ff3e7cad714b416bb116abfe624dc1012fe1a929ab0b7fae5426a90a99156cc7f8d8453780765e352976d2ebc23616fee5",
//			adds.Config.Vdpos.Ip[k], adds.Config.Vdpos.Port[k])
//	}
//	AddSuperNode("188", "188", "2d1edb9d057df5d6cf147e1ea810699252193a091a8835174e4c0e0dcb738e0ce17b5e7b96e269f807eef1956744cb577fd7093cde4f5a17527b2062afbec242",
//		"192.168.1.238", 30001)
	//AddSuperNode("188", "188", "453f6b1414c0f40b8b1f81ca28d77fe793c4ac4925d6493cf4c5522d1de067b36828c3cedc7aed66c4afb0f5fce20c34b1a771e4b9f08d3bd1f2ddb39b10710a",
	//	"192.168.1.188", 30313)
	//AddSuperNode("181", "181", "1e573a4ceaafdd63d83d95ff1ded52f4d311380e05232f78efa698151749d9f56a463bee721ee19ba1c0421aeb3a740c19aacecfe002329aa3bae12b66b18956",
	//	"192.168.1.181", 30303)
	//AddSuperNode("182", "182", "59a68ae8a82f63ecd8478a94bf2070c5e37a914a2f50bc033a9d93e603635c7b40af6e7211d82fd52f8877ee65992d283b7348870289bd314ceac8f56e55a2fe",
	////	"192.168.1.182", 30303)
	//supernodes:=CalculateSuperNodeOrder()
	//fmt.Println("super node lenth==============================================",len(supernodes))
}
type address struct {
	Config config `json:"config"`
}
type config struct {
	Vdpos vdposs `json:"vdpos"`
}

type vdposs struct {
	Signers []string `json:"signers"`
	Ip []string `json:"ip"`
	Port []uint `json:"port"`
}
//type wizard struct {
//	network string // Network name to manage
//	conf    config // Configurations from previous runs
//
//	servers  map[string]*sshClient // SSH connections to servers to administer
//	services map[string][]string   // Ethereum services known to be running on servers
//
//	in   *bufio.Reader // Wrapper around stdin to allow reading user input
//	lock sync.Mutex    // Lock to protect configs during concurrent service discovery
//}
//type sshClient struct {
//	server  string // Server name or IP without port number
//	address string // IP address of the remote server
//	pubkey  []byte // RSA public key to authenticate the server
//	client  *ssh.Client
//	logger  log.Logger
//}
//type config struct {
//	path      string   // File containing the configuration values
//	bootnodes []string // Bootnodes to always connect to by all nodes
//	ethstats  string   // Ethstats settings to cache for node deploys
//
//	Genesis *core.Genesis     `json:"genesis,omitempty"` // Genesis block to cache for node deploys
//	Servers map[string][]byte `json:"servers,omitempty"`
//}
//func makeWizard(network string) *wizard {
//	return &wizard{
//		network: network,
//		conf: config{
//			Servers: make(map[string][]byte),
//		},
//		servers:  make(map[string]*sshClient),
//		services: make(map[string][]string),
//		in:       bufio.NewReader(os.Stdin),
//	}
//}
//func (w *wizard) run() []common.Address {
//	var signers []common.Address
//	for {
//		fmt.Println("woshidshei")
//		if address := w.readAddress(); address != nil {
//			signers = append(signers, *address)
//			continue
//		}
//		if len(signers) > 0 {
//			break
//		}
//	}
//	return signers
//}
//func (w *wizard) readAddress() *common.Address {
//	for {
//		// Read the address from the user
//		fmt.Printf("> 0x")
//		text, err := w.in.ReadString('\n')
//		if err != nil {
//			log.Crit("Failed to read user input", "err", err)
//		}
//		if text = strings.TrimSpace(text); text == "" {
//			return nil
//		}
//		// Make sure it looks ok and return it if so
//		if len(text) != 40 {
//			log.Error("Invalid address length, please retry")
//			continue
//		}
//		bigaddr, _ := new(big.Int).SetString(text, 16)
//		address := common.BigToAddress(bigaddr)
//		return &address
//	}
//}



func SuperNodeOrder() []*SuperNode {
	return superNodeOrder
}

// If allow the super node with id connect, TODO only allow the super nodes to connect?
func AllowConnect(id string) bool {
	for _, superNode := range superNodes.Nodes {
		if superNode.Id == id {
			return true
		}
	}
	return false
}

// Calculate the order of the super node generating block
// Use this method when every turn finished
func CalculateSuperNodeOrder() []*SuperNode {
	//TODO Need to calculate by the distances
	superNodeOrder = superNodeOrder[0:0]
	superNodeOrder = make([]*SuperNode, len(superNodes.Nodes), cap(superNodes.Nodes))

	rand.Seed(time.Now().UnixNano())
	indexes := make([]int, len(superNodes.Nodes), len(superNodes.Nodes))
	for index, _ := range superNodes.Nodes {
		indexes[index] = index
	}
	vcommon.RandomInt(indexes)
	for index, superNode := range superNodes.Nodes {
		//superNodeOrder[indexes[index]] = fmt.Sprintf(superNode.Id, ":", superNode.Port)
		superNodeOrder[indexes[index]] = superNode
		//superNodeOrder[rand.Intn(len(superNodes))] = superNode.Id
		//superNodeOrder = append(superNodeOrder, superNode.Id)
	}
	return superNodeOrder
}

func GetSuperNodes() SuperNodes {
	return superNodes
}

func NewSuperNode(name string, account string, id string, ip string, port uint) *SuperNode {
	superNode := &SuperNode{Name: name, Account: account, Id: id, Ip: ip, Port: port}
	return superNode
}

func AddSuperNode(name string, account string, id string, ip string, port uint) *SuperNode {
	superNode := NewSuperNode(name, account, id, ip, port)
	superNodes.Nodes = append(superNodes.Nodes, superNode)
	return superNode
}

func InvalidSuperNode(id string) {
	for index := range superNodes.Nodes {
		if superNodes.Nodes[index].Id == id {
			superNodes.Nodes[index].Valid = false
			break
		}
	}
}

func ConnectAllSuperNode() {
	if len(superNodes.Nodes) > 0 {
		for index := range superNodes.Nodes {
			superNode := superNodes.Nodes[index]
			ConnectSuperNode(superNode)
		}
	}
}

func ConnectSuperNode(superNode *SuperNode) (bool, error) {
	url := ParsePeerUrl(superNode)
	if !common.IsBlank(url) {
		//currentNode := vcommon.CurrentNode()
		//node, err := enode.ParseV4(url)
		//if err != nil {
		//	return false, fmt.Errorf("invalid enode: %v", err)
		//}
		//vcommon.CurrentNode().Server().AddPeer(node)

		return true, nil
	}
	return false, nil
}

func ParsePeerUrl(superNode *SuperNode) string {
	var urlBuffer bytes.Buffer
	if superNode != nil && !common.IsBlank(superNode.Id) && !common.IsBlank(superNode.Ip) && superNode.Port > 0 {
		urlBuffer.WriteString("enode://")
		urlBuffer.WriteString(superNode.Id)
		urlBuffer.WriteString("@")
		urlBuffer.WriteString(superNode.Ip)
		urlBuffer.WriteString(":")
		urlBuffer.WriteString(common.ToString(int(superNode.Port)))
	}
	return urlBuffer.String()
}
