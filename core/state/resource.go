package state

import (
	"math/big"
	"strconv"
	"sync/atomic"
	"time"
)

var (
	PerINBGainNetNum *big.Int
	PerINBGainCpuNum *big.Int
)

type record struct {
	rddData RdDdataInterface
	hash    atomic.Value
	size    atomic.Value
	from    atomic.Value
}
type RdDdataInterface interface {
}
type BaseRecordData struct {
	AccountNonce uint64   `json:"nonce"        gencodec:"required"`
	CpuPrice     *big.Int `json:"netPrice"     gencodec:"required"`
	NetPrice     *big.Int `json:"cpuPrice"     gencodec:"required"`
	Amount       *big.Int `json:"value"        gencodec:"required"` //inb number
	CpuAmount    *big.Int `json:"CpuAmount"    gencodec:"required"` //cpu number
	NetAmount    *big.Int `json:"NetAmount"    gencodec:"required"` //net number
	//sign
	V *big.Int `json:"v" gencodec:"required"`
	R *big.Int `json:"r" gencodec:"required"`
	S *big.Int `json:"s" gencodec:"required"`
}
type Mortgagtion struct {
	BaseRecordData
	mortgagtionDate time.Time
}
type Unmortgagtion struct {
	BaseRecordData
	UnmortgagtionDate time.Time
	expectedDate      time.Time
}

//1 inb can be exchanged for Net
func (c *StateDB) PerInbIsNet() *big.Int {

	as := c.GetPrivilegedSateObject().data.Resources.NET.MortgagteINB
	asString := as.Set(as).String()
	asValue, err := strconv.ParseInt(asString, 10, 64)
	if err != nil {

	}

	if as == big.NewInt(0) || asValue == 0 {
		PerINBGainNetNum = big.NewInt(1).Div(big.NewInt(86400*1000*1024*1000), big.NewInt(10*100000000))
	} else {
		PerINBGainNetNum = as.Div(big.NewInt(86400*1000*1024*1000), as)
	}
	return PerINBGainNetNum
}

//1 inb can be exchanged for CPU
func (c *StateDB) PerInbIsCpu() *big.Int {

	as := c.GetPrivilegedSateObject().data.Resources.CPU.MortgagteINB
	asString := as.Set(as).String()
	asValue, err := strconv.ParseInt(asString, 10, 64)
	if err != nil {

	}

	if as == big.NewInt(0) || asValue == 0 {
		PerINBGainCpuNum = big.NewInt(1).Div(big.NewInt(691200000*1000), big.NewInt(10*100000000))
	} else {
		PerINBGainCpuNum = as.Div(big.NewInt(691200000*1000), as)
	}
	return PerINBGainCpuNum
}

//mortgage how much NET inb gets
func (c *StateDB) GainNumberOfNet(inbNumber *big.Int) *big.Int {

	everyINBGainNetNum := c.PerInbIsNet()

	if everyINBGainNetNum == big.NewInt(0) {
		return big.NewInt(0)
	} else {
		if inbNumber != nil {
			return big.NewInt(1).Mul(inbNumber, everyINBGainNetNum)
		}
		return big.NewInt(0)
	}
}

//mortgage how much CPU inb gets
func (c *StateDB) GainNumberOfCpu(inbNumber *big.Int) *big.Int {

	everyINBGainCpuNum := c.PerInbIsCpu()
	if everyINBGainCpuNum == big.NewInt(0) {
		return big.NewInt(0)
	} else {
		if inbNumber != nil {

			return big.NewInt(1).Mul(inbNumber, everyINBGainCpuNum)
		}
		return big.NewInt(0)
	}
}
