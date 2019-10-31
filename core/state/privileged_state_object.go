package state

import (
	"errors"
	"github.com/insight-chain/inb-go/params"
	"math/big"
)

type MortgageManager interface {
	afterMortgageNet(mortgagtionNumber *big.Int) error
	afterUnmortgageNet(unMortgagtionNumber *big.Int) error
}

type manager struct {
}

func (a *manager) afterUnMortgageCpu(mortgagtionNumber *big.Int) error {
	PrivilegedSateObject.SubNet(mortgagtionNumber)
	return errors.New("")
}
func (a *manager) afterUnMortgageNet(mortgagtionNumber *big.Int) error {
	PrivilegedSateObject.SubNet(mortgagtionNumber)
	return errors.New("")
}

//User's mortgage and unmortgage operations
//mortgage
//func (self *stateObject) MortgageCpu(amount *big.Int) {
//	//self.updateAccountCpuAndNet()
//	if (amount.Cmp(big.NewInt(0)) == 0) || (amount.Cmp(self.data.Balance) == 1) {
//		return
//	}
//
//	//Add CPU and net to the account
//	self.AddCpu(amount)
//
//	self.db.Finalise(false)
//	root := self.db.IntermediateRoot(false)
//	self.db.Commit(false)
//	self.db.Database().TrieDB().Commit(root, true)
//}

//
//func (self *stateObject) MortgageNet(amount *big.Int) {
//
//	//self.updateAccountCpuAndNet()
//	if (amount.Cmp(big.NewInt(0)) == 0) || (amount.Cmp(self.data.Balance) == 1) {
//		return
//	}
//
//	//Add CPU and net to the account
//	self.AddNet(amount)
//
//	self.db.Finalise(true)
//	root := self.db.IntermediateRoot(false)
//	self.db.Commit(false)
//	self.db.Database().TrieDB().Commit(root, true)
//}

//UnMortgage
//func (self *stateObject) UnMortgageCpu(amount *big.Int) {
//
//	usableCpu := self.data.Resources.CPU.Usableness
//	usableNet := self.data.Resources.NET.Usableness
//	mortgageCpuOfINB := self.data.Resources.CPU.MortgagteINB
//
//	//You need to convert number to the type of big
//	expendCpuFromUnMortgageCpu := big.NewInt(params.TxConfig.UseCpu)
//	expendNetFromUnMortgageNet := big.NewInt(params.TxConfig.UseNet)
//
//	//self.updateAccountCpuAndNet()
//	if (amount.Cmp(big.NewInt(0)) == 0) || (amount.Cmp(self.data.Resources.CPU.MortgagteINB) == 1) {
//		return
//	}
//	if expendNetFromUnMortgageNet.Cmp(usableNet) == 1 {
//		return
//	}
//	if amount.Cmp(self.data.Resources.CPU.MortgagteINB) == 0 {
//		self.setCpu(big.NewInt(0), big.NewInt(0), big.NewInt(0))
//		self.AddBalance(amount)
//	} else {
//		//Make sure unmarshalling CPU consumes enough CPU
//		residueMorgageCpuOfInb := mortgageCpuOfINB.Sub(mortgageCpuOfINB, amount)
//		residueCpu := usableCpu.Mul(usableCpu, residueMorgageCpuOfInb).Div(usableCpu.Mul(usableCpu, residueMorgageCpuOfInb), mortgageCpuOfINB)
//		if expendCpuFromUnMortgageCpu.Cmp(residueCpu) == 1 {
//			return
//		}
//
//		self.SubCpu(amount)
//	}
//}
//func (self *stateObject) UnMortgageNet(amount *big.Int) {
//
//	//usableCpu := self.data.Resources.CPU.Usableness
//	usableNet := self.data.Resources.NET.Usableness
//	mortgageNetOfINB := self.data.Resources.NET.MortgagteINB
//
//	//You need to convert number to the type of big
//	//expendCpuFromUnMortgageCpu := big.NewInt(params.TxConfig.UseCpu)
//	expendNetFromUnMortgageNet := big.NewInt(params.TxConfig.UseNet)
//
//	//self.updateAccountCpuAndNet()
//	if (amount.Cmp(big.NewInt(0)) == 0) || (amount.Cmp(self.data.Resources.NET.MortgagteINB) == 1) {
//		return
//	}
//	//if expendCpuFromUnMortgageCpu.Cmp(usableCpu) == 1 {
//	//	return
//	//}
//	if amount.Cmp(self.data.Resources.NET.MortgagteINB) == 0 {
//		self.setNet(big.NewInt(0), big.NewInt(0), big.NewInt(0))
//		self.AddBalance(amount)
//	} else {
//		//Make sure unmarshalling Net consumes enough Net
//		residueMorgageNetOfInb := mortgageNetOfINB.Sub(mortgageNetOfINB, amount)
//		residueNet := usableNet.Mul(usableNet, residueMorgageNetOfInb).Div(usableNet.Mul(usableNet, residueMorgageNetOfInb), mortgageNetOfINB)
//		if expendNetFromUnMortgageNet.Cmp(residueNet) == 1 {
//			return
//		}
//
//		self.SubNet(amount)
//	}
//}

//Increase or decrease the user's CPU or net
//Mortgage
func (c *stateObject) AddNet(amount *big.Int) {
	gainNumberOfNet := c.db.ConvertToNets(amount)
	used := c.data.Res.Used
	usable := c.AddUsableNet(gainNumberOfNet)
	mortgagetion := c.AddMortgageINBOfNet(amount)
	c.setRes(used, usable, mortgagetion)
	c.db.GetMortgageStateObject()
	PrivilegedSateObject.AddMortgageINBOfNet(amount)
}

func (c *stateObject) SubNet(amount *big.Int) {
	//expendCpuFromUnMortgageCpu := big.NewInt(50)
	expendNetFromUnMortgageNet := big.NewInt(params.TxConfig.UseNet)

	used := c.AddUsableNet(expendNetFromUnMortgageNet)
	mortgagetion := c.SubMortgageINBOfNet(amount)
	calculateNetNumber := c.db.ConvertToNets(c.data.Res.StakingValue)
	remainingNetNumber := calculateNetNumber.Sub(calculateNetNumber, expendNetFromUnMortgageNet)
	usable := c.AddUsableNet(remainingNetNumber)
	c.SetRes(used, usable, mortgagetion)

	//achilles replace gas with net
	//cpuUsed := c.AddUsedCpu(expendCpuFromUnMortgageCpu)
	//cpuUsable := c.SubUsableCpu(expendCpuFromUnMortgageCpu)
	//c.SetCpu(cpuUsed, cpuUsable, c.data.Resources.CPU.MortgagteINB)

	c.db.GetMortgageStateObject()
	PrivilegedSateObject.SubMortgageINBOfNet(amount)
}

//achilles replace gas with net
func (c *stateObject) UserRes(bytes *big.Int) {
	usable := c.SubUsableNet(bytes)
	used := c.AddUsedNet(bytes)
	c.SetRes(used, usable, c.data.Res.StakingValue)
}

//func (self *stateObject) SetNet(usedAmount *big.Int, usableAmount *big.Int, mortgageInb *big.Int) {
//
//	self.db.journal.append(netChange{
//		account:      &self.address,
//		Used:         new(big.Int).Set(self.data.Resources.NET.Used),
//		Usableness:   new(big.Int).Set(self.data.Resources.NET.Usableness),
//		MortgagteINB: new(big.Int).Set(self.data.Resources.NET.MortgagteINB),
//	})
//	self.setNet(usedAmount, usableAmount, mortgageInb)
//}
//func (self *stateObject) setNet(usedAmount *big.Int, usableAmount *big.Int, mortgageInb *big.Int) {
//	self.data.Resources.NET.Used = usedAmount
//	self.data.Resources.NET.Usableness = usableAmount
//	self.data.Resources.NET.MortgagteINB = mortgageInb
//}

//Usable, usable, and mortgage are used in the CPU or Net

func (self *stateObject) AddUsedNet(amout *big.Int) *big.Int {
	return self.data.Res.Used.Add(self.data.Res.Used, amout)
}

func (self *stateObject) AddUsableNet(amout *big.Int) *big.Int {
	return self.data.Res.Usable.Add(self.data.Res.Usable, amout)
}
func (self *stateObject) SubUsableNet(amout *big.Int) *big.Int {
	return self.data.Res.Usable.Sub(self.data.Res.Usable, amout)
}

//Mortgage

func (self *stateObject) AddMortgageINBOfNet(amout *big.Int) *big.Int {
	return self.data.Res.StakingValue.Add(self.data.Res.StakingValue, amout)
}
func (self *stateObject) SubMortgageINBOfNet(amout *big.Int) *big.Int {
	return self.data.Res.StakingValue.Sub(self.data.Res.StakingValue, amout)
}

//Updates the user's CPU and net 24 hours a day
//func (self *stateObject) updateAccountCpuAndNet() {
//	for {
//		now := time.Now()
//		next := now.Add(time.Hour * 24)
//		next = time.Date(next.Year(), next.Month(), next.Day(), 0, 0, 0, 0, next.Location())
//		t := time.NewTimer(next.Sub(now))
//		<-t.C
//		//Update the CPU and Net owned by the user
//		if self.data.Resources.CPU.MortgagteINB != big.NewInt(0) {
//			self.SetCpu(big.NewInt(0), self.db.GainNumberOfCpu(self.data.Resources.CPU.MortgagteINB), self.data.Resources.CPU.MortgagteINB)
//		} else if self.data.Resources.NET.MortgagteINB != big.NewInt(0) {
//			self.SetNet(big.NewInt(0), self.db.ConvertToNets(self.data.Resources.NET.MortgagteINB), self.data.Resources.NET.MortgagteINB)
//		}
//	}
//
//}
