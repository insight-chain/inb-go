package state

import (
	"errors"
	"math/big"
	"time"
)

type MortgageManager interface {
	afterMortgageCpu(mortgagtionNumber *big.Int) error
	afterMortgageNet(mortgagtionNumber *big.Int) error
	afterUnmortgageCpu(unMortgagtionNumber *big.Int) error
	afterUnmortgageNet(unMortgagtionNumber *big.Int) error
}

type manager struct {
}

func (a *manager) afterMortgageCpu(mortgagtionNumber *big.Int) error {
	PrivilegedSateObject.AddCpu(mortgagtionNumber)
	return errors.New("")
}
func (a *manager) afterMortgageNet(mortgagtionNumber *big.Int) error {
	PrivilegedSateObject.AddCpu(mortgagtionNumber)
	return errors.New("")
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
func (self *stateObject) MortgageCpu(amount *big.Int) {
	//self.updateAccountCpuAndNet()
	if (amount.Cmp(big.NewInt(0)) == 0) || (amount.Cmp(self.data.Balance) == 1) {
		return
	}

	//Add CPU and net to the account
	self.AddCpu(amount)

	self.db.Finalise(false)
	root := self.db.IntermediateRoot(false)
	self.db.Commit(false)
	self.db.Database().TrieDB().Commit(root, true)
}
func (self *stateObject) MortgageNet(amount *big.Int) {

	//self.updateAccountCpuAndNet()
	if (amount.Cmp(big.NewInt(0)) == 0) || (amount.Cmp(self.data.Balance) == 1) {
		return
	}

	//Add CPU and net to the account
	self.AddNet(amount)

	self.db.Finalise(true)
	root := self.db.IntermediateRoot(false)
	self.db.Commit(false)
	self.db.Database().TrieDB().Commit(root, true)
}
//UnMortgage
func (self *stateObject) UnMortgageCpu(amount *big.Int) {

	usableCpu := self.data.Resources.CPU.Usableness
	usableNet := self.data.Resources.NET.Usableness
	mortgageCpuOfINB := self.data.Resources.CPU.MortgagteINB

	//You need to convert number to the type of big
	expendCpuFromUnMortgageCpu := big.NewInt(50)
	expendNetFromUnMortgageNet := big.NewInt(300)

	//self.updateAccountCpuAndNet()
	if (amount.Cmp(big.NewInt(0)) == 0) || (amount.Cmp(self.data.Resources.CPU.MortgagteINB) == 1) {
		return
	}
	if expendNetFromUnMortgageNet.Cmp(usableNet) == 1 {
		return
	}
	if amount.Cmp(self.data.Resources.CPU.MortgagteINB) == 0 {
		self.setCpu(big.NewInt(0), big.NewInt(0), big.NewInt(0))
		self.AddBalance(amount)
	} else {
		//Make sure unmarshalling CPU consumes enough CPU
		residueMorgageCpuOfInb := mortgageCpuOfINB.Sub(mortgageCpuOfINB, amount)
		residueCpu := usableCpu.Mul(usableCpu, residueMorgageCpuOfInb).Div(usableCpu.Mul(usableCpu, residueMorgageCpuOfInb), mortgageCpuOfINB)
		if expendCpuFromUnMortgageCpu.Cmp(residueCpu) == 1 {
			return
		}

		self.SubCpu(amount)
	}
}
func (self *stateObject) UnMortgageNet(amount *big.Int) {

	usableCpu := self.data.Resources.CPU.Usableness
	usableNet := self.data.Resources.NET.Usableness
	mortgageNetOfINB := self.data.Resources.NET.MortgagteINB

	//You need to convert number to the type of big
	expendCpuFromUnMortgageCpu := big.NewInt(50)
	expendNetFromUnMortgageNet := big.NewInt(300)

	//self.updateAccountCpuAndNet()
	if (amount.Cmp(big.NewInt(0)) == 0) || (amount.Cmp(self.data.Resources.NET.MortgagteINB) == 1) {
		return
	}
	if expendCpuFromUnMortgageCpu.Cmp(usableCpu) == 1 {
		return
	}
	if amount.Cmp(self.data.Resources.NET.MortgagteINB) == 0 {
		self.setNet(big.NewInt(0), big.NewInt(0), big.NewInt(0))
		self.AddBalance(amount)
	} else {
		//Make sure unmarshalling Net consumes enough Net
		residueMorgageNetOfInb := mortgageNetOfINB.Sub(mortgageNetOfINB, amount)
		residueNet := usableNet.Mul(usableNet, residueMorgageNetOfInb).Div(usableNet.Mul(usableNet, residueMorgageNetOfInb), mortgageNetOfINB)
		if expendNetFromUnMortgageNet.Cmp(residueNet) == 1 {
			return
		}

		self.SubNet(amount)
	}
}
//Increase or decrease the user's CPU or net
//Mortgage
func (c *stateObject) AddCpu(amount *big.Int) {

	gainNumberOfCpu := c.db.GainNumberOfCpu(amount)
	used := c.data.Resources.CPU.Used
	usable := c.AddUsableCpu(gainNumberOfCpu)
	mortgagetion := c.AddMortgageINBOfCpu(amount)
	c.SetCpu(used, usable, mortgagetion)

	c.db.GetPrivilegedSateObject()
	PrivilegedSateObject.AddMortgageINBOfCpu(amount)
}
func (c *stateObject) AddNet(amount *big.Int) {

	gainNumberOfNet := c.db.GainNumberOfNet(amount)
	used := c.data.Resources.NET.Used
	usable := c.AddUsableNet(gainNumberOfNet)
	mortgagetion := c.AddMortgageINBOfNet(amount)
	c.setNet(used, usable, mortgagetion)

	c.db.GetPrivilegedSateObject()
	PrivilegedSateObject.AddMortgageINBOfNet(amount)
}

//unMorgage
func (c *stateObject) SubCpu(amount *big.Int) {
	expendCpuFromUnMortgageCpu := big.NewInt(50)
	expendNetFromUnMortgageNet := big.NewInt(300)

	used := c.AddUsableCpu(expendCpuFromUnMortgageCpu)
	mortgagetion := c.SubMortgageINBOfCpu(amount)
	calculateCpuNumber := c.db.GainNumberOfCpu(c.data.Resources.CPU.MortgagteINB)
	remainingCpuNumber := calculateCpuNumber.Sub(calculateCpuNumber, expendCpuFromUnMortgageCpu)
	usable := c.AddUsableCpu(remainingCpuNumber)
	c.SetCpu(used, usable, mortgagetion)

	netUsed := c.AddUsedNet(expendNetFromUnMortgageNet)
	netUsable := c.SubUsableNet(expendNetFromUnMortgageNet)
	c.SetNet(netUsed, netUsable, c.data.Resources.NET.MortgagteINB)

	c.db.GetPrivilegedSateObject()
	PrivilegedSateObject.SubMortgageINBOfCpu(amount)
}
func (c *stateObject) SubNet(amount *big.Int) {
	expendCpuFromUnMortgageCpu := big.NewInt(50)
	expendNetFromUnMortgageNet := big.NewInt(300)

	used := c.AddUsableNet(expendNetFromUnMortgageNet)
	mortgagetion := c.SubMortgageINBOfNet(amount)
	calculateNetNumber := c.db.GainNumberOfNet(c.data.Resources.NET.MortgagteINB)
	remainingNetNumber := calculateNetNumber.Sub(calculateNetNumber, expendNetFromUnMortgageNet)
	usable := c.AddUsableNet(remainingNetNumber)
	c.SetNet(used, usable, mortgagetion)

	cpuUsed := c.AddUsedCpu(expendCpuFromUnMortgageCpu)
	cpuUsable := c.SubUsableCpu(expendCpuFromUnMortgageCpu)
	c.SetCpu(cpuUsed, cpuUsable, c.data.Resources.CPU.MortgagteINB)

	c.db.GetPrivilegedSateObject()
	PrivilegedSateObject.SubMortgageINBOfNet(amount)
}

//Set up the user's CPU and net
func (self *stateObject) SetCpu(usedAmount *big.Int, usableAmount *big.Int, mortgageInb *big.Int) {

	self.db.journal.append(cpuChange{
		account:      &self.address,
		Used:         new(big.Int).Set(self.data.Resources.CPU.Used),
		Usableness:   new(big.Int).Set(self.data.Resources.CPU.Usableness),
		MortgagteINB: new(big.Int).Set(self.data.Resources.CPU.MortgagteINB),
	})
	self.setCpu(usedAmount, usableAmount, mortgageInb)
}
func (self *stateObject) setCpu(usedAmount *big.Int, usableAmount *big.Int, mortgageInb *big.Int) {

	self.data.Resources.CPU.Used = usedAmount
	self.data.Resources.CPU.Usableness = usableAmount
	self.data.Resources.CPU.MortgagteINB = mortgageInb
}
func (self *stateObject) SetNet(usedAmount *big.Int, usableAmount *big.Int, mortgageInb *big.Int) {

	self.db.journal.append(netChange{
		account:      &self.address,
		Used:         new(big.Int).Set(self.data.Resources.NET.Used),
		Usableness:   new(big.Int).Set(self.data.Resources.NET.Usableness),
		MortgagteINB: new(big.Int).Set(self.data.Resources.NET.MortgagteINB),
	})
	self.setNet(usedAmount, usableAmount, mortgageInb)
}
func (self *stateObject) setNet(usedAmount *big.Int, usableAmount *big.Int, mortgageInb *big.Int) {
	self.data.Resources.NET.Used = usedAmount
	self.data.Resources.NET.Usableness = usableAmount
	self.data.Resources.NET.MortgagteINB = mortgageInb
}

//Usable, usable, and mortgage are used in the CPU or Net
//used
func (self *stateObject) AddUsedCpu(amout *big.Int) *big.Int {
	return self.data.Resources.CPU.Used.Add(self.data.Resources.CPU.Used, amout)
}
func (self *stateObject) AddUsedNet(amout *big.Int) *big.Int {
	return self.data.Resources.NET.Used.Add(self.data.Resources.NET.Used, amout)
}

//Usable
func (self *stateObject) AddUsableCpu(amout *big.Int) *big.Int {
	return self.data.Resources.CPU.Usableness.Add(self.data.Resources.CPU.Usableness, amout)
}
func (self *stateObject) AddUsableNet(amout *big.Int) *big.Int {
	return self.data.Resources.NET.Usableness.Add(self.data.Resources.NET.Usableness, amout)
}
func (self *stateObject) SubUsableCpu(amout *big.Int) *big.Int {
	return self.data.Resources.CPU.Usableness.Sub(self.data.Resources.CPU.Usableness, amout)
}
func (self *stateObject) SubUsableNet(amout *big.Int) *big.Int {
	return self.data.Resources.NET.Usableness.Sub(self.data.Resources.NET.Usableness, amout)
}

//Mortgage
func (self *stateObject) AddMortgageINBOfCpu(amout *big.Int) *big.Int {
	return self.data.Resources.CPU.MortgagteINB.Add(self.data.Resources.CPU.MortgagteINB, amout)
}
func (self *stateObject) AddMortgageINBOfNet(amout *big.Int) *big.Int {
	return self.data.Resources.NET.MortgagteINB.Add(self.data.Resources.NET.MortgagteINB, amout)
}
func (self *stateObject) SubMortgageINBOfCpu(amout *big.Int) *big.Int {
	return self.data.Resources.CPU.MortgagteINB.Sub(self.data.Resources.CPU.MortgagteINB, amout)
}
func (self *stateObject) SubMortgageINBOfNet(amout *big.Int) *big.Int {
	return self.data.Resources.NET.MortgagteINB.Sub(self.data.Resources.NET.MortgagteINB, amout)
}
//Updates the user's CPU and net 24 hours a day
func (self *stateObject) updateAccountCpuAndNet() {
	for {
		now := time.Now()
		next := now.Add(time.Hour * 24)
		next = time.Date(next.Year(), next.Month(), next.Day(), 0, 0, 0, 0, next.Location())
		t := time.NewTimer(next.Sub(now))
		<-t.C
		//Update the CPU and Net owned by the user
		if self.data.Resources.CPU.MortgagteINB != big.NewInt(0) {
			self.SetCpu(big.NewInt(0), self.db.GainNumberOfCpu(self.data.Resources.CPU.MortgagteINB), self.data.Resources.CPU.MortgagteINB)
		}else if self.data.Resources.NET.MortgagteINB != big.NewInt(0){
			self.SetNet(big.NewInt(0), self.db.GainNumberOfNet(self.data.Resources.NET.MortgagteINB), self.data.Resources.NET.MortgagteINB)
		}
	}

}
