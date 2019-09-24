package common

import (
	"math/big"
)

// 2019.7.22 inb by ghy begin
var (
	//One day block height
	OneDayHeight = big.NewInt(24 * 60 * 60 / 2)

	//One week block height
	OneWeekHeight = big.NewInt(7 * 24 * 60 * 60 / 2)

	//vote
	VoteRewardCycleSeconds  = new(big.Int).Mul(big.NewInt(1), OneDayHeight)
	VoteRewardCycleTimes    = big.NewInt(7)
	VoteDenominator         = big.NewInt(5)
	VoteHundred             = big.NewInt(100)
	VoteNumberOfDaysOneYear = big.NewInt(365)

	//Mortgage,unMortgage,change vote
	VoteRewardCycleSecondsForChange  = new(big.Int).Mul(big.NewInt(1), OneDayHeight)
	VoteRewardCycleTimesForChange    = big.NewInt(1)
	VoteDenominatorForChange         = big.NewInt(5)
	VoteHundredForChange             = big.NewInt(100)
	VoteNumberOfDaysOneYearForChange = big.NewInt(365)

	//locked 30days
	LockedRewardCycleSecondsFor30days  = new(big.Int).Mul(big.NewInt(1), OneDayHeight)
	LockedRewardCycleTimesFor30days    = big.NewInt(7)
	LockedDenominatorFor30days         = big.NewInt(1)
	LockedHundredFor30days             = big.NewInt(100)
	LockedNumberOfDaysOneYearFor30days = big.NewInt(365)

	//locked 90days
	LockedRewardCycleSecondsFor90days  = new(big.Int).Mul(big.NewInt(1), OneDayHeight)
	LockedRewardCycleTimesFor90days    = big.NewInt(7)
	LockedDenominatorFor90days         = big.NewInt(3)
	LockedHundredFor90days             = big.NewInt(100)
	LockedNumberOfDaysOneYearFor90days = big.NewInt(365)

	//locked 180days
	LockedRewardCycleSecondsFor180days  = new(big.Int).Mul(big.NewInt(1), OneDayHeight)
	LockedRewardCycleTimesFor180days    = big.NewInt(7)
	LockedDenominatorFor180days         = big.NewInt(5)
	LockedHundredFor180days             = big.NewInt(100)
	LockedNumberOfDaysOneYearFor180days = big.NewInt(365)

	//locked 360days
	LockedRewardCycleSecondsFor360days  = new(big.Int).Mul(big.NewInt(1), OneDayHeight)
	LockedRewardCycleTimesFor360days    = big.NewInt(7)
	LockedDenominatorFor360days         = big.NewInt(9)
	LockedHundredFor360days             = big.NewInt(100)
	LockedNumberOfDaysOneYearFor360days = big.NewInt(365)

	// 2019.7.22 inb by ghy end
	//
)

// Declare :
// declare come from custom tx which data like "inb:1:event:declare:id~ip~port"
// Sender of tx is Signer or Candidate

type EnodeInfo struct {
	Address        Address `json:"address"`
	ReceiveAccount string  `json:"receiveAccount"`
	Id             string  `json:"id"`
	Ip             string  `json:"ip"`
	Port           string  `json:"port"`
	//inb by ghy begin
	//Name    string `json:"name"`
	//Nation  string `json:"nation"`
	//City    string `json:"city"`
	//Image   string `json:"image"`
	//Website string `json:"website"`
	//Email   string `json:"email"`
	//Data    string `json:"data"`
	//Vote    uint64 `json:"vote"`
	//inb by ghy end
}

func (node *EnodeInfo) GetReceiveAccount() Address {
	return HexToAddress(node.ReceiveAccount)
}

type EnodesInfo struct {
	Address        Address `json:"address"`
	ReceiveAccount string  `json:"receiveAccount"`
	Id             string  `json:"id"`
	Ip             string  `json:"ip"`
	Port           string  `json:"port"`
	//inb by ghy begin
	Name    string `json:"name"`
	Nation  string `json:"nation"`
	City    string `json:"city"`
	Image   string `json:"image"`
	Website string `json:"website"`
	Email   string `json:"email"`
	Data    string `json:"data"`

	//inb by ghy end
}
