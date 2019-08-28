package common

import (
	"math/big"
)

// 2019.7.22 inb by ghy begin
var (
	OneDaySecond = big.NewInt(24 * 60 * 60)

	//vote
	VoteRewardCycleSeconds  = big.NewInt(1)
	VoteRewardCycleTimes    = big.NewInt(7)
	VoteDenominator         = big.NewInt(12)
	VoteHundred             = big.NewInt(100)
	VoteNumberOfDaysOneYear = big.NewInt(365)

	//Mortgage,unMortgage,change vote
	VoteRewardCycleSecondsForChange  = big.NewInt(1)
	VoteRewardCycleTimesForChange    = big.NewInt(1)
	VoteDenominatorForChange         = big.NewInt(12)
	VoteHundredForChange             = big.NewInt(100)
	VoteNumberOfDaysOneYearForChange = big.NewInt(365)

	//locked 30days
	LockedRewardCycleSecondsFor30days  = big.NewInt(1)
	LockedRewardCycleTimesFor30days    = big.NewInt(7)
	LockedDenominatorFor30days         = big.NewInt(9)
	LockedHundredFor30days             = big.NewInt(100)
	LockedNumberOfDaysOneYearFor30days = big.NewInt(365)

	//locked 90days
	LockedRewardCycleSecondsFor90days  = big.NewInt(1)
	LockedRewardCycleTimesFor90days    = big.NewInt(7)
	LockedDenominatorFor90days         = big.NewInt(10)
	LockedHundredFor90days             = big.NewInt(100)
	LockedNumberOfDaysOneYearFor90days = big.NewInt(365)

	//locked 180days
	LockedRewardCycleSecondsFor180days  = big.NewInt(1)
	LockedRewardCycleTimesFor180days    = big.NewInt(7)
	LockedDenominatorFor180days         = big.NewInt(11)
	LockedHundredFor180days             = big.NewInt(100)
	LockedNumberOfDaysOneYearFor180days = big.NewInt(365)

	//locked 360days
	LockedRewardCycleSecondsFor360days  = big.NewInt(1)
	LockedRewardCycleTimesFor360days    = big.NewInt(7)
	LockedDenominatorFor360days         = big.NewInt(12)
	LockedHundredFor360days             = big.NewInt(100)
	LockedNumberOfDaysOneYearFor360days = big.NewInt(365)

	// 2019.7.22 inb by ghy end
	//

)

// Declare :
// declare come from custom tx which data like "inb:1:event:declare:id~ip~port"
// Sender of tx is Signer or Candidate

type EnodeInfo struct {
	Address Address `json:"address"`
	Id      string  `json:"id"`
	Ip      string  `json:"ip"`
	Port    string  `json:"port"`
	//inb by ghy begin
	Name    string `json:"name"`
	Nation  string `json:"nation"`
	City    string `json:"city"`
	Image   string `json:"image"`
	Website string `json:"website"`
	Email   string `json:"email"`
	Data    string `json:"data"`
	Vote    uint64 `json:"vote"`
	//inb by ghy end
}
