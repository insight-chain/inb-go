package common

import "math/big"

// 2019.7.22 inb by ghy begin
var (
	OneDaySecond = big.NewInt(24 * 60 * 60)

	//vote
	VoteRewardCycleSeconds  = big.NewInt(1)
	VoteRewardCycleTimes    = big.NewInt(7)
	VoteDenominator         = big.NewInt(12)
	VoteHundred             = big.NewInt(100)
	VoteNumberOfDaysOneYear = big.NewInt(365)

	//locked
	LockedRewardCycleSeconds  = big.NewInt(1)
	LockedRewardCycleTimes    = big.NewInt(7)
	LockedDenominator         = big.NewInt(12)
	LockedHundred             = big.NewInt(100)
	LockedNumberOfDaysOneYear = big.NewInt(365)

	// 2019.7.22 inb by ghy end

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
