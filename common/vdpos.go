package common

import "math/big"

// Declare :
// declare come from custom tx which data like "inb:1:event:declare:id~ip~port"
// Sender of tx is Signer or Candidate

var (
	//inb by ghy begin

	//vote

	//VoteRewardCycleSeconds = int64(7 * 24 * 60 * 60)//
	//VoteRewardOneDayRate = float64(0.12 / 365)
	//VoteRewardOneDaySecond= int64(24 * 60 * 60)
	////else
	//ResponseRate        = float64(0.12/365)
	//VoteRewardCycleDays = int64(7)
	//RewardOneDaySecond  = int64(24 * 60 * 60)

	//test
	//vote

	VoteRewardCycleSeconds = int64(60) //
	VoteRewardOneDayRate   = float64(1)
	VoteRewardOneDaySecond = int64(10)
	//else
	ResponseRate        = float64(1)
	VoteRewardCycleDays = int64(7)
	RewardOneDaySecond  = int64(10)

	Denominator         = big.NewInt(12)
	ReceivingCycleDays  = big.NewInt(7)
	Hundred             = big.NewInt(100)
	NumberOfDaysOneYear = big.NewInt(365)
	OneCycleSeconds     = big.NewInt(24 * 60 * 60)
	DefaultTotalAccount = new(big.Int).Mul(big.NewInt(10), big.NewInt(1e+18))
	BeVotedNeedINB      = new(big.Int).Mul(big.NewInt(100000), big.NewInt(1e+18))

	//inb by ghy end

)

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
