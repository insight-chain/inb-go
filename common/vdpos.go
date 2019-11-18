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
	VoteDenominator         = big.NewInt(2)
	VoteHundred             = big.NewInt(100)
	VoteNumberOfDaysOneYear = big.NewInt(365)

	//Mortgage,unMortgage,change vote
	VoteRewardCycleSecondsForChange  = new(big.Int).Mul(big.NewInt(1), OneDayHeight)
	VoteRewardCycleTimesForChange    = big.NewInt(1)
	VoteDenominatorForChange         = big.NewInt(2)
	VoteHundredForChange             = big.NewInt(100)
	VoteNumberOfDaysOneYearForChange = big.NewInt(365)

	//locked 30days
	LockedRewardCycleSecondsFor30days  = new(big.Int).Mul(big.NewInt(1), OneDayHeight)
	LockedRewardCycleTimesFor30days    = big.NewInt(7)
	LockedDenominatorFor30days         = big.NewInt(5)
	LockedHundredFor30days             = big.NewInt(1000)
	LockedNumberOfDaysOneYearFor30days = big.NewInt(365)

	//locked 90days
	LockedRewardCycleSecondsFor90days  = new(big.Int).Mul(big.NewInt(1), OneDayHeight)
	LockedRewardCycleTimesFor90days    = big.NewInt(7)
	LockedDenominatorFor90days         = big.NewInt(15)
	LockedHundredFor90days             = big.NewInt(1000)
	LockedNumberOfDaysOneYearFor90days = big.NewInt(365)

	//locked 180days
	LockedRewardCycleSecondsFor180days  = new(big.Int).Mul(big.NewInt(1), OneDayHeight)
	LockedRewardCycleTimesFor180days    = big.NewInt(7)
	LockedDenominatorFor180days         = big.NewInt(3)
	LockedHundredFor180days             = big.NewInt(100)
	LockedNumberOfDaysOneYearFor180days = big.NewInt(365)

	//locked 360days
	LockedRewardCycleSecondsForMoreThan360days  = new(big.Int).Mul(big.NewInt(1), OneDayHeight)
	LockedRewardCycleTimesForMoreThan360days    = big.NewInt(7)
	LockedDenominatorForMoreThan360days         = big.NewInt(5)
	LockedHundredForMoreThan360days             = big.NewInt(100)
	LockedNumberOfDaysOneYearForMoreThan360days = big.NewInt(365)

	// 2019.7.22 inb by ghy end

	SpecialAddressPrefix = 5
	MortgageAccount      = "0x9530000000000000000000000000000000000000" // account record value of mortgaging

	LenOfNodeInfoByte      = 900
	LenOfNodeInfoPort      = 5
	LenOfNodeInfoImage     = 100
	LenOfNodeInfoEmail     = 35
	LenOfNodeInfoWebsite   = 35
	LenOfNodeInfoId        = 128
	LenOfNodeInfoNation    = 15
	LenOfNodeInfoExtraData = 150
	LenOfNodeInfoName      = 15

	LenOfLightTokenByte        = 200
	LenOfLightTokenName        = 20
	LightTokenDecimals         = uint8(5)
	LenOfLightTokenSymbol      = 10
	LenOfLightTokenTotalSupply = new(big.Int).Mul(big.NewInt(1e12), big.NewInt(1e5))
	LightTokenMinValue         = new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e5))
	LightTokenMaxValue         = new(big.Int).Mul(big.NewInt(10000), big.NewInt(1e5))
)

// Declare :
// declare come from custom tx which data like "inb:1:event:declare:id~ip~port"
// Sender of tx is Signer or Candidate

type SuperNode struct {
	Address       Address `json:"address"`
	RewardAccount string  `json:"rewardAccount"`
	Id            string  `json:"id"`
	Ip            string  `json:"ip"`
	Port          string  `json:"port"`
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

func (node *SuperNode) GetReceiveAccount() Address {
	return HexToAddress(node.RewardAccount)
}

type SuperNodeExtra struct {
	SuperNode
	//inb by ghy begin
	Name      string `json:"name"`
	Nation    string `json:"nation"`
	Image     string `json:"image"`
	Website   string `json:"website"`
	Email     string `json:"email"`
	ExtraData string `json:"extraData"`

	//inb by ghy end
}
