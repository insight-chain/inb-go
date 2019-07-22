package common

// Declare :
// declare come from custom tx which data like "inb:1:event:declare:id~ip~port"
// Sender of tx is Signer or Candidate




var(
	//inb by ghy begin
	ResponseRate                	= float64(0.01)
	CycleTimes                       = uint64(12)
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
