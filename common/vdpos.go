package common

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
	Vote    uint64 `json:"vote,omitempty"`
	//inb by ghy end
}
