package types

type FuzzResult struct {
	Method    string `json:"method"`
	URL       string `json:"url"`
	Payload   string `json:"payload"`
	Reason    string `json:"reason"`
	Response  string `json:"response"`
	Injection string `json:"injection"`
}
