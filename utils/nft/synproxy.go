package nft

import "encoding/json"

type SynProxy struct {
	Mss    uint16 `json:"mss"`
	Wscale uint8  `json:"wscale"`
	Flags  uint32 `json:"flags"`
}

func (s *SynProxy) Validate() error {
	//TODO implement me
	panic("implement me")
}

func (s *SynProxy) TypeName() string {
	return "synproxy"
}

func (s *SynProxy) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.ReallyValue())
}

func (s *SynProxy) UnmarshalJSON(data []byte) error {
	type InnerSynProxy *SynProxy
	return json.Unmarshal(data, InnerSynProxy(s))
}

func (s *SynProxy) ReallyValue() interface{} {
	return map[string]interface{}{
		"mss":    s.Mss,
		"wscale": s.Wscale,
		"flags":  s.Flags,
	}
}

var _ Any = &SynProxy{}
