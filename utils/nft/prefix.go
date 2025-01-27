package nft

import "encoding/json"

type Prefix struct {
	Addr string `json:"addr"`
	Len  int    `json:"len"`
}

func (p *Prefix) Validate() error {
	//TODO implement me
	panic("implement me")
}

func (p *Prefix) ReallyValue() interface{} {
	return map[string]interface{}{
		"addr": p.Addr,
		"len":  p.Len,
	}
}
func (p *Prefix) TypeName() string {
	return "prefix"
}
func (p *Prefix) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ReallyValue())
}
func (p *Prefix) UnmarshalJSON(data []byte) error {
	//var raw map[string]interface{}
	type InnerPrefix *Prefix
	if err := json.Unmarshal(data, InnerPrefix(p)); err != nil {
		return err
	}
	//p.Addr = raw["addr"].(string)
	//p.Len = int(raw["len"].(float64))
	return nil
}

var _ Any = &Prefix{}
