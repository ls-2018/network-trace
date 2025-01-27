package nft

import "encoding/json"

type Mangle struct {
	Key   Any `json:"key"`
	Value Any `json:"value"`
}

func (m *Mangle) Validate() error {
	return nil
}

func (m *Mangle) TypeName() string {
	return "mangle"
}

func (m *Mangle) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.ReallyValue())
}

func (m *Mangle) UnmarshalJSON(data []byte) error {
	type InnerMangle *Mangle
	return json.Unmarshal(data, InnerMangle(m))
}

func (m *Mangle) ReallyValue() interface{} {
	return map[string]interface{}{
		"key":   m.Key.ReallyValue(),
		"value": m.Value.ReallyValue(),
	}
}

var _ Any = &Mangle{}
