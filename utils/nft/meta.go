package nft

import "encoding/json"

type Meta struct {
	Key string `json:"key"`
}

func (m *Meta) Validate() error {
	//TODO implement me
	panic("implement me")
}

func (m *Meta) ReallyValue() interface{} {
	return map[string]string{
		"key": m.Key,
	}
}
func (m *Meta) TypeName() string {
	return "meta"
}
func (m *Meta) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.ReallyValue())
}
func (m *Meta) UnmarshalJSON(data []byte) error {
	type InnerMeta *Meta
	if err := json.Unmarshal(data, InnerMeta(m)); err != nil {
		return err
	}
	return nil
}

var _ Any = &Meta{}
