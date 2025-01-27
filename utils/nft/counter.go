package nft

import "encoding/json"

type Counter struct {
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
}

func (c *Counter) Validate() error {
	//TODO implement me
	panic("implement me")
}

func (c *Counter) TypeName() string {
	return "counter"
}

func (c *Counter) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.ReallyValue())
}

func (c *Counter) UnmarshalJSON(data []byte) error {
	type InnerCounter *Counter
	return json.Unmarshal(data, InnerCounter(c))
}

func (c *Counter) ReallyValue() interface{} {
	return map[string]uint64{
		"bytes":   c.Bytes,
		"packets": c.Packets,
	}
}

var _ Any = &Counter{}
