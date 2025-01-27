package nft

import "encoding/json"

type CT struct {
	Key string `json:"key"`
}

func (c *CT) Validate() error {
	return nil
}

func (c *CT) TypeName() string {
	return "ct"
}

func (c *CT) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.ReallyValue())
}

func (c *CT) UnmarshalJSON(data []byte) error {
	type InnerCT *CT
	return json.Unmarshal(data, InnerCT(c))
}

func (c *CT) ReallyValue() interface{} {
	return map[string]interface{}{
		"key": c.Key,
	}
}

var _ Any = &CT{}
