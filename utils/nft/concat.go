package nft

import "encoding/json"

type Concat struct {
	Data ExprData `json:"data"`
}

func (c *Concat) TypeName() string {
	return "concat"
}

func (c *Concat) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.ReallyValue())
}

func (c *Concat) UnmarshalJSON(data []byte) error {
	type InnerConcat *Concat
	return json.Unmarshal(data, InnerConcat(c))
}

func (c *Concat) ReallyValue() interface{} {
	return c.Data.ReallyValue()

}

func (c *Concat) Validate() error {
	return nil
}

var _ Any = &Concat{}
