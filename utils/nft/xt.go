package nft

import "encoding/json"

type XT struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

func (x *XT) Validate() error {
	//TODO implement me
	panic("implement me")
}

func (x *XT) ReallyValue() interface{} {
	return map[string]string{
		"type": x.Type,
		"name": x.Name,
	}
}
func (x *XT) TypeName() string {
	return "xt"
}
func (x *XT) MarshalJSON() ([]byte, error) {
	return json.Marshal(x.ReallyValue())
}
func (x *XT) UnmarshalJSON(data []byte) error {
	//var raw map[string]interface{}
	type InnerXT *XT
	if err := json.Unmarshal(data, InnerXT(x)); err != nil {
		return err
	}
	//p.Addr = raw["addr"].(string)
	//p.Len = int(raw["len"].(float64))
	return nil
}

var _ Any = &XT{}
