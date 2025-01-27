package nft

import "encoding/json"

type Range []string

func (r *Range) Validate() error {
	//TODO implement me
	panic("implement me")
}

func (r *Range) ReallyValue() interface{} {
	return []string(*r)
}
func (r *Range) TypeName() string {
	return "range"
}
func (r *Range) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.ReallyValue())
}
func (r *Range) UnmarshalJSON(data []byte) error {
	var raw []string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*r = raw
	return nil
}

var _ Any = &Range{}
