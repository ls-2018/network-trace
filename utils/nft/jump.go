package nft

import "encoding/json"

type Jump struct {
	Target string `json:"target"`
}

func (j *Jump) Validate() error {
	//TODO implement me
	panic("implement me")
}

func (j *Jump) TypeName() string {
	return "jump"
}

func (j *Jump) MarshalJSON() ([]byte, error) {
	return json.Marshal(j.ReallyValue())
}

func (j *Jump) UnmarshalJSON(data []byte) error {
	type InnerJump *Jump
	return json.Unmarshal(data, InnerJump(j))
}

func (j *Jump) ReallyValue() interface{} {
	return map[string]string{
		"target": j.Target,
	}
}

var _ Any = &Jump{}
