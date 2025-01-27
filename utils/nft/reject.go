package nft

import "encoding/json"

type Reject struct {
	Type string `json:"type"`
	Expr string `json:"expr"`
}

func (r *Reject) Validate() error {
	//TODO implement me
	panic("implement me")
}

func (r *Reject) TypeName() string {
	return "reject"
}

func (r *Reject) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.ReallyValue())
}

func (r *Reject) UnmarshalJSON(data []byte) error {
	type InnerReject *Reject
	return json.Unmarshal(data, InnerReject(r))
}

func (r *Reject) ReallyValue() interface{} {
	return map[string]string{
		"type": r.Type,
		"expr": r.Expr,
	}
}

var _ Any = &Reject{}
