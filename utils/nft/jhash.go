package nft

import "encoding/json"

type Jhash struct {
	Mod    int            `json:"mod"`
	Offset int            `json:"offset"`
	Expr   map[string]Any `json:"expr"`
}

func (j *Jhash) Validate() error {
	return nil
}

func (j *Jhash) TypeName() string {
	return "jhash"
}

func (j *Jhash) MarshalJSON() ([]byte, error) {
	return json.Marshal(j.ReallyValue())
}

func (j *Jhash) UnmarshalJSON(data []byte) error {
	type InnerJhash *Jhash
	return json.Unmarshal(data, InnerJhash(j))
}

func (j *Jhash) ReallyValue() interface{} {
	res := map[string]interface{}{}
	res["mod"] = j.Mod
	res["offset"] = j.Offset
	res["expr"] = map[string]interface{}{}
	for k, v := range j.Expr {
		res[k] = v.ReallyValue()
	}
	return res
}

var _ Any = &Jhash{}
