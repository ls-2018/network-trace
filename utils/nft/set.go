package nft

import "encoding/json"

type Set struct {
	data []RightValue
}

func (s *Set) Validate() error {
	//TODO implement me
	panic("implement me")
}

func (s *Set) ReallyValue() interface{} {
	var res []interface{}
	for _, v := range s.data {
		if len(v.anys) == 0 {
			res = append(res, v.data)
		} else {
			for k, _v := range v.anys {
				res = append(res, map[string]interface{}{
					k: _v.ReallyValue(),
				})
			}
		}
	}
	return res
}
func (s *Set) TypeName() string {
	return "set"
}
func (s *Set) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.ReallyValue())
}
func (s *Set) UnmarshalJSON(data []byte) error {
	var raw []RightValue
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	s.data = raw
	return nil
}

var _ Any = &Set{}
