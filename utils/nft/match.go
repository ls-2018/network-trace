package nft

import "encoding/json"

type Match struct {
	Op    Op             `json:"op"`
	Left  map[string]Any `json:"left,omitempty"`
	Right *RightValue    `json:"right"`
}

func (m *Match) Validate() error {
	//TODO implement me
	panic("implement me")
}

func (m *Match) ReallyValue() interface{} {
	res := map[string]interface{}{}
	res["op"] = m.Op
	if len(m.Left) > 0 {
		t := map[string]interface{}{}
		for k, v := range m.Left {
			t[k] = v.ReallyValue()
		}
		res["left"] = t
	}
	res["right"] = m.Right.ReallyValue()
	return res
}
func (m *Match) TypeName() string {
	return "match"
}
func (m *Match) MarshalJSON() ([]byte, error) {
	raw := map[string]interface{}{
		"op": m.Op,
	}
	if m.Left != nil {
		rawLeft := make(map[string]interface{})
		for key, value := range m.Left {
			rawLeft[key] = value
		}
		raw["left"] = rawLeft
	}
	if m.Right != nil {
		raw["right"] = m.Right.ReallyValue()
	}
	x, err := json.Marshal(raw)
	return x, err
}
func (m *Match) UnmarshalJSON(data []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	m.Op = Op(raw["op"].(string))

	if rawRight, ok := raw["right"]; ok {
		rightData, err := json.Marshal(rawRight)
		if err != nil {
			return err
		}
		m.Right = &RightValue{}
		if err := m.Right.UnmarshalJSON(rightData); err != nil {
			return err
		}
	}

	if rawLeft, ok := raw["left"]; ok {
		leftData, err := json.Marshal(rawLeft)
		if err != nil {
			return err
		}
		var leftMap map[string]interface{}
		if err := json.Unmarshal(leftData, &leftMap); err != nil {
			return err
		}
		m.Left = make(map[string]Any)
		for key, value := range leftMap {
			expr := exprFromName(key)
			if expr == nil {
				continue
			}
			exprData, err := json.Marshal(value)
			if err != nil {
				return err
			}
			if err := json.Unmarshal(exprData, expr); err != nil {
				return err
			}
			m.Left[key] = expr
		}
	}

	return nil
}

var _ Any = &Match{}
