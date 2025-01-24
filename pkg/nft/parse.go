package nft

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
)

type Any interface {
	Name() string
	MarshalJSON() ([]byte, error)
	UnmarshalJSON(data []byte) error
	ReallyValue() interface{}
}

type Rule struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Chain  string `json:"chain"`
	Handle int    `json:"handle"`
	Expr   ExprData
}

type ExprData []map[string]Any

func (e *ExprData) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	var rawExpressions []map[string]interface{}
	if err := json.Unmarshal(data, &rawExpressions); err != nil {
		return err
	}

	for _, items := range rawExpressions {
		for k, value := range items {
			expr := exprFromName(k)
			if expr == nil {
				continue // Skip unsupported types
			}
			marshaledValue, err := json.Marshal(value)
			if err != nil {
				return err
			}
			if err := json.Unmarshal(marshaledValue, expr); err != nil {
				return err
			}
			raw := []map[string]Any(*e)
			raw = append(raw, map[string]Any{
				expr.Name(): expr,
			})
			a := ExprData(raw)
			*e = a
		}
	}
	return nil
}
func (e *ExprData) MarshalJSON() ([]byte, error) {
	var res []map[string]interface{}
	for _, items := range []map[string]Any(*e) {
		for k, value := range items {
			res = append(res, map[string]interface{}{
				k: value.ReallyValue(),
			})
		}
	}

	return json.Marshal(res)
}

type Match struct {
	Op    string         `json:"op"`
	Left  map[string]Any `json:"left,omitempty"`
	Right *RightValue    `json:"right"`
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
func (m *Match) Name() string {
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

	m.Op = raw["op"].(string)

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

type RightValue struct {
	anys map[string]Any
	data interface{}
}

func (r *RightValue) Name() string {
	return " "
}
func (r *RightValue) ReallyValue() interface{} {
	if len(r.anys) != 0 {
		res := map[string]interface{}{}
		for k, v := range r.anys {
			res[k] = v.ReallyValue()
		}
		return res
	}
	return r.data
}
func (r *RightValue) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	if data[0] == '{' {
		r.anys = map[string]Any{}
		var rawMap map[string]interface{}
		if err := json.Unmarshal(data, &rawMap); err != nil {
			return err
		}
		for k, value := range rawMap {
			expr := exprFromName(k)
			if expr == nil {
				continue
			}
			marshaledValue, err := json.Marshal(value)
			if err != nil {
				return err
			}
			if err := json.Unmarshal(marshaledValue, expr); err != nil {
				return err
			}
			r.anys[k] = expr
		}
	} else {
		err := json.Unmarshal(data, &r.data)
		return err
	}
	return nil
}

type Range []string

func (r *Range) ReallyValue() interface{} {
	return []string(*r)
}
func (r *Range) Name() string {
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

type Set struct {
	data []RightValue
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
func (s *Set) Name() string {
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

type Prefix struct {
	Addr string `json:"addr"`
	Len  int    `json:"len"`
}

func (p *Prefix) ReallyValue() interface{} {
	return map[string]interface{}{
		"addr": p.Addr,
		"len":  p.Len,
	}
}
func (p *Prefix) Name() string {
	return "prefix"
}
func (p *Prefix) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ReallyValue())
}
func (p *Prefix) UnmarshalJSON(data []byte) error {
	//var raw map[string]interface{}
	type InnerPrefix *Prefix
	if err := json.Unmarshal(data, InnerPrefix(p)); err != nil {
		return err
	}
	//p.Addr = raw["addr"].(string)
	//p.Len = int(raw["len"].(float64))
	return nil
}

type Queue struct {
	Num int `json:"num"`
}

func (q *Queue) ReallyValue() interface{} {
	return map[string]int{
		"num": q.Num,
	}
}
func (q *Queue) Name() string {
	return "queue"
}
func (q *Queue) MarshalJSON() ([]byte, error) {
	return json.Marshal(q.ReallyValue())
}
func (q *Queue) UnmarshalJSON(data []byte) error {
	if data[0] == '{' {
		var raw struct {
			Num int `json:"num"`
		}
		if err := json.Unmarshal(data, &raw); err != nil {
			return err
		}
		q.Num = raw.Num
	} else if strings.HasPrefix(string(data), "to ") {
		num, err := strconv.Atoi(string(data[3:]))
		if err != nil {
			return err
		}
		q.Num = num
	} else {
		num, err := strconv.Atoi(string(data))
		if err != nil {
			return err
		}
		q.Num = num
	}
	return nil
}

type Log struct {
	Prefix string `json:"prefix"`
}

func (l *Log) ReallyValue() interface{} {
	return map[string]string{
		"prefix": l.Prefix,
	}
}
func (l *Log) Name() string {
	return "log"
}
func (l *Log) MarshalJSON() ([]byte, error) {
	return json.Marshal(l.ReallyValue())
}
func (l *Log) UnmarshalJSON(data []byte) error {
	type InnerLog *Log
	if err := json.Unmarshal(data, InnerLog(l)); err != nil {
		return err
	}
	return nil
}

type Meta struct {
	Key string `json:"key"`
}

func (m *Meta) ReallyValue() interface{} {
	return map[string]string{
		"key": m.Key,
	}
}
func (m *Meta) Name() string {
	return "meta"
}
func (m *Meta) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.ReallyValue())
}
func (m *Meta) UnmarshalJSON(data []byte) error {
	type InnerMeta *Meta
	if err := json.Unmarshal(data, InnerMeta(m)); err != nil {
		return err
	}
	return nil
}

type Payload struct {
	Protocol string `json:"protocol"`
	Field    string `json:"field"`
}

func (p *Payload) ReallyValue() interface{} {
	return map[string]string{
		"protocol": p.Protocol,
		"field":    p.Field,
	}
}
func (p *Payload) Name() string {
	return "payload"
}
func (p *Payload) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ReallyValue())
}
func (p *Payload) UnmarshalJSON(data []byte) error {
	type InnerPayload *Payload
	if err := json.Unmarshal(data, InnerPayload(p)); err != nil {
		return err
	}
	return nil
}

func exprFromName(name string) Any {
	switch name {
	case "range":
		return &Range{}
	case "meta":
		return &Meta{}
	case "payload":
		return &Payload{}
	case "log":
		return &Log{}
	case "match":
		return &Match{}
	case "queue":
		return &Queue{}
	case "set":
		return &Set{}
	case "prefix":
		return &Prefix{}
	default:
		return nil
	}
}

type Wrapper struct {
	A Rule `json:"rule"`
}
type All struct {
	Table []Wrapper `json:"nftables"`
}

//type All struct {
//	Table []map[string]Rule `json:"nftables"`
//}

func main() {
	file, err := ioutil.ReadFile("./a/a.json")
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}

	var allRules All
	if err := json.Unmarshal(file, &allRules); err != nil {
		fmt.Printf("Error unmarshaling JSON: %v\n", err)
		return
	}

	marshaledData, err := json.MarshalIndent(allRules, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		return
	}

	fmt.Println(string(marshaledData))
}
