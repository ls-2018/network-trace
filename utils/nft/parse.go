package nft

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

type MetaInfo struct {
	Version     string `json:"version"`
	ReleaseName string `json:"release_name"`
}
type Rule struct {
	Family  string `json:"family"`
	Table   string `json:"table"`
	Chain   string `json:"chain"`
	Handle  int    `json:"handle"`
	Comment string `json:"comment"`
	Expr    ExprData
}

type Table struct {
	Family string `json:"family"`
	Name   string `json:"name"`
	Handle int    `json:"handle"`
}

type Chain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Handle int    `json:"handle"`
	Policy string `json:"policy"`
}

type Wrapper struct {
	MetaInfo *MetaInfo `json:"metainfo,omitempty"`
	Rule     *Rule     `json:"rule,omitempty"`
	Table    *Table    `json:"table,omitempty"`
	Chain    *Chain    `json:"chain,omitempty"`
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
				expr.TypeName(): expr,
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
func (e *ExprData) ReallyValue() interface{} {
	var res []map[string]interface{}
	for _, items := range []map[string]Any(*e) {
		for k, value := range items {
			res = append(res, map[string]interface{}{
				k: value.ReallyValue(),
			})
		}
	}

	return res
}

type Op string

const (
	Eq    Op = "=="
	NoeEq Op = "!="
)

type RightValue struct {
	anys map[string]Any
	data interface{}
}

func (r *RightValue) TypeName() string {
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

func exprFromName(name string) Any {
	var e Any
	switch name {
	case "range":
		e = &Range{}
	case "meta":
		e = &Meta{}
	case "counter":
		e = &Counter{}
	case "payload":
		e = &Payload{}
	case "log":
		e = &Log{}
	case "match":
		e = &Match{}
	case "queue":
		e = &Queue{}
	case "synproxy":
		e = &SynProxy{}
	case "jump":
		e = &Jump{}
	case "xt":
		e = &XT{}
	case "ct":
		e = &CT{}
	case "prefix":
		e = &Prefix{}
	case "reject":
		e = &Reject{}
	case "mangle":
		e = &Mangle{}
	case "jhash":
		e = &Jhash{}
	case "concat":
		e = &Concat{}

	//	 ------

	//case "cmp":
	//	e = &Cmp{}
	//case "objref":
	//	e = &Objref{}
	//case "lookup":
	//	e = &Lookup{}
	//case "immediate":
	//	e = &Immediate{}
	//case "bitwise":
	//	e = &Bitwise{}
	//case "redir":
	//	e = &Redir{}
	//case "nat":
	//	e = &NAT{}
	//case "limit":
	//	e = &Limit{}
	//case "quota":
	//	e = &Quota{}
	//case "dynset":
	//	e = &Dynset{}
	//case "exthdr":
	//	e = &Exthdr{}
	//case "target":
	//	e = &Target{}
	//case "connlimit":
	//	e = &Connlimit{}
	//case "flow_offload":
	//	e = &FlowOffload{}
	//case "masq":
	//	e = &Masq{}
	//case "hash":
	//	e = &Hash{}
	//case "cthelper":
	//	e = &CtHelper{}
	//case "ctexpect":
	//	e = &CtExpect{}
	//case "secmark":
	//	e = &SecMark{}
	//case "cttimeout":
	//	e = &CtTimeout{}
	//case "fib":
	//	e = &Fib{}
	default:
		return nil
	}
	return e
}

type All struct {
	Info []Wrapper `json:"nftables"`
}

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
