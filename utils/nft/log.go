package nft

import "encoding/json"

type Log struct {
	Prefix string `json:"prefix"`
}

func (l *Log) Validate() error {
	//TODO implement me
	panic("implement me")
}

func (l *Log) ReallyValue() interface{} {
	return map[string]string{
		"prefix": l.Prefix,
	}
}
func (l *Log) TypeName() string {
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

var _ Any = &Log{}
