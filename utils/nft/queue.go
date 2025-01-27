package nft

import (
	"encoding/json"
	"strconv"
	"strings"
)

type Queue struct {
	Num int `json:"num"`
}

func (q *Queue) Validate() error {
	//TODO implement me
	panic("implement me")
}

func (q *Queue) ReallyValue() interface{} {
	return map[string]int{
		"num": q.Num,
	}
}
func (q *Queue) TypeName() string {
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

var _ Any = &Queue{}
